package jacs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ReplayStoreScope describes whether replay state is isolated to one process
// or shared atomically across service replicas.
type ReplayStoreScope string

const (
	// ReplayStoreScopeProcessLocal is unsuitable for the external shared-replay
	// API and is rejected before cryptographic preparation.
	ReplayStoreScopeProcessLocal ReplayStoreScope = "process_local"
	// ReplayStoreScopeShared identifies an atomic cross-replica backend.
	ReplayStoreScopeShared ReplayStoreScope = "shared"
)

// SharedReplayStore is an application-owned atomic nonce-consumption backend.
// Consume must return true to exactly one caller for a new key and false to all
// duplicates until ttl expires. Implementations must honor context cancellation.
// Store failures must be returned; JACS fails closed and never releases data.
// The helper returns at its deadline even for a noncooperative implementation,
// but such an implementation can still cause a late backend side effect and
// retain its worker goroutine until Consume returns.
type SharedReplayStore interface {
	Scope() ReplayStoreScope
	Name() string
	Consume(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// ReplayErrorCode is a stable cross-language error code from
// binding-core/tests/fixtures/external_replay_contract.json.
type ReplayErrorCode string

const (
	ReplayErrorDuplicate          ReplayErrorCode = "replay_duplicate"
	ReplayErrorStoreUnavailable   ReplayErrorCode = "replay_store_unavailable"
	ReplayErrorStoreTimeout       ReplayErrorCode = "replay_store_timeout"
	ReplayErrorStoreInvalidResult ReplayErrorCode = "replay_store_invalid_result"
	ReplayErrorStoreNotShared     ReplayErrorCode = "replay_store_not_shared"
	ReplayErrorSignedEventExpired ReplayErrorCode = "signed_event_expired"
)

// ReplayError reports a fail-closed external replay decision. It never embeds
// the event payload, replay key, signature, or key material.
type ReplayError struct {
	Code    ReplayErrorCode
	message string
}

func (e *ReplayError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.message != "" {
		return string(e.Code) + ": " + e.message
	}
	return string(e.Code)
}

// SignedEventReplayPreparation is returned after complete cryptographic and
// freshness verification but before replay consumption. It intentionally has
// no payload and is not a delivery authorization result.
type SignedEventReplayPreparation struct {
	ContractVersion           uint64 `json:"contractVersion"`
	Status                    string `json:"status"`
	CryptographicallyVerified bool   `json:"cryptographicallyVerified"`
	FreshnessVerified         bool   `json:"freshnessVerified"`
	ReplayConsumed            bool   `json:"replayConsumed"`
	SignerID                  string `json:"signerId"`
	Timestamp                 string `json:"timestamp"`
	Algorithm                 string `json:"algorithm"`
	DocumentID                string `json:"documentId"`
	EventSHA256               string `json:"eventSha256"`
	ReplayKey                 string `json:"replayKey"`
	ReplayTTLSeconds          uint64 `json:"replayTtlSeconds"`
	ExpiresAtUnixSeconds      uint64 `json:"expiresAtUnixSeconds"`
	RawJSON                   string `json:"-"`
}

// VerifiedSignedEvent is returned only after cryptographic verification,
// freshness checks, and one successful atomic shared-store consumption.
// Data is copied from the exact immutable event string verified by Rust.
type VerifiedSignedEvent struct {
	Status         string          `json:"status"`
	Verified       bool            `json:"verified"`
	ReplayConsumed bool            `json:"replayConsumed"`
	Data           json.RawMessage `json:"data"`
	SignerID       string          `json:"signerId"`
	Timestamp      string          `json:"timestamp"`
	Algorithm      string          `json:"algorithm"`
	DocumentID     string          `json:"documentId"`
}

// SignedEventReplayOptions controls freshness and replay-backend deadlines.
// Zero fields select the documented defaults.
type SignedEventReplayOptions struct {
	MaxAge       time.Duration
	StoreTimeout time.Duration
}

const (
	DefaultSignedEventMaxAge             = 5 * time.Minute
	DefaultSignedEventStoreTimeout       = 5 * time.Second
	maxSignedEventFutureSkewSeconds      = uint64(300)
	maxSignedEventReplayPreparationBytes = 64 * 1024
)

type signedEventReplayPreparer func(eventJSON, serverKeysJSON string, maxAgeSeconds uint64) (*SignedEventReplayPreparation, error)

var signedEventReplayPreparationFields = map[string]struct{}{
	"contractVersion":           {},
	"status":                    {},
	"cryptographicallyVerified": {},
	"freshnessVerified":         {},
	"replayConsumed":            {},
	"signerId":                  {},
	"timestamp":                 {},
	"algorithm":                 {},
	"documentId":                {},
	"eventSha256":               {},
	"replayKey":                 {},
	"replayTtlSeconds":          {},
	"expiresAtUnixSeconds":      {},
}

func replayInvalidResult(_ string, message string, _ error) *ReplayError {
	return &ReplayError{
		Code:    ReplayErrorStoreInvalidResult,
		message: message,
	}
}

func decodeUniqueReplayPreparationFields(raw string) (map[string]json.RawMessage, error) {
	if len(raw) > maxSignedEventReplayPreparationBytes {
		return nil, errors.New("native replay preparation exceeded the size limit")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := opening.(json.Delim)
	if !ok || delimiter != '{' {
		return nil, errors.New("native replay preparation must be a JSON object")
	}

	fields := make(map[string]json.RawMessage, len(signedEventReplayPreparationFields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		field, ok := token.(string)
		if !ok {
			return nil, errors.New("native replay preparation field name was not a string")
		}
		if _, duplicate := fields[field]; duplicate {
			return nil, errors.New("native replay preparation contains duplicate fields")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[field] = append(json.RawMessage(nil), value...)
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return nil, errors.New("native replay preparation object was not closed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("native replay preparation contains trailing JSON")
		}
		return nil, err
	}
	return fields, nil
}

func decodeSignedEventReplayPreparation(raw string) (*SignedEventReplayPreparation, error) {
	fields, err := decodeUniqueReplayPreparationFields(raw)
	if err != nil {
		return nil, replayInvalidResult(
			"",
			"native replay preparation was not valid JSON",
			err,
		)
	}
	if len(fields) != len(signedEventReplayPreparationFields) {
		return nil, replayInvalidResult(
			"",
			"native replay preparation fields do not match contract version 1",
			nil,
		)
	}
	for field := range signedEventReplayPreparationFields {
		if _, found := fields[field]; !found {
			return nil, replayInvalidResult(
				"",
				"native replay preparation is missing a required field",
				nil,
			)
		}
	}
	for field := range fields {
		if _, expected := signedEventReplayPreparationFields[field]; !expected {
			return nil, replayInvalidResult(
				"",
				"native replay preparation contains an unexpected field",
				nil,
			)
		}
	}

	var claim SignedEventReplayPreparation
	if err := json.Unmarshal([]byte(raw), &claim); err != nil {
		return nil, replayInvalidResult(
			"",
			"native replay preparation fields have invalid types",
			fmt.Errorf("decode signed-event replay preparation: %w", err),
		)
	}
	claim.RawJSON = raw
	if err := validateSignedEventReplayPreparationFixedFields(&claim, ""); err != nil {
		return nil, err
	}
	return &claim, nil
}

func validateSignedEventReplayPreparationFixedFields(claim *SignedEventReplayPreparation, storeName string) error {
	if claim == nil {
		return replayInvalidResult(storeName, "native replay preparation is nil", nil)
	}
	if claim.ContractVersion != 1 || claim.Status != "crypto_verified_replay_pending" ||
		!claim.CryptographicallyVerified || !claim.FreshnessVerified || claim.ReplayConsumed ||
		claim.SignerID == "" || claim.Timestamp == "" || claim.Algorithm == "" ||
		claim.DocumentID == "" || claim.EventSHA256 == "" || claim.ReplayKey == "" ||
		claim.ReplayTTLSeconds == 0 || claim.ExpiresAtUnixSeconds == 0 {
		return replayInvalidResult(
			storeName,
			"native replay preparation violates contract version 1",
			nil,
		)
	}
	for _, value := range []string{
		claim.SignerID,
		claim.Timestamp,
		claim.Algorithm,
		claim.DocumentID,
		claim.EventSHA256,
		claim.ReplayKey,
	} {
		if !utf8.ValidString(value) {
			return replayInvalidResult(
				storeName,
				"native replay preparation contains invalid UTF-8",
				nil,
			)
		}
	}
	return nil
}

func expectedSignedEventReplayKey(signerID, documentID string) string {
	scope := "signed-event:" + signerID
	return "jacs-replay-v1:" + strconv.Itoa(len(scope)) + ":" + scope + ":" + documentID
}

var strictReplayTimestampPattern = regexp.MustCompile(
	`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|([+-])([0-9]{2}):([0-9]{2}))$`,
)

func parseStrictReplayTimestamp(value string) (time.Time, error) {
	matches := strictReplayTimestampPattern.FindStringSubmatch(value)
	if matches == nil {
		return time.Time{}, errors.New("timestamp must use strict RFC 3339 syntax")
	}
	year, _ := strconv.Atoi(matches[1])
	offsetHour := 0
	offsetMinute := 0
	if matches[8] != "Z" {
		offsetHour, _ = strconv.Atoi(matches[10])
		offsetMinute, _ = strconv.Atoi(matches[11])
	}
	if year < 1970 || offsetHour > 23 || offsetMinute > 59 {
		return time.Time{}, errors.New("timestamp is outside the supported RFC 3339 range")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Unix() < 0 {
		return time.Time{}, errors.New("timestamp is not a valid RFC 3339 instant")
	}
	return parsed, nil
}

func validateSignedEventReplayPreparation(
	claim *SignedEventReplayPreparation,
	eventJSON string,
	maxAgeSeconds uint64,
	storeName string,
	nowUnixSeconds int64,
) error {
	if err := validateSignedEventReplayPreparationFixedFields(claim, storeName); err != nil {
		return err
	}

	expectedDigest := sha256.Sum256([]byte(eventJSON))
	if claim.EventSHA256 != hex.EncodeToString(expectedDigest[:]) {
		return replayInvalidResult(
			storeName,
			"native replay preparation digest does not match exact input",
			nil,
		)
	}
	if claim.ReplayKey != expectedSignedEventReplayKey(claim.SignerID, claim.DocumentID) {
		return replayInvalidResult(
			storeName,
			"native replay preparation replay key does not match signer and document",
			nil,
		)
	}

	issuedAt, err := parseStrictReplayTimestamp(claim.Timestamp)
	if err != nil {
		return replayInvalidResult(
			storeName,
			"native replay preparation returned an invalid timestamp",
			err,
		)
	}
	issuedAtUnixSeconds := uint64(issuedAt.Unix())
	if nowUnixSeconds < 0 {
		return replayInvalidResult(storeName, "system clock predates the Unix epoch", nil)
	}
	if issuedAt.Unix() > nowUnixSeconds+int64(maxSignedEventFutureSkewSeconds) {
		return replayInvalidResult(
			storeName,
			"native replay preparation timestamp exceeds the allowed future skew",
			nil,
		)
	}
	if issuedAtUnixSeconds > ^uint64(0)-maxAgeSeconds ||
		issuedAtUnixSeconds+maxAgeSeconds != claim.ExpiresAtUnixSeconds {
		return replayInvalidResult(
			storeName,
			"native replay preparation expiry does not match timestamp plus max age",
			nil,
		)
	}
	if claim.ExpiresAtUnixSeconds > uint64(math.MaxInt64) {
		return replayInvalidResult(
			storeName,
			"native replay preparation expiry exceeds Go timestamp range",
			nil,
		)
	}
	if claim.ReplayTTLSeconds > uint64(math.MaxInt64/int64(time.Second)) {
		return replayInvalidResult(
			storeName,
			"native replay preparation TTL exceeds Go duration range",
			nil,
		)
	}
	if maxAgeSeconds > ^uint64(0)-maxSignedEventFutureSkewSeconds-1 ||
		claim.ReplayTTLSeconds > maxAgeSeconds+maxSignedEventFutureSkewSeconds+1 {
		return replayInvalidResult(
			storeName,
			"native replay preparation TTL exceeds the bounded freshness window",
			nil,
		)
	}
	if nowUnixSeconds > int64(claim.ExpiresAtUnixSeconds) {
		return &ReplayError{Code: ReplayErrorSignedEventExpired, message: "signed event expired before replay consumption"}
	}
	minimumSafeTTL := claim.ExpiresAtUnixSeconds - uint64(nowUnixSeconds) + 1
	if claim.ReplayTTLSeconds < minimumSafeTTL {
		return replayInvalidResult(
			storeName,
			"native replay preparation TTL ends before absolute event expiry",
			nil,
		)
	}
	return nil
}

func normalizeSignedEventReplayOptions(options *SignedEventReplayOptions) (uint64, time.Duration, error) {
	maxAge := DefaultSignedEventMaxAge
	storeTimeout := DefaultSignedEventStoreTimeout
	if options != nil {
		if options.MaxAge < 0 || options.StoreTimeout < 0 {
			return 0, 0, errors.New("signed-event replay durations must not be negative")
		}
		if options.MaxAge != 0 {
			maxAge = options.MaxAge
		}
		if options.StoreTimeout != 0 {
			storeTimeout = options.StoreTimeout
		}
	}
	if maxAge < time.Second || maxAge%time.Second != 0 {
		return 0, 0, errors.New("signed-event max age must be a positive whole number of seconds")
	}
	if storeTimeout <= 0 {
		return 0, 0, errors.New("replay-store timeout must be greater than zero")
	}
	return uint64(maxAge / time.Second), storeTimeout, nil
}

func replayStoreIsNil(store SharedReplayStore) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func replayStoreMetadata(store SharedReplayStore) (name string, scope ReplayStoreScope, panicked bool) {
	defer func() {
		if recover() != nil {
			name = ""
			scope = ""
			panicked = true
		}
	}()
	name = strings.TrimSpace(store.Name())
	scope = store.Scope()
	return name, scope, false
}

func validateSharedReplayStore(store SharedReplayStore) (string, error) {
	if replayStoreIsNil(store) {
		return "", &ReplayError{
			Code:    ReplayErrorStoreUnavailable,
			message: "shared replay store is unavailable",
		}
	}
	name, scope, panicked := replayStoreMetadata(store)
	if panicked {
		return "", &ReplayError{
			Code:    ReplayErrorStoreUnavailable,
			message: "shared replay store metadata could not be read",
		}
	}
	if name == "" {
		return "", &ReplayError{
			Code:    ReplayErrorStoreInvalidResult,
			message: "shared replay store must provide a non-empty name",
		}
	}
	if scope != ReplayStoreScopeShared {
		return name, &ReplayError{
			Code:    ReplayErrorStoreNotShared,
			message: "signed-event delivery requires a shared replay store",
		}
	}
	return name, nil
}

func contextReplayError(ctx context.Context, _ string, fallback error) error {
	contextErr := fallback
	if ctx != nil && ctx.Err() != nil {
		contextErr = ctx.Err()
	}
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return &ReplayError{
			Code:    ReplayErrorStoreTimeout,
			message: "shared replay store deadline elapsed",
		}
	}
	return &ReplayError{
		Code:    ReplayErrorStoreUnavailable,
		message: "shared replay store operation failed",
	}
}

func signedEventExpired(claim *SignedEventReplayPreparation) bool {
	return time.Now().Unix() > int64(claim.ExpiresAtUnixSeconds)
}

type replayStoreConsumeResult struct {
	fresh    bool
	err      error
	panicked bool
}

func callSharedReplayStore(
	store SharedReplayStore,
	ctx context.Context,
	key string,
	ttl time.Duration,
) (result replayStoreConsumeResult) {
	defer func() {
		if recover() != nil {
			result = replayStoreConsumeResult{panicked: true}
		}
	}()
	result.fresh, result.err = store.Consume(ctx, key, ttl)
	return result
}

func consumeSharedReplayStoreBounded(
	store SharedReplayStore,
	ctx context.Context,
	key string,
	ttl time.Duration,
) <-chan replayStoreConsumeResult {
	result := make(chan replayStoreConsumeResult, 1)
	go func() {
		result <- callSharedReplayStore(store, ctx, key, ttl)
	}()
	return result
}

func unwrapSignedEventWithReplayStore(
	ctx context.Context,
	eventJSON string,
	serverKeysJSON string,
	store SharedReplayStore,
	options *SignedEventReplayOptions,
	prepare signedEventReplayPreparer,
) (result *VerifiedSignedEvent, err error) {
	defer func() {
		var replayErr *ReplayError
		if errors.As(err, &replayErr) {
			slog.Warn(
				"JACS signed-event replay delivery rejected",
				"event", "jacs_security_outcome",
				"operation", "signed_event_replay",
				"outcome", "rejected",
				"error_code", replayErr.Code,
			)
		}
	}()
	storeName, err := validateSharedReplayStore(store)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, &ReplayError{
			Code:    ReplayErrorStoreUnavailable,
			message: "context must not be nil",
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, contextReplayError(ctx, storeName, err)
	}
	maxAgeSeconds, storeTimeout, err := normalizeSignedEventReplayOptions(options)
	if err != nil {
		return nil, &ReplayError{Code: ReplayErrorStoreInvalidResult, message: err.Error()}
	}

	claim, err := prepare(eventJSON, serverKeysJSON, maxAgeSeconds)
	if err != nil {
		return nil, err
	}
	if err := validateSignedEventReplayPreparation(
		claim,
		eventJSON,
		maxAgeSeconds,
		storeName,
		time.Now().Unix(),
	); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, contextReplayError(ctx, storeName, err)
	}

	consumeCtx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	consumeResult := consumeSharedReplayStoreBounded(
		store,
		consumeCtx,
		claim.ReplayKey,
		time.Duration(claim.ReplayTTLSeconds)*time.Second,
	)
	var consumed replayStoreConsumeResult
	select {
	case consumed = <-consumeResult:
		if err := consumeCtx.Err(); err != nil {
			return nil, contextReplayError(consumeCtx, storeName, err)
		}
	case <-consumeCtx.Done():
		return nil, contextReplayError(consumeCtx, storeName, consumeCtx.Err())
	}
	if consumed.panicked {
		return nil, &ReplayError{
			Code:    ReplayErrorStoreUnavailable,
			message: "shared replay store consume panicked",
		}
	}
	if consumed.err != nil {
		return nil, contextReplayError(consumeCtx, storeName, consumed.err)
	}
	if !consumed.fresh {
		return nil, &ReplayError{
			Code:    ReplayErrorDuplicate,
			message: "signed event replay key was already consumed",
		}
	}
	if signedEventExpired(claim) {
		return nil, &ReplayError{
			Code:    ReplayErrorSignedEventExpired,
			message: "signed event expired during replay consumption",
		}
	}

	// Parse only after successful replay consumption. Rust already strictly
	// parsed and verified this exact immutable string, including duplicate-name
	// rejection; RawMessage preserves its data representation for the caller.
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(eventJSON), &envelope); err != nil || len(envelope.Data) == 0 {
		if err == nil {
			err = errors.New("verified event has no data field")
		}
		return nil, &ReplayError{
			Code:    ReplayErrorStoreInvalidResult,
			message: "verified signed event could not be parsed after replay consumption",
		}
	}

	return &VerifiedSignedEvent{
		Status:         "verified",
		Verified:       true,
		ReplayConsumed: true,
		Data:           append(json.RawMessage(nil), envelope.Data...),
		SignerID:       claim.SignerID,
		Timestamp:      claim.Timestamp,
		Algorithm:      claim.Algorithm,
		DocumentID:     claim.DocumentID,
	}, nil
}
