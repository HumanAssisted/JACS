package jacs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingReplayStore struct {
	scope         ReplayStoreScope
	name          string
	err           error
	delay         time.Duration
	waitForDone   bool
	ignoreContext bool
	panicName     any
	panicScope    any
	panicConsume  any

	mu       sync.Mutex
	seen     map[string]struct{}
	calls    int
	lastKey  string
	lastTTL  time.Duration
	forceNew *bool
}

func newRecordingReplayStore() *recordingReplayStore {
	return &recordingReplayStore{
		scope: ReplayStoreScopeShared,
		name:  "test-shared",
		seen:  make(map[string]struct{}),
	}
}

func (s *recordingReplayStore) Scope() ReplayStoreScope {
	if s.panicScope != nil {
		panic(s.panicScope)
	}
	return s.scope
}

func (s *recordingReplayStore) Name() string {
	if s.panicName != nil {
		panic(s.panicName)
	}
	return s.name
}

func (s *recordingReplayStore) Consume(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if s.panicConsume != nil {
		panic(s.panicConsume)
	}
	s.mu.Lock()
	s.calls++
	s.lastKey = key
	s.lastTTL = ttl
	s.mu.Unlock()

	if s.waitForDone {
		<-ctx.Done()
		return false, ctx.Err()
	}
	if s.delay > 0 {
		if s.ignoreContext {
			time.Sleep(s.delay)
		} else {
			timer := time.NewTimer(s.delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}
	}
	if s.err != nil {
		return false, s.err
	}
	if s.forceNew != nil {
		return *s.forceNew, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.seen[key]; exists {
		return false, nil
	}
	s.seen[key] = struct{}{}
	return true, nil
}

func (s *recordingReplayStore) snapshot() (calls int, key string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.lastKey, s.lastTTL
}

type signedEventFixture struct {
	signer *JacsSimpleAgent
	event  string
	keys   string
	data   json.RawMessage
}

func newSignedEventFixture(t *testing.T) signedEventFixture {
	t.Helper()
	skipIfLibraryMissing(t)
	algorithm := "ed25519"
	signer, _, err := EphemeralSimpleAgent(&algorithm)
	if err != nil {
		t.Fatalf("EphemeralSimpleAgent: %v", err)
	}
	payload := json.RawMessage(`{"command":"send-email","attempt":7}`)
	event, err := signer.SignResponse(string(payload))
	if err != nil {
		signer.Close()
		t.Fatalf("SignResponse: %v", err)
	}
	var envelope struct {
		Data      json.RawMessage `json:"data"`
		Signature struct {
			AgentID string `json:"agentID"`
		} `json:"jacsSignature"`
	}
	if err := json.Unmarshal([]byte(event), &envelope); err != nil {
		signer.Close()
		t.Fatalf("parse signed event: %v", err)
	}
	pem, err := signer.GetPublicKeyPEM()
	if err != nil {
		signer.Close()
		t.Fatalf("GetPublicKeyPEM: %v", err)
	}
	keysBytes, err := json.Marshal(map[string]string{envelope.Signature.AgentID: pem})
	if err != nil {
		signer.Close()
		t.Fatalf("marshal keys: %v", err)
	}
	t.Cleanup(signer.Close)
	return signedEventFixture{
		signer: signer,
		event:  event,
		keys:   string(keysBytes),
		data:   append(json.RawMessage(nil), envelope.Data...),
	}
}

func TestSignResponseRejectsUnsafeCrossLanguageInteger(t *testing.T) {
	skipIfLibraryMissing(t)
	algorithm := "ed25519"
	signer, _, err := EphemeralSimpleAgent(&algorithm)
	if err != nil {
		t.Fatalf("EphemeralSimpleAgent: %v", err)
	}
	defer signer.Close()

	if signed, err := signer.SignResponse(`{"attempt":9007199254740993}`); err == nil {
		t.Fatalf("unsafe integer was signed for cross-language use: %s", signed)
	}
}

func requireReplayCode(t *testing.T, err error, want ReplayErrorCode) {
	t.Helper()
	var replayErr *ReplayError
	if !errors.As(err, &replayErr) {
		t.Fatalf("error %T %v is not *ReplayError", err, err)
	}
	if replayErr.Code != want {
		t.Fatalf("replay code = %q, want %q (error: %v)", replayErr.Code, want, err)
	}
}

func TestPrepareSignedEventReplayAgentAndSimple(t *testing.T) {
	fixture := newSignedEventFixture(t)

	simpleClaim, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("simple preparation: %v", err)
	}
	if simpleClaim.Status != "crypto_verified_replay_pending" ||
		!simpleClaim.CryptographicallyVerified || !simpleClaim.FreshnessVerified ||
		simpleClaim.ReplayConsumed {
		t.Fatalf("unexpected simple claim: %+v", simpleClaim)
	}
	if simpleClaim.ReplayKey == "" || simpleClaim.ReplayTTLSeconds == 0 || simpleClaim.EventSHA256 == "" {
		t.Fatalf("incomplete simple claim: %+v", simpleClaim)
	}

	agent, err := NewJacsAgent()
	if err != nil {
		t.Fatalf("NewJacsAgent: %v", err)
	}
	defer agent.Close()
	agentClaim, err := agent.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("agent preparation: %v", err)
	}
	if agentClaim.ReplayKey != simpleClaim.ReplayKey ||
		agentClaim.EventSHA256 != simpleClaim.EventSHA256 ||
		agentClaim.ExpiresAtUnixSeconds != simpleClaim.ExpiresAtUnixSeconds {
		t.Fatalf("agent/simple claim mismatch:\nagent=%+v\nsimple=%+v", agentClaim, simpleClaim)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(simpleClaim.RawJSON), &raw); err != nil {
		t.Fatalf("parse raw claim: %v", err)
	}
	for _, forbidden := range []string{"data", "valid", "verified"} {
		if _, found := raw[forbidden]; found {
			t.Fatalf("preparation leaked forbidden field %q: %s", forbidden, simpleClaim.RawJSON)
		}
	}
}

func TestUnwrapSignedEventWithReplayStoreReleasesExactDataAndProvenance(t *testing.T) {
	fixture := newSignedEventFixture(t)
	claim, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("prepare fixture claim: %v", err)
	}
	store := newRecordingReplayStore()

	result, err := fixture.signer.UnwrapSignedEventWithReplayStore(
		context.Background(), fixture.event, fixture.keys, store, nil,
	)
	if err != nil {
		t.Fatalf("UnwrapSignedEventWithReplayStore: %v", err)
	}
	if result.Status != "verified" || !result.Verified || !result.ReplayConsumed {
		t.Fatalf("unexpected verified result: %+v", result)
	}
	if result.SignerID != claim.SignerID || result.Timestamp != claim.Timestamp ||
		result.Algorithm != claim.Algorithm || result.DocumentID != claim.DocumentID {
		t.Fatalf("provenance mismatch: result=%+v claim=%+v", result, claim)
	}
	if string(result.Data) != string(fixture.data) {
		t.Fatalf("data changed: got %s want %s", result.Data, fixture.data)
	}
	calls, key, ttl := store.snapshot()
	if calls != 1 || key != claim.ReplayKey || ttl != time.Duration(claim.ReplayTTLSeconds)*time.Second {
		t.Fatalf("store call = calls:%d key:%q ttl:%s; claim=%+v", calls, key, ttl, claim)
	}
}

func TestUnwrapSignedEventInvalidCryptoNeverCallsStore(t *testing.T) {
	fixture := newSignedEventFixture(t)
	var envelope map[string]any
	if err := json.Unmarshal([]byte(fixture.event), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["data"] = map[string]any{"command": "attacker"}
	tampered, _ := json.Marshal(envelope)
	store := newRecordingReplayStore()

	result, err := fixture.signer.UnwrapSignedEventWithReplayStore(
		context.Background(), string(tampered), fixture.keys, store, nil,
	)
	if err == nil || result != nil {
		t.Fatalf("tampered event released: result=%+v err=%v", result, err)
	}
	if calls, _, _ := store.snapshot(); calls != 0 {
		t.Fatalf("invalid crypto called store %d times", calls)
	}
}

func TestUnwrapSignedEventRejectsInvalidPreparationBeforeStore(t *testing.T) {
	fixture := newSignedEventFixture(t)
	base, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("prepare base claim: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*SignedEventReplayPreparation)
		code   ReplayErrorCode
	}{
		{
			name: "fixed claim value",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.CryptographicallyVerified = false
			},
			code: ReplayErrorStoreInvalidResult,
		},
		{
			name: "exact event digest",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.EventSHA256 = "00"
			},
			code: ReplayErrorStoreInvalidResult,
		},
		{
			name: "replay key version",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.ReplayKey = "unscoped-key"
			},
			code: ReplayErrorStoreInvalidResult,
		},
		{
			name: "expiry math",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.ExpiresAtUnixSeconds++
			},
			code: ReplayErrorStoreInvalidResult,
		},
		{
			name: "ttl coverage",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.ReplayTTLSeconds = 1
			},
			code: ReplayErrorStoreInvalidResult,
		},
		{
			name: "already expired",
			mutate: func(claim *SignedEventReplayPreparation) {
				now := time.Now().Unix()
				claim.Timestamp = time.Unix(now-301, 0).UTC().Format(time.RFC3339)
				claim.ExpiresAtUnixSeconds = uint64(now - 1)
				claim.ReplayTTLSeconds = 1
			},
			code: ReplayErrorSignedEventExpired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim := *base
			test.mutate(&claim)
			store := newRecordingReplayStore()
			prepare := func(_, _ string, _ uint64) (*SignedEventReplayPreparation, error) {
				return &claim, nil
			}

			result, err := unwrapSignedEventWithReplayStore(
				context.Background(),
				fixture.event,
				fixture.keys,
				store,
				&SignedEventReplayOptions{MaxAge: 300 * time.Second},
				prepare,
			)
			if result != nil || err == nil {
				t.Fatalf("invalid preparation released payload: result=%+v err=%v", result, err)
			}
			requireReplayCode(t, err, test.code)
			if calls, _, _ := store.snapshot(); calls != 0 {
				t.Fatalf("invalid preparation called Consume %d times", calls)
			}
		})
	}
}

func TestDecodeSignedEventReplayPreparationRequiresExactContractFields(t *testing.T) {
	fixture := newSignedEventFixture(t)
	claim, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("prepare claim: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(claim.RawJSON), &fields); err != nil {
		t.Fatalf("parse preparation: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]json.RawMessage)
	}{
		{
			name: "missing",
			mutate: func(fields map[string]json.RawMessage) {
				delete(fields, "algorithm")
			},
		},
		{
			name: "unexpected",
			mutate: func(fields map[string]json.RawMessage) {
				fields["futureField"] = json.RawMessage(`true`)
			},
		},
		{
			name: "forbidden payload",
			mutate: func(fields map[string]json.RawMessage) {
				fields["data"] = json.RawMessage(`{"secret":true}`)
			},
		},
		{
			name: "wrong type",
			mutate: func(fields map[string]json.RawMessage) {
				fields["contractVersion"] = json.RawMessage(`true`)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyFields := make(map[string]json.RawMessage, len(fields))
			for key, value := range fields {
				copyFields[key] = append(json.RawMessage(nil), value...)
			}
			test.mutate(copyFields)
			raw, err := json.Marshal(copyFields)
			if err != nil {
				t.Fatalf("marshal mutated preparation: %v", err)
			}
			decoded, err := decodeSignedEventReplayPreparation(string(raw))
			if decoded != nil || err == nil {
				t.Fatalf("invalid preparation decoded: claim=%+v err=%v", decoded, err)
			}
			requireReplayCode(t, err, ReplayErrorStoreInvalidResult)
		})
	}
}

func TestDecodeSignedEventReplayPreparationRejectsDuplicateDecodedFields(t *testing.T) {
	fixture := newSignedEventFixture(t)
	claim, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("prepare claim: %v", err)
	}
	duplicate := strings.Replace(
		claim.RawJSON,
		`"status":"crypto_verified_replay_pending"`,
		`"status":"verified","st\u0061tus":"crypto_verified_replay_pending"`,
		1,
	)
	if duplicate == claim.RawJSON {
		t.Fatalf("fixture did not contain expected status field: %s", claim.RawJSON)
	}

	decoded, err := decodeSignedEventReplayPreparation(duplicate)
	if decoded != nil || err == nil {
		t.Fatalf("duplicate preparation decoded: claim=%+v err=%v", decoded, err)
	}
	requireReplayCode(t, err, ReplayErrorStoreInvalidResult)
}

func TestUnwrapSignedEventRejectsReplayClaimSubstitutionAndRetentionAbuse(t *testing.T) {
	fixture := newSignedEventFixture(t)
	base, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("prepare base claim: %v", err)
	}
	now := time.Now().Unix()

	tests := []struct {
		name   string
		mutate func(*SignedEventReplayPreparation)
	}{
		{
			name: "prefixed but wrong replay key",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.ReplayKey = "jacs-replay-v1:attacker-controlled"
			},
		},
		{
			name: "signer substitution with unchanged key",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.SignerID = "attacker-signer"
			},
		},
		{
			name: "document substitution with unchanged key",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.DocumentID = "attacker-document"
			},
		},
		{
			name: "timestamp beyond future skew",
			mutate: func(claim *SignedEventReplayPreparation) {
				issued := now + 301
				claim.Timestamp = time.Unix(issued, 0).UTC().Format(time.RFC3339)
				claim.ExpiresAtUnixSeconds = uint64(issued + 300)
				claim.ReplayTTLSeconds = 602
			},
		},
		{
			name: "ttl exceeds bounded freshness window",
			mutate: func(claim *SignedEventReplayPreparation) {
				claim.ReplayTTLSeconds = 602
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim := *base
			test.mutate(&claim)
			store := newRecordingReplayStore()
			prepare := func(_, _ string, _ uint64) (*SignedEventReplayPreparation, error) {
				return &claim, nil
			}

			result, err := unwrapSignedEventWithReplayStore(
				context.Background(), fixture.event, fixture.keys, store,
				&SignedEventReplayOptions{MaxAge: 300 * time.Second}, prepare,
			)
			if result != nil || err == nil {
				t.Fatalf("invalid claim released payload: result=%+v err=%v", result, err)
			}
			requireReplayCode(t, err, ReplayErrorStoreInvalidResult)
			if calls, _, _ := store.snapshot(); calls != 0 {
				t.Fatalf("invalid claim called Consume %d times", calls)
			}
		})
	}
}

func TestValidateSignedEventReplayPreparationUsesUTF8ByteLengthInExactKey(t *testing.T) {
	fixture := newSignedEventFixture(t)
	claim, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("prepare claim: %v", err)
	}
	claim.SignerID = "签名者"
	scope := "signed-event:" + claim.SignerID
	claim.ReplayKey = fmt.Sprintf("jacs-replay-v1:%d:%s:%s", len([]byte(scope)), scope, claim.DocumentID)
	if err := validateSignedEventReplayPreparation(
		claim, fixture.event, 300, "test-shared", time.Now().Unix(),
	); err != nil {
		t.Fatalf("UTF-8 byte-length replay key rejected: %v", err)
	}

	claim.ReplayKey = fmt.Sprintf("jacs-replay-v1:%d:%s:%s", len([]rune(scope)), scope, claim.DocumentID)
	err = validateSignedEventReplayPreparation(
		claim, fixture.event, 300, "test-shared", time.Now().Unix(),
	)
	requireReplayCode(t, err, ReplayErrorStoreInvalidResult)
}

func TestValidateSignedEventReplayPreparationRejectsNonStrictRFC3339(t *testing.T) {
	fixture := newSignedEventFixture(t)
	base, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 300)
	if err != nil {
		t.Fatalf("prepare claim: %v", err)
	}

	for _, timestamp := range []string{
		"2026-07-11T00:00:00,5Z",
		"2026-07-11T00:00:00+24:00",
		"2026-02-30T00:00:00Z",
		"2026-07-11T00:00:00+00:60",
	} {
		t.Run(timestamp, func(t *testing.T) {
			claim := *base
			claim.Timestamp = timestamp
			err := validateSignedEventReplayPreparation(
				&claim, fixture.event, 300, "test-shared", time.Now().Unix(),
			)
			requireReplayCode(t, err, ReplayErrorStoreInvalidResult)
		})
	}
}

func TestUnwrapSignedEventReplayStoreFailuresFailClosed(t *testing.T) {
	fixture := newSignedEventFixture(t)
	falseValue := false

	tests := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		new  func() *recordingReplayStore
		opts *SignedEventReplayOptions
		code ReplayErrorCode
	}{
		{
			name: "duplicate false",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			new: func() *recordingReplayStore {
				s := newRecordingReplayStore()
				s.forceNew = &falseValue
				return s
			},
			code: ReplayErrorDuplicate,
		},
		{
			name: "backend error",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			new: func() *recordingReplayStore {
				s := newRecordingReplayStore()
				s.err = errors.New("redis unavailable")
				return s
			},
			code: ReplayErrorStoreUnavailable,
		},
		{
			name: "process local",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			new: func() *recordingReplayStore {
				s := newRecordingReplayStore()
				s.scope = ReplayStoreScopeProcessLocal
				return s
			},
			code: ReplayErrorStoreNotShared,
		},
		{
			name: "missing name",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			new: func() *recordingReplayStore {
				s := newRecordingReplayStore()
				s.name = " "
				return s
			},
			code: ReplayErrorStoreInvalidResult,
		},
		{
			name: "timeout",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			new: func() *recordingReplayStore {
				s := newRecordingReplayStore()
				s.waitForDone = true
				return s
			},
			opts: &SignedEventReplayOptions{StoreTimeout: 20 * time.Millisecond},
			code: ReplayErrorStoreTimeout,
		},
		{
			name: "caller canceled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			new:  newRecordingReplayStore,
			code: ReplayErrorStoreUnavailable,
		},
		{
			name: "caller canceled during consume",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(20*time.Millisecond, cancel)
				return ctx, cancel
			},
			new: func() *recordingReplayStore {
				s := newRecordingReplayStore()
				s.waitForDone = true
				return s
			},
			opts: &SignedEventReplayOptions{StoreTimeout: time.Second},
			code: ReplayErrorStoreUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.ctx()
			defer cancel()
			store := test.new()
			result, err := fixture.signer.UnwrapSignedEventWithReplayStore(
				ctx, fixture.event, fixture.keys, store, test.opts,
			)
			if result != nil || err == nil {
				t.Fatalf("failure released payload: result=%+v err=%v", result, err)
			}
			requireReplayCode(t, err, test.code)
			if test.code == ReplayErrorStoreNotShared || test.code == ReplayErrorStoreInvalidResult || test.name == "caller canceled" {
				if calls, _, _ := store.snapshot(); calls != 0 {
					t.Fatalf("pre-store rejection called Consume %d times", calls)
				}
			}
		})
	}
}

func TestUnwrapSignedEventNonCooperativeStoreTimeoutIsBounded(t *testing.T) {
	fixture := newSignedEventFixture(t)
	store := newRecordingReplayStore()
	store.delay = 250 * time.Millisecond
	store.ignoreContext = true

	started := time.Now()
	result, err := fixture.signer.UnwrapSignedEventWithReplayStore(
		context.Background(), fixture.event, fixture.keys, store,
		&SignedEventReplayOptions{StoreTimeout: 10 * time.Millisecond},
	)
	elapsed := time.Since(started)
	if result != nil || err == nil {
		t.Fatalf("noncooperative timeout released payload: result=%+v err=%v", result, err)
	}
	requireReplayCode(t, err, ReplayErrorStoreTimeout)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("noncooperative store blocked helper for %s", elapsed)
	}
}

func TestUnwrapSignedEventRecoversAndRedactsStorePanics(t *testing.T) {
	fixture := newSignedEventFixture(t)
	secret := "redis://operator:super-secret@replay.internal/event-payload-canary"

	tests := []struct {
		name      string
		configure func(*recordingReplayStore)
		wantCalls int
	}{
		{
			name: "name panic",
			configure: func(store *recordingReplayStore) {
				store.panicName = secret
			},
			wantCalls: 0,
		},
		{
			name: "scope panic",
			configure: func(store *recordingReplayStore) {
				store.panicScope = secret
			},
			wantCalls: 0,
		},
		{
			name: "consume panic",
			configure: func(store *recordingReplayStore) {
				store.panicConsume = secret
			},
			wantCalls: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newRecordingReplayStore()
			test.configure(store)
			result, err := fixture.signer.UnwrapSignedEventWithReplayStore(
				context.Background(), fixture.event, fixture.keys, store, nil,
			)
			if result != nil || err == nil {
				t.Fatalf("store panic released payload: result=%+v err=%v", result, err)
			}
			requireReplayCode(t, err, ReplayErrorStoreUnavailable)
			if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%+v", err), secret) {
				t.Fatalf("store panic leaked secret: %v", err)
			}
			if unwrapped := errors.Unwrap(err); unwrapped != nil {
				t.Fatalf("store panic exposed raw cause: %v", unwrapped)
			}
			if calls, _, _ := store.snapshot(); calls != test.wantCalls {
				t.Fatalf("store calls=%d, want %d", calls, test.wantCalls)
			}
		})
	}
}

func TestUnwrapSignedEventRedactsBackendErrorsAndStoreName(t *testing.T) {
	fixture := newSignedEventFixture(t)
	secret := "redis://operator:super-secret@replay.internal/event-payload-canary"
	store := newRecordingReplayStore()
	store.name = secret
	store.err = errors.New(secret)

	result, err := fixture.signer.UnwrapSignedEventWithReplayStore(
		context.Background(), fixture.event, fixture.keys, store, nil,
	)
	if result != nil || err == nil {
		t.Fatalf("backend failure released payload: result=%+v err=%v", result, err)
	}
	requireReplayCode(t, err, ReplayErrorStoreUnavailable)
	for _, rendered := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err)} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("backend failure leaked secret in %q", rendered)
		}
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("backend failure exposed raw cause: %v", unwrapped)
	}
}

func TestReplayFailureEmitsOneStructuredRedactedWarning(t *testing.T) {
	fixture := newSignedEventFixture(t)
	secret := "redis://operator:do-not-log@replay.internal/private-key"
	store := newRecordingReplayStore()
	store.err = errors.New(secret)

	var output bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })

	result, err := fixture.signer.UnwrapSignedEventWithReplayStore(
		context.Background(), fixture.event, fixture.keys, store, nil,
	)
	if result != nil || err == nil {
		t.Fatalf("backend failure released payload: result=%+v err=%v", result, err)
	}
	requireReplayCode(t, err, ReplayErrorStoreUnavailable)

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("security warning count = %d, want 1: %s", len(lines), output.String())
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("security warning is not structured JSON: %v: %s", err, lines[0])
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve replay test source path")
	}
	contractBytes, readErr := os.ReadFile(filepath.Join(
		filepath.Dir(thisFile), "../binding-core/tests/fixtures/external_replay_contract.json",
	))
	if readErr != nil {
		t.Fatalf("read replay contract: %v", readErr)
	}
	var contract struct {
		Observability struct {
			Level          string `json:"level"`
			Event          string `json:"event"`
			Operation      string `json:"operation"`
			Outcome        string `json:"outcome"`
			ErrorCodeField string `json:"errorCodeField"`
		} `json:"observability"`
	}
	if err := json.Unmarshal(contractBytes, &contract); err != nil {
		t.Fatalf("parse replay contract: %v", err)
	}
	level, _ := event["level"].(string)
	if strings.ToLower(level) != contract.Observability.Level ||
		event["event"] != contract.Observability.Event ||
		event["operation"] != contract.Observability.Operation ||
		event["outcome"] != contract.Observability.Outcome ||
		event[contract.Observability.ErrorCodeField] != string(ReplayErrorStoreUnavailable) {
		t.Fatalf("unexpected security warning: %#v", event)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("security warning leaked backend details: %s", output.String())
	}
}

func TestUnwrapSignedEventSharedStoreExactlyOnceAcrossAgents(t *testing.T) {
	fixture := newSignedEventFixture(t)
	verifierA, _, err := EphemeralSimpleAgent(nil)
	if err != nil {
		t.Fatalf("verifier A: %v", err)
	}
	defer verifierA.Close()
	verifierB, _, err := EphemeralSimpleAgent(nil)
	if err != nil {
		t.Fatalf("verifier B: %v", err)
	}
	defer verifierB.Close()
	store := newRecordingReplayStore()

	const workers = 64
	start := make(chan struct{})
	var successes atomic.Int32
	var duplicates atomic.Int32
	var unexpectedMu sync.Mutex
	var unexpected []error
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		agent := verifierA
		if i%2 == 1 {
			agent = verifierB
		}
		go func(agent *JacsSimpleAgent) {
			defer wg.Done()
			<-start
			result, err := agent.UnwrapSignedEventWithReplayStore(
				context.Background(), fixture.event, fixture.keys, store, nil,
			)
			if err == nil {
				if result == nil || !result.Verified || !result.ReplayConsumed {
					unexpectedMu.Lock()
					unexpected = append(unexpected, fmt.Errorf("invalid success: %+v", result))
					unexpectedMu.Unlock()
					return
				}
				successes.Add(1)
				return
			}
			var replayErr *ReplayError
			if errors.As(err, &replayErr) && replayErr.Code == ReplayErrorDuplicate {
				duplicates.Add(1)
				return
			}
			unexpectedMu.Lock()
			unexpected = append(unexpected, err)
			unexpectedMu.Unlock()
		}(agent)
	}
	close(start)
	wg.Wait()

	if len(unexpected) != 0 {
		t.Fatalf("unexpected errors: %v", unexpected)
	}
	if successes.Load() != 1 || duplicates.Load() != workers-1 {
		t.Fatalf("successes=%d duplicates=%d, want 1/%d", successes.Load(), duplicates.Load(), workers-1)
	}
	if calls, _, _ := store.snapshot(); calls != workers {
		t.Fatalf("store calls=%d, want %d", calls, workers)
	}
}

func TestUnwrapSignedEventExpiryCrossingConsumesButReleasesNoPayload(t *testing.T) {
	fixture := newSignedEventFixture(t)
	claim, err := fixture.signer.PrepareSignedEventReplay(fixture.event, fixture.keys, 1)
	if err != nil {
		t.Fatalf("prepare one-second claim: %v", err)
	}
	releaseAt := time.Unix(int64(claim.ExpiresAtUnixSeconds)+1, 0)
	delay := time.Until(releaseAt)
	if delay < 0 {
		delay = 0
	}
	store := newRecordingReplayStore()
	store.delay = delay

	result, err := fixture.signer.UnwrapSignedEventWithReplayStore(
		context.Background(), fixture.event, fixture.keys, store,
		&SignedEventReplayOptions{MaxAge: time.Second, StoreTimeout: 5 * time.Second},
	)
	if result != nil || err == nil {
		t.Fatalf("expired-after-consume event released: result=%+v err=%v", result, err)
	}
	requireReplayCode(t, err, ReplayErrorSignedEventExpired)
	if calls, _, _ := store.snapshot(); calls != 1 {
		t.Fatalf("store calls=%d, want 1", calls)
	}
}

func TestReplayMethodsRejectClosedAndNilHandlesWithoutStoreAccess(t *testing.T) {
	fixture := newSignedEventFixture(t)
	store := newRecordingReplayStore()

	simple, _, err := EphemeralSimpleAgent(nil)
	if err != nil {
		t.Fatal(err)
	}
	simple.Close()
	if _, err := simple.PrepareSignedEventReplay(fixture.event, fixture.keys, 300); !errors.Is(err, errSimpleAgentClosed) {
		t.Fatalf("closed simple prepare error=%v", err)
	}
	if result, err := simple.UnwrapSignedEventWithReplayStore(context.Background(), fixture.event, fixture.keys, store, nil); result != nil || !errors.Is(err, errSimpleAgentClosed) {
		t.Fatalf("closed simple unwrap result=%+v err=%v", result, err)
	}

	agent, err := NewJacsAgent()
	if err != nil {
		t.Fatal(err)
	}
	agent.Close()
	if _, err := agent.PrepareSignedEventReplay(fixture.event, fixture.keys, 300); !errors.Is(err, errAgentClosed) {
		t.Fatalf("closed agent prepare error=%v", err)
	}
	if result, err := agent.UnwrapSignedEventWithReplayStore(context.Background(), fixture.event, fixture.keys, store, nil); result != nil || !errors.Is(err, errAgentClosed) {
		t.Fatalf("closed agent unwrap result=%+v err=%v", result, err)
	}

	var nilSimple *JacsSimpleAgent
	if _, err := nilSimple.PrepareSignedEventReplay(fixture.event, fixture.keys, 300); !errors.Is(err, errSimpleAgentClosed) {
		t.Fatalf("nil simple error=%v", err)
	}
	if result, err := nilSimple.UnwrapSignedEventWithReplayStore(context.Background(), fixture.event, fixture.keys, store, nil); result != nil || !errors.Is(err, errSimpleAgentClosed) {
		t.Fatalf("nil simple unwrap result=%+v err=%v", result, err)
	}
	var nilAgent *JacsAgent
	if _, err := nilAgent.PrepareSignedEventReplay(fixture.event, fixture.keys, 300); !errors.Is(err, errAgentClosed) {
		t.Fatalf("nil agent error=%v", err)
	}
	if result, err := nilAgent.UnwrapSignedEventWithReplayStore(context.Background(), fixture.event, fixture.keys, store, nil); result != nil || !errors.Is(err, errAgentClosed) {
		t.Fatalf("nil agent unwrap result=%+v err=%v", result, err)
	}
	if calls, _, _ := store.snapshot(); calls != 0 {
		t.Fatalf("closed/nil handles called store %d times", calls)
	}
}

func TestConcurrentReplayPreparationErrorsStayWithTheirCallingGoroutine(t *testing.T) {
	skipIfLibraryMissing(t)
	simple, _, err := EphemeralSimpleAgent(nil)
	if err != nil {
		t.Fatalf("simple agent: %v", err)
	}
	defer simple.Close()
	agent, err := NewJacsAgent()
	if err != nil {
		t.Fatalf("full agent: %v", err)
	}
	defer agent.Close()

	tests := []struct {
		name    string
		prepare func(string, string, uint64) (*SignedEventReplayPreparation, error)
	}{
		{name: "simple", prepare: simple.PrepareSignedEventReplay},
		{name: "agent", prepare: agent.PrepareSignedEventReplay},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const workers = 256
			start := make(chan struct{})
			errorsByWorker := make([]error, workers)
			var wg sync.WaitGroup
			wg.Add(workers)
			for index := 0; index < workers; index++ {
				index := index
				go func() {
					defer wg.Done()
					<-start
					canary := fmt.Sprintf("replay-error-canary-%03d", index)
					keys := fmt.Sprintf(`{"%s":""}`, canary)
					result, err := test.prepare("{}", keys, 300)
					if result != nil || err == nil || !strings.Contains(err.Error(), canary) {
						errorsByWorker[index] = fmt.Errorf(
							"result=%+v error=%v did not contain %q",
							result,
							err,
							canary,
						)
					}
				}()
			}
			close(start)
			wg.Wait()
			for index, err := range errorsByWorker {
				if err != nil {
					t.Fatalf("worker %d received a missing or cross-call FFI error: %v", index, err)
				}
			}
		})
	}
}

func TestExternalReplayErrorCodesMatchContractFixture(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixturePath := filepath.Join(filepath.Dir(thisFile), "../binding-core/tests/fixtures/external_replay_contract.json")
	contents, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read external replay contract: %v", err)
	}
	var contract struct {
		SharedStore struct {
			RequiredErrors []string          `json:"requiredErrors"`
			ErrorSemantics map[string]string `json:"errorSemantics"`
		} `json:"sharedStore"`
	}
	if err := json.Unmarshal(contents, &contract); err != nil {
		t.Fatalf("parse external replay contract: %v", err)
	}
	want := append([]string(nil), contract.SharedStore.RequiredErrors...)
	got := []string{
		string(ReplayErrorDuplicate),
		string(ReplayErrorStoreUnavailable),
		string(ReplayErrorStoreTimeout),
		string(ReplayErrorStoreInvalidResult),
		string(ReplayErrorStoreNotShared),
		string(ReplayErrorSignedEventExpired),
	}
	sort.Strings(want)
	sort.Strings(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Go replay error codes=%v, contract=%v", got, want)
	}
	wantSemantics := map[string]string{
		"wrongScope":           string(ReplayErrorStoreNotShared),
		"invalidName":          string(ReplayErrorStoreInvalidResult),
		"metadataUnavailable":  string(ReplayErrorStoreUnavailable),
		"backendUnavailable":   string(ReplayErrorStoreUnavailable),
		"backendTimeout":       string(ReplayErrorStoreTimeout),
		"duplicate":            string(ReplayErrorDuplicate),
		"invalidBackendResult": string(ReplayErrorStoreInvalidResult),
		"invalidPreparation":   string(ReplayErrorStoreInvalidResult),
		"expired":              string(ReplayErrorSignedEventExpired),
	}
	if fmt.Sprint(contract.SharedStore.ErrorSemantics) != fmt.Sprint(wantSemantics) {
		t.Fatalf(
			"Go replay error semantics=%v, contract=%v",
			wantSemantics,
			contract.SharedStore.ErrorSemantics,
		)
	}
}
