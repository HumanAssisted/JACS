package jacs

import "encoding/json"

// AgentInfo contains information about a created or loaded agent.
type AgentInfo struct {
	// AgentID is the unique identifier for the agent (UUID).
	AgentID string `json:"agent_id"`
	// Name is the human-readable name of the agent.
	Name string `json:"name"`
	// PublicKeyPath is the path to the public key file.
	PublicKeyPath string `json:"public_key_path"`
	// ConfigPath is the path to the configuration file.
	ConfigPath string `json:"config_path"`
}

// SignedDocument represents a signed JACS document.
type SignedDocument struct {
	// Raw is the full JSON string of the signed JACS document.
	Raw string `json:"raw"`
	// DocumentID is the unique identifier for this document (UUID).
	DocumentID string `json:"document_id"`
	// AgentID is the ID of the agent that signed this document.
	AgentID string `json:"agent_id"`
	// Timestamp is the ISO 8601 timestamp of when the document was signed.
	Timestamp string `json:"timestamp"`
}

// VerificationResult contains the result of verifying a signed document.
type VerificationResult struct {
	// Valid indicates whether the signature is valid.
	Valid bool `json:"valid"`
	// Data is the original data that was signed.
	Data interface{} `json:"data"`
	// SignerID is the ID of the agent that signed the document.
	SignerID string `json:"signer_id"`
	// SignerName is the name of the signer (if available in trust store).
	SignerName string `json:"signer_name,omitempty"`
	// Timestamp is the ISO 8601 timestamp of when the document was signed.
	Timestamp string `json:"timestamp"`
	// Attachments contains any file attachments in the document.
	Attachments []Attachment `json:"attachments,omitempty"`
	// Errors contains error messages if verification failed.
	Errors []string `json:"errors,omitempty"`
}

// AgreementV2Role is a named role accepted by
// [JacsSimpleAgent.SignAgreementV2]. The signing method still accepts the raw
// lowercase string; these constants document and standardize the allowed
// values so callers do not hardcode magic strings.
type AgreementV2Role string

const (
	// AgreementV2RoleSigner is a binding party whose signature counts toward quorum.
	AgreementV2RoleSigner AgreementV2Role = "signer"
	// AgreementV2RoleWitness attests to having observed the agreement without binding consent.
	AgreementV2RoleWitness AgreementV2Role = "witness"
	// AgreementV2RoleNotary provides an authoritative third-party attestation.
	AgreementV2RoleNotary AgreementV2Role = "notary"
)

// String returns the wire value of the role.
func (r AgreementV2Role) String() string { return string(r) }

// AgreementV2VerificationReport is returned by
// [JacsSimpleAgent.VerifyAgreementV2].
type AgreementV2VerificationReport struct {
	Valid                    bool     `json:"valid"`
	Status                   string   `json:"status"`
	ExpectedStatus           string   `json:"expectedStatus"`
	RecomputedAgreementHash  string   `json:"recomputedAgreementHash"`
	RecomputedTranscriptHash string   `json:"recomputedTranscriptHash"`
	SignerCount              int      `json:"signerCount"`
	WitnessCount             int      `json:"witnessCount"`
	NotaryCount              int      `json:"notaryCount"`
	Errors                   []string `json:"errors,omitempty"`
}

// AgreementV2MergeAnalysis is returned by
// [JacsSimpleAgent.DetectAgreementV2BranchConflict].
type AgreementV2MergeAnalysis struct {
	SameDocument             bool     `json:"sameDocument"`
	SameParent               bool     `json:"sameParent"`
	AutoMergeable            bool     `json:"autoMergeable"`
	ConflictFields           []string `json:"conflictFields,omitempty"`
	LeftChangedFields        []string `json:"leftChangedFields,omitempty"`
	RightChangedFields       []string `json:"rightChangedFields,omitempty"`
	LeftTranscriptAdditions  int      `json:"leftTranscriptAdditions"`
	RightTranscriptAdditions int      `json:"rightTranscriptAdditions"`
	Errors                   []string `json:"errors,omitempty"`
}

// AgreementV2CreateInput is an optional typed convenience for building the JSON
// passed to [JacsSimpleAgent.CreateAgreementV2]. Callers may still pass a raw
// JSON string; marshal this struct with encoding/json to produce that string.
// Field names match the Rust CreateAgreementV2 wire shape (camelCase).
type AgreementV2CreateInput struct {
	Question        string                 `json:"question,omitempty"`
	Context         string                 `json:"context,omitempty"`
	Terms           map[string]interface{} `json:"terms,omitempty"`
	RequiredSigners []string               `json:"requiredSigners,omitempty"`
	Policy          map[string]interface{} `json:"policy,omitempty"`
}

// JSON marshals the input to the JSON string accepted by CreateAgreementV2.
func (in AgreementV2CreateInput) JSON() (string, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// AgreementV2Mutation is an optional typed convenience for building the JSON
// passed to [JacsSimpleAgent.ApplyAgreementV2] /
// [JacsSimpleAgent.ResolveAgreementV2BranchConflict]. Field names match the
// Rust AgreementV2Mutation wire shape (camelCase).
type AgreementV2Mutation struct {
	SetTerms          map[string]interface{}   `json:"setTerms,omitempty"`
	AppendTranscript  []map[string]interface{} `json:"appendTranscript,omitempty"`
	SetStatus         string                   `json:"setStatus,omitempty"`
	AddRequiredSigner string                   `json:"addRequiredSigner,omitempty"`
}

// JSON marshals the mutation to the JSON string accepted by ApplyAgreementV2.
func (m AgreementV2Mutation) JSON() (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Attachment represents a file attachment in a signed document.
type Attachment struct {
	// Filename is the original filename.
	Filename string `json:"filename"`
	// MimeType is the MIME type of the file.
	MimeType string `json:"mime_type"`
	// Content is the file content (decoded if embedded).
	Content []byte `json:"content,omitempty"`
	// Hash is the SHA-256 hash of the original file.
	Hash string `json:"hash"`
	// Embedded indicates whether the file was embedded (true) or referenced (false).
	Embedded bool `json:"embedded"`
}

// AttestationVerificationResult contains the result of verifying an attestation.
type AttestationVerificationResult struct {
	// Valid indicates whether the attestation is valid overall.
	Valid bool `json:"valid"`
	// Crypto contains cryptographic verification results.
	Crypto AttestationCrypto `json:"crypto"`
	// Evidence contains per-evidence-ref verification results (full tier only).
	Evidence []AttestationEvidenceResult `json:"evidence,omitempty"`
	// Chain contains derivation chain verification results (full tier only).
	Chain *AttestationChainResult `json:"chain,omitempty"`
	// Errors contains error messages for any failures.
	Errors []string `json:"errors,omitempty"`
}

// AttestationCrypto contains cryptographic verification results.
type AttestationCrypto struct {
	// SignatureValid indicates the signature matches the document and public key.
	SignatureValid bool `json:"signature_valid"`
	// HashValid indicates the hash matches the canonicalized document content.
	HashValid bool `json:"hash_valid"`
}

// AttestationEvidenceResult contains verification results for one evidence reference.
type AttestationEvidenceResult struct {
	// Kind is the evidence type (a2a, email, jwt, tlsnotary, custom).
	Kind string `json:"kind"`
	// DigestValid indicates the evidence digest matches.
	DigestValid bool `json:"digest_valid"`
	// FreshnessValid indicates the collectedAt timestamp is within bounds.
	FreshnessValid bool `json:"freshness_valid"`
	// Errors contains error messages for this evidence item.
	Errors []string `json:"errors,omitempty"`
}

// AttestationChainResult contains derivation chain verification results.
type AttestationChainResult struct {
	// Depth is the number of links in the derivation chain.
	Depth int `json:"depth"`
	// AllLinksValid indicates every derivation link verified.
	AllLinksValid bool `json:"all_links_valid"`
	// Links contains per-link verification details.
	Links []AttestationChainLink `json:"links,omitempty"`
}

// AttestationChainLink contains verification details for one derivation link.
type AttestationChainLink struct {
	// InputDigestsValid indicates input digests match.
	InputDigestsValid bool `json:"input_digests_valid"`
	// OutputDigestsValid indicates output digests match.
	OutputDigestsValid bool `json:"output_digests_valid"`
}

// TrustedAgent contains information about a trusted agent.
type TrustedAgent struct {
	// AgentID is the agent's unique identifier.
	AgentID string `json:"agent_id"`
	// Name is the agent's human-readable name.
	Name string `json:"name,omitempty"`
	// PublicKeyPEM is the agent's public key in PEM format.
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	// PublicKeyHash is the hash of the public key for quick lookups.
	PublicKeyHash string `json:"public_key_hash"`
	// TrustedAt is when this agent was trusted.
	TrustedAt string `json:"trusted_at"`
}

// =============================================================================
// Inline text + media signing types (Task 12 — PRD §3.1, §3.2, §4.1, §4.2)
// =============================================================================

// SignTextOpts controls the behaviour of [JacsSimpleAgent.SignText] /
// [JacsSimpleAgent.SignTextFile]. Pass nil for defaults.
type SignTextOpts struct {
	// NoBackup skips the automatic <path>.bak backup. Default false.
	NoBackup bool
}

// SignTextResult is returned by SignText / SignTextFile.
type SignTextResult struct {
	// Path is the file that was signed (always equal to the input path).
	Path string `json:"path"`
	// SignersAdded counts new signature blocks. 0 on a duplicate-signer no-op.
	SignersAdded int `json:"signers_added"`
	// BackupPath is the path of the .bak written prior to signing, when not
	// suppressed via SignTextOpts.NoBackup.
	BackupPath string `json:"backup_path,omitempty"`
}

// VerifyTextOpts controls the behaviour of [JacsSimpleAgent.VerifyText] /
// [JacsSimpleAgent.VerifyTextFile]. Pass nil for defaults.
type VerifyTextOpts struct {
	// Strict (PRD §C1): when true, missing-signature returns an error wrapping
	// ErrMissingSignature; permissive (default) returns a typed status.
	Strict bool
	// KeyDir (PRD §4.1.5) is an optional directory of <signer_id>.public.pem
	// files for offline verification.
	KeyDir string
}

// SignatureEntry is one entry in the VerifyTextResult / VerifyImageResult
// signatures slice.
type SignatureEntry struct {
	SignerID  string `json:"signer_id"`
	Algorithm string `json:"algorithm"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
}

// VerifyTextResult is returned by VerifyText / VerifyTextFile in permissive
// mode. In strict mode missing-signature returns an error instead.
type VerifyTextResult struct {
	// Status is one of "signed" | "missing_signature" | "malformed".
	Status     string           `json:"status"`
	Signatures []SignatureEntry `json:"signatures"`
}

// SignImageOpts controls the behaviour of [JacsSimpleAgent.SignImage].
// Pass nil for defaults.
type SignImageOpts struct {
	// Robust (PRD §4.2.4): enable LSB embedding for re-encode survivability.
	// PNG/JPEG only. Default false (Q4).
	Robust bool
	// Format is an optional explicit format override ("png" | "jpeg" | "webp").
	Format string
	// RefuseOverwrite (PRD §4.2.2): refuse if the input image already carries a
	// JACS signature.
	RefuseOverwrite bool
}

// SignImageResult is returned by SignImage.
type SignImageResult struct {
	OutPath    string `json:"out_path"`
	SignerID   string `json:"signer_id"`
	Format     string `json:"format"`
	Robust     bool   `json:"robust"`
	BackupPath string `json:"backup_path,omitempty"`
}

// VerifyImageOpts controls the behaviour of [JacsSimpleAgent.VerifyImage].
// Pass nil for defaults.
type VerifyImageOpts struct {
	Strict bool
	KeyDir string
	// Robust (PRD §4.2.4): when true, scan the LSB channel as a fallback when
	// the metadata payload is missing. Default false.
	Robust bool
}

// VerifyImageResult is returned by VerifyImage.
type VerifyImageResult struct {
	// Status is one of "valid" | "missing_signature" | "malformed" |
	// "invalid_signature" | "hash_mismatch" | "key_not_found" | "unsupported_algorithm".
	Status    string `json:"status"`
	SignerID  string `json:"signer_id,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Format    string `json:"format,omitempty"`
	// EmbeddingChannels is a free-form description of where in the image the
	// signature was found (e.g. "metadata"). Optional; serialized as a string
	// to match the Rust core's `Option<String>`.
	EmbeddingChannels string `json:"embedding_channels,omitempty"`
}

// ExtractMediaOpts controls the behaviour of [JacsSimpleAgent.ExtractMediaSignature].
// Pass nil for defaults.
type ExtractMediaOpts struct {
	// RawPayload (PRD §3.2): when true, return the raw base64url wire form
	// instead of the decoded JACS signed-document JSON. Default false.
	RawPayload bool
}
