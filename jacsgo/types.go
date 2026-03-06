package jacs

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
