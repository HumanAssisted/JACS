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
