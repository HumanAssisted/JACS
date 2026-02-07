# Security

JACS goal is to introduce no safety vulnerabilities to systems where it is integrated.
Open to ideas on what cryptography to add next: https://cryptography.rs/, like https://doc.dalek.rs/bulletproofs/index.html.

### filesystem

However, filesystem acces can also be turned off completely for documents. This means your app passing strings in and out of JACS but can not save().

By default a directory is used that is configured.  JACS should not touch any files outside the key directory JACS_KEY_DIRECTORY and the JACS_DIRECTORY.

### path validation (v0.6.0)

All paths built from untrusted input (e.g. `publicKeyHash` from documents, filenames) are validated by `require_relative_path_safe()` in `validation.rs`. This rejects path segments that are empty, `.`, `..`, or contain null bytes. The function is used in `make_data_directory_path`, `make_key_directory_path`, and trust store key cache operations, providing a single validation surface for path traversal prevention.

### private keys

Private keys are stored in memory with https://docs.rs/secrecy/latest/secrecy/
They are encrypted at rest (AES-256-GCM with PBKDF2, 600k iterations) when `JACS_PRIVATE_KEY_PASSWORD` is set. The password must only be set via environment variable, never in config files.



## header validation process

The following is a brief explanation of documents are created, signed, and verified.


### signing

Signature options are "ring-Ed25519", "RSA-PSS", and "pq-dilithium".
These are all open source projects and JACS is not an encryption library in itself.


1. a json document is loaded as a "new" document
2. as a new document it must not have an id, version etc
3. an id and version uuid is created, along with date, etc
4. all the fields are hashed and put into a field that is not part of the hash, and the hash is added
5. all the fields are used to sign with the agent's private key, and the public keys sha256 is aded to the document, as well as the signing agent's id and version

### verifying

1. a document is loaded and is verified as being a jacs document using the schema
2. the hash is checked by taking the value of the fields excluding signature areas, and checking the hash
3. the agent id is used to find the public key of the document and the signature is checked


## trust

When data is changed documents are versioned and the version is cryptographically signed by your agent.
Changes can be verified and approved by other agents using your public key, allowing for creation and exchange of trusted data.


NOTE: Doesn’t *require* central key authority yet, but this does mean that anyone can spoof anyone.
Until then, use for self signing only, or exchange public keys only with trusted services.

JACS should not need to make network calls for JSON schema as they are loaded into the lib.