# Error Codes

This reference documents error codes and messages you may encounter when using JACS.

## CLI Exit Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | General Error | Unspecified error occurred |
| 2 | Invalid Arguments | Command line arguments invalid |
| 3 | File Not Found | Specified file does not exist |
| 4 | Verification Failed | Document or signature verification failed |
| 5 | Signature Invalid | Cryptographic signature is invalid |

## Configuration Errors

### Missing Configuration

**Error:** `Configuration file not found: jacs.config.json`

**Cause:** JACS cannot find the configuration file.

**Solution:**
```bash
# Initialize JACS to create configuration
jacs init

# Or specify a custom config path
JACS_CONFIG_PATH=./custom.config.json jacs agent verify
```

### Invalid Configuration

**Error:** `Invalid configuration: missing required field 'jacs_key_directory'`

**Cause:** Configuration file is missing required fields.

**Solution:** Ensure your `jacs.config.json` contains all required fields:
```json
{
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_default_storage": "fs"
}
```

### Key Directory Not Found

**Error:** `Key directory not found: ./jacs_keys`

**Cause:** The specified key directory does not exist.

**Solution:**
```bash
# Create the directory
mkdir -p ./jacs_keys

# Or run init to create everything
jacs init
```

## Cryptographic Errors

### Private Key Not Found

**Error:** `Private key file not found: private.pem`

**Cause:** The private key file is missing from the key directory.

**Solution:**
```bash
# Generate new keys
jacs agent create --create-keys true
```

### Invalid Key Format

**Error:** `Failed to parse private key: invalid PEM format`

**Cause:** The key file is corrupted or in wrong format.

**Solution:**
- Regenerate keys with `jacs agent create --create-keys true`
- Ensure the key file is not corrupted

### Key Password Required

**Error:** `Private key is encrypted but no password provided`

**Cause:** Encrypted private key requires password.

**Solution:**
```bash
export JACS_PRIVATE_KEY_PASSWORD="your-password"
jacs document create -f doc.json
```

### Algorithm Mismatch

**Error:** `Key algorithm 'ring-Ed25519' does not match configured algorithm 'RSA-PSS'`

**Cause:** The key file was created with a different algorithm than configured.

**Solution:**
- Update config to match key algorithm, or
- Regenerate keys with the correct algorithm

## Signature Errors

### Verification Failed

**Error:** `Document verification failed: signature does not match content`

**Cause:** Document content has been modified after signing.

**Solution:**
- The document may have been tampered with
- Re-sign the document if you have the original content

### Missing Signature

**Error:** `Document missing jacsSignature field`

**Cause:** Document was not signed or signature was removed.

**Solution:**
```bash
# Create a signed document
jacs document create -f unsigned-doc.json
```

### Invalid Signature Format

**Error:** `Invalid signature format: expected base64 encoded string`

**Cause:** The signature field is malformed.

**Solution:**
- Re-sign the document
- Verify the document hasn't been corrupted

### Unknown Signing Algorithm

**Error:** `Unknown signing algorithm: unknown-algo`

**Cause:** Document was signed with an unsupported algorithm.

**Solution:**
- Use a supported algorithm: `ring-Ed25519`, `RSA-PSS`, `pq-dilithium`, `pq2025`

## DNS Verification Errors

### DNSSEC Validation Failed

**Error:** `strict DNSSEC validation failed for <owner> (TXT not authenticated). Enable DNSSEC and publish DS at registrar`

**Cause:** DNSSEC mode was requested but the TXT response wasn't authenticated.

**Solution:**
1. Enable DNSSEC for your domain zone
2. Publish the DS record at your registrar
3. Wait for propagation (up to 48 hours)

### DNS Record Not Found

**Error:** `DNS TXT lookup failed for <owner> (record missing or not yet propagated)`

**Cause:** The JACS TXT record doesn't exist or hasn't propagated.

**Solution:**
1. Verify the TXT record was created:
   ```bash
   dig _v1.agent.jacs.yourdomain.com TXT
   ```
2. Wait for DNS propagation (can take up to 48 hours)
3. Confirm record name and value are correct

### DNS Required

**Error:** `DNS TXT lookup required (domain configured) or provide embedded fingerprint`

**Cause:** Strict DNS mode is active because a domain is configured.

**Solution:**
- Publish the TXT record, or
- Run with `--no-dns` during initial setup:
  ```bash
  jacs agent verify --no-dns
  ```

### DNS Lookup Timeout

**Error:** `DNS lookup timed out for <domain>`

**Cause:** DNS server did not respond in time.

**Solution:**
- Check network connectivity
- Try again later
- Verify DNS server is accessible

## Document Errors

### Invalid JSON

**Error:** `Failed to parse document: invalid JSON at line 5`

**Cause:** Document file contains invalid JSON.

**Solution:**
- Validate JSON with a linter
- Check for syntax errors (missing commas, quotes)

### Schema Validation Failed

**Error:** `Schema validation failed: missing required field 'amount'`

**Cause:** Document doesn't conform to the specified schema.

**Solution:**
```bash
# Check which fields are required by the schema
cat schema.json | jq '.required'

# Add missing fields to your document
```

### Document Not Found

**Error:** `Document not found: 550e8400-e29b-41d4-a716-446655440000`

**Cause:** The specified document ID doesn't exist in storage.

**Solution:**
- Verify the document ID is correct
- Check the storage directory

### Version Mismatch

**Error:** `Document version mismatch: expected v2, got v1`

**Cause:** Attempting to update with incorrect base version.

**Solution:**
- Get the latest version of the document
- Apply updates to the correct version

## Agreement Errors

### Agreement Not Found

**Error:** `Document has no jacsAgreement field`

**Cause:** Attempting agreement operations on a document without an agreement.

**Solution:**
```bash
# Create an agreement first
jacs document create-agreement -f doc.json -i agent1-id,agent2-id
```

### Already Signed

**Error:** `Agent has already signed this agreement`

**Cause:** Attempting to sign an agreement that was already signed by this agent.

**Solution:**
- No action needed, the signature is already present

### Not Authorized

**Error:** `Agent is not in the agreement's agentIDs list`

**Cause:** Attempting to sign with an agent not listed in the agreement.

**Solution:**
- Only agents listed in `jacsAgreement.agentIDs` can sign

### Agreement Locked

**Error:** `Cannot modify document: agreement is complete`

**Cause:** Attempting to modify a document with a completed agreement.

**Solution:**
- Create a new version/agreement if changes are needed

## Storage Errors

### Storage Backend Error

**Error:** `Storage error: failed to write to filesystem`

**Cause:** Unable to write to the configured storage backend.

**Solution:**
- Check filesystem permissions
- Verify storage directory exists
- Check disk space

### AWS S3 Error

**Error:** `S3 error: AccessDenied`

**Cause:** AWS credentials don't have required permissions.

**Solution:**
- Verify IAM permissions include s3:GetObject, s3:PutObject
- Check bucket policy
- Verify credentials are correct

### Connection Error

**Error:** `Failed to connect to storage: connection refused`

**Cause:** Cannot connect to remote storage backend.

**Solution:**
- Check network connectivity
- Verify endpoint URL is correct
- Check firewall rules

## HTTP/MCP Errors

### Request Verification Failed

**Error:** `JACS request verification failed`

**Cause:** Incoming HTTP request has invalid JACS signature.

**Solution:**
- Ensure client is signing requests correctly
- Verify client and server are using compatible keys

### Response Verification Failed

**Error:** `JACS response verification failed`

**Cause:** Server response has invalid signature.

**Solution:**
- Check server JACS configuration
- Verify server is signing responses

### Middleware Configuration Error

**Error:** `JACSExpressMiddleware: config file not found`

**Cause:** Middleware cannot find JACS configuration.

**Solution:**
```javascript
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.config.json'  // Verify path is correct
}));
```

## Debugging Tips

### Enable Verbose Output

```bash
# CLI verbose mode
jacs document verify -f doc.json -v

# Environment variable
export JACS_DEBUG=true
```

### Check Configuration

```bash
# Display current configuration
jacs config read
```

### Verify Agent

```bash
# Verify agent is properly configured
jacs agent verify -v
```

### Test Signing

```bash
# Create a test document
echo '{"test": true}' > test.json
jacs document create -f test.json -v
```

## See Also

- [Configuration Reference](configuration.md) - Configuration options
- [CLI Command Reference](cli-commands.md) - CLI usage
- [Security Model](../advanced/security.md) - Security details
