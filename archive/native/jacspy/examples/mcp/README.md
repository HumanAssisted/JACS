# Authenticated MCP example

The checked-in historical config and key material is not a runnable identity
and must not be used as a trust anchor. Generate fresh server and client JACS
identities, provide their key passwords through `JACS_PASSWORD_FILE` or your OS
keychain, and set the following values explicitly.

Server:

```bash
export JACS_CONFIG_PATH=/absolute/path/to/server/jacs.config.json
export JACS_MCP_ALLOWED_CLIENT_AGENT_ID=<client-agent-id>
python server.py
```

Client:

```bash
export JACS_CONFIG_PATH=/absolute/path/to/client/jacs.config.json
export JACS_MCP_EXPECTED_SERVER_AGENT_ID=<server-agent-id>
# Optional: pin one exact server key as well as its identity.
export JACS_MCP_EXPECTED_SERVER_KEY_HASH=<server-public-key-hash>
python client.py
```

The server allowlist and client pin are deployment trust policy. Signature
verification alone proves key possession, not that the signer is the intended
peer.
