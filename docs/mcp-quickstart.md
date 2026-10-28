# Connect an MCP client

Install the portable CLI:

```sh
cargo install jacs-cli --locked
jacs mcp
```

For clients that accept an `mcpServers` configuration, the verification-only
connection is:

```json
{
  "mcpServers": {
    "jacs": { "command": "jacs", "args": ["mcp"] }
  }
}
```

The host starts a local stdio process. There is no HTTP listener; diagnostics
go to stderr. The only default tool is `jacs_verify_document`. Select the
signer's public evidence independently, parse the returned JSON text, and
check its `valid` field. See the
[verification use case](https://github.com/HumanAssisted/JACS/blob/main/USECASES.md#verify-an-artifact-before-using-it).

## Verify a sample document

To create a local test fixture, run in a private directory (skip this when you
already have a signed document and independently selected public identity):

```sh
mkdir -m 700 .jacs
jacs create --output .jacs/agent.json > public-identity.json
printf '%s' '{"message":"hello"}' | jacs sign --agent .jacs/agent.json --input - > signed.json
jacs verify --public-identity public-identity.json --input signed.json
```

The CLI prompts for the key password. Its successful verification reports
`valid: true`. To prepare the equivalent MCP request with Python 3:

```python
import json
from pathlib import Path

trusted = json.loads(Path("public-identity.json").read_text())
request = {
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "jacs_verify_document", "arguments": {
        "document": Path("signed.json").read_text(),
        "public_key": trusted["public_key"],
        "algorithm": trusted["algorithm"],
    }},
}
print(json.dumps(request))
```

Send this through your MCP client after its normal connection/initialization.
`document` is an exact JSON **string**; `public_key` is canonical standard Base64
of the raw public-key bytes, not PEM. Parse the response's text content as JSON
and require `valid: true`. For identity attribution, also compare `signer_id`
to the independently selected public identity's `agent_id`. Malformed requests can return protocol/tool
errors. Do not accept a key merely because it arrived beside an untrusted document.

## Enable local signing explicitly

Start the signer with the encrypted fixture vault created above:

```sh
jacs mcp --profile local-sign --agent .jacs/agent.json
```

The terminal prompts for the password. A noninteractive MCP host must supply
`JACS_PRIVATE_KEY_PASSWORD` through its secret-handling mechanism; do not put
passwords in tool arguments, command arguments or committed client config.
Configure the client to launch this profile with an absolute vault path:

```json
{
  "mcpServers": {
    "jacs": {
      "command": "jacs",
      "args": ["mcp", "--profile", "local-sign", "--agent", "/absolute/path/.jacs/agent.json"]
    }
  }
}
```

Local signing enables seven portable tools for the selected vault. Creation
and encrypted import require an empty vault and refuse to overwrite an identity.
Rotation retains the current password unless the host supplies
`JACS_NEW_PRIVATE_KEY_PASSWORD`; re-encryption requires that new password at
startup. The host owns approval of
that process-level grant. Unix vault permissions are enforced; platforms
without the required filesystem custody adapter can still verify public data.

For agreements and text/images, choose the separate
[extended MCP profiles](https://github.com/HumanAssisted/JACS/blob/main/docs/native-mcp.md).
For service integration, use the
[direct libraries](https://github.com/HumanAssisted/JACS/blob/main/docs/libraries.md).

Call `jacs_sign_document` with `{"document":"{\"message\":\"hello\"}"}`.
Its parsed text response contains a `document` object and `algorithm`; serialize
that object to a JSON string for subsequent verification. Check the active
`tools/list` inventory before calling lifecycle tools.

Portable and extended MCP schemas differ: the extended signer accepts `content`
and returns `signed_document`; its verifier takes raw key bytes as a JSON array.
Use the selected server's contract rather than reusing arguments across them.
For other protocols, follow the [A2A how-to](https://humanassisted.github.io/JACS/a2a.html)
or [W3C DID how-to](https://humanassisted.github.io/JACS/w3c-did.html).
