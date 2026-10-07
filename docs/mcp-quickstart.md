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

## Enable local signing explicitly

Create an encrypted agent in a private directory from a terminal:

```sh
mkdir -m 700 .jacs
jacs create --output .jacs/agent.json > public-identity.json
jacs mcp --profile local-sign --agent .jacs/agent.json
```

The terminal prompts for the password. A noninteractive MCP host must supply
`JACS_PRIVATE_KEY_PASSWORD` through its secret-handling mechanism; do not put
passwords in tool arguments, command arguments or committed client config.
Use an absolute vault path in the client's process configuration.

Local signing enables all seven portable tools for the selected vault.
Rotation and re-encryption additionally need the destination password at
startup through `JACS_NEW_PRIVATE_KEY_PASSWORD`. The host owns approval of
that process-level grant. Unix vault permissions are enforced; platforms
without the required filesystem custody adapter can still verify public data.

For agreements and text/images, choose the separate
[extended MCP profiles](https://github.com/HumanAssisted/JACS/blob/main/docs/native-mcp.md).
For service integration, use the
[direct libraries](https://github.com/HumanAssisted/JACS/blob/main/docs/libraries.md).
