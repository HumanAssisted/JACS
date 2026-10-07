# A2A integration quickstart

A2A remains available through the JACS integration libraries and extended `jacs-compat` CLI.
The default portable `jacs mcp` server exposes document verification; it does
not advertise discovery or A2A artifact tools.

Install a current native integration:

```sh
python -m pip install 'jacs[a2a-server]==0.15.0'
# Or, for Node.js:
npm install --save-exact @hai.ai/jacs@0.15.0
# Or the extended Rust CLI:
cargo install jacs-cli-compat --version 0.15.0 --locked
jacs-compat a2a --help
```

Start with the retained guides, using the current package versions above and
`jacs-compat` wherever an extended CLI example says `jacs`:

1. [Create and serve an Agent Card](archive/native/jacs/docs/jacsbook/src/guides/a2a-serve.md).
2. [Discover and assess a remote agent](archive/native/jacs/docs/jacsbook/src/guides/a2a-discover.md).
3. [Exchange signed artifacts](archive/native/jacs/docs/jacsbook/src/guides/a2a-exchange.md).
4. Consult the [A2A API reference](archive/native/jacs/docs/jacsbook/src/integrations/a2a.md)
   and [example index](examples/README.md).

The native PQ signing identity and an explicitly provisioned ES256 Agent Card
compatibility key have different roles. Discovery verification must apply the
configured trust policy; a valid signature alone is not permission to act.
The `verified` policy establishes origin/key continuity; `strict` additionally
requires a trusted native JACS root and its signed compatibility binding.

See the [supported libraries](docs/libraries.md) and [MCP use cases](USECASES.md)
for the other integration paths. Examples that predate the workspace move
still need their own fixture/path checks; this entry point does not claim a
fresh run of every discovery demo.
