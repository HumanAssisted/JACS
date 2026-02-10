# Deployment Compatibility

JACS includes native bindings (Rust compiled to platform-specific libraries), so deployment depends on pre-built binary availability for your target platform.

## Supported Platforms

| Platform | Language | Notes |
|----------|----------|-------|
| Linux (x86_64, aarch64) | All | Primary target |
| macOS (Apple Silicon, Intel) | All | Full support |
| Windows (x86_64) | Rust, Node.js | Python wheels may need manual build |
| AWS Lambda | Python, Node.js | Use Lambda layers for native deps |
| Docker / Kubernetes | All | Standard containerization |
| Vercel (Node.js runtime) | Node.js | Via serverless functions |

## Not Yet Supported

| Platform | Why | Workaround |
|----------|-----|------------|
| Cloudflare Workers | No native module support (WASM-only) | Use a proxy service |
| Deno Deploy | No native Node.js addons | Use Deno with `--allow-ffi` locally |
| Bun | Native builds may fail | Use Node.js runtime instead |
| Browser / WASM | Post-quantum crypto not available in WASM | Planned for a future release |

## Version Requirements

| Language | Minimum Version |
|----------|----------------|
| Rust | 1.93+ (edition 2024) |
| Python | 3.10+ |
| Node.js | 18+ (LTS recommended) |

## Docker Example

```dockerfile
FROM python:3.12-slim
RUN pip install jacs
COPY . /app
WORKDIR /app
RUN python -c "import jacs.simple as j; j.quickstart()"
CMD ["python", "main.py"]
```

## Lambda Deployment

For AWS Lambda, include the JACS native library in a Lambda layer or bundle it in your deployment package. Set `JACS_PRIVATE_KEY_PASSWORD` as a Lambda environment variable (use AWS Secrets Manager for production).

## Building from Source

If no pre-built binary exists for your platform:

```bash
# Python
pip install maturin
cd jacspy && maturin develop --release

# Node.js
cd jacsnpm && npm run build
```

Requires Rust 1.93+ toolchain installed via [rustup](https://rustup.rs/).
