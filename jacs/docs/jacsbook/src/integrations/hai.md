# HAI.ai Integration

This chapter is no longer part of the main JACS book path.

The maintained registry and HAI-specific workflows now live in the separate `haisdk` repository, not in the core JACS bindings. Earlier versions of this chapter mixed that external SDK surface with JACS runtime features and created the impression that the full HAI workflow was first-class inside this repo.

## What To Use Today

- Use this book for JACS signing, MCP, A2A, framework adapters, and trust bootstrap.
- Use `haisdk` for HAI registration or remote registry workflows.

## Why This Chapter Was Reduced

- The code and release cadence for HAI integration are separate from JACS core.
- The old chapter described flows that do not belong in the primary JACS adoption path.
- Cross-repo guidance is still useful, but it needs to be maintained where the implementation lives.

Future cross-repo interop docs are tracked in `docs/missing-features.md`.
