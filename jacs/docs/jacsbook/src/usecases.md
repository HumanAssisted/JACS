# Use cases

JACS supports a wide range of workflows: proving where data came from, protecting who runs an agent, registering with a platform, enforcing provenance in your app, and proving that a specific agent sent a message. This page summarizes five common use cases; each links to the full fictional scenario and technical flow in the repository.

For detailed narratives (scenario, technical flow, outcome), see **[USECASES.md](https://github.com/HumanAssisted/JACS/blob/main/USECASES.md)** in the JACS repo.

---

## 1. Verifying that JSON came from a specific program

**Summary.** You have a pipeline or service that emits JSON (configs, reports, compliance data). Consumers need to trust that a given file or payload was produced by that program and not modified. With JACS, the program has one agent identity: it signs each artifact with `sign_message` or `sign_file` at emission; consumers verify with `verify()` or `verify_by_id()` (local storage), or use `verify_standalone()` for one-off verification without loading an agent. No central server is required.

See [USECASES.md § 1](https://github.com/HumanAssisted/JACS/blob/main/USECASES.md#1-verifying-that-json-files-came-from-a-specific-program) for the full scenario.

---

## 2. Protecting your agent's identity on the internet

**Summary.** You run a public-facing agent and want its messages to be verifiable (signed) without exposing who operates it. JACS supports this by keeping signing internal-only and publishing only the public key (via DNS and optionally HAI). Recipients use `verify()` (core JACS) or `jacs_verify_auto` (OpenClaw/moltyjacs) to confirm origin and integrity; they never learn who runs the agent.

See [USECASES.md § 2](https://github.com/HumanAssisted/JACS/blob/main/USECASES.md#2-protecting-your-agents-identity-on-the-internet) for the full scenario.

---

## 3. Registering and testing your agent on HAI.ai

**Summary.** You want to register your JACS agent with HAI.ai for attestation and discoverability, and to test verification before going live. Use the HAI registration flow: from Node `registerWithHai()` (@hai.ai/jacs), from Go `RegisterWithHai()` (jacsgo), from Python `register_with_hai` / `register_new_agent()` (jacspy), or `openclaw jacs register` (moltyjacs). Set `HAI_API_KEY`, then check attestation and run verification with `JACS_KEY_RESOLUTION=local,hai`.

See [USECASES.md § 3](https://github.com/HumanAssisted/JACS/blob/main/USECASES.md#3-registering-and-testing-your-agent-on-haiai) for the full scenario.

---

## 4. A Go, Node, or Python agent with strong data provenance

**Summary.** Your agent (in Go, Node, or Python) must prove the origin and integrity of every important output for compliance. Use the simple API in jacspy, jacsnpm, or jacsgo: `load(config)`, `sign_message(payload)` for each output, and `verify(signed.raw)` (or `verify_standalone()` for one-off verification without agent setup) wherever you consume signed data. Keys stay local; use `JACS_KEY_RESOLUTION` for external signers or air-gapped use.

See [USECASES.md § 4](https://github.com/HumanAssisted/JACS/blob/main/USECASES.md#4-a-go-node-or-python-agent-with-strong-data-provenance) for the full scenario.

---

## 5. OpenClaw (moltyjacs): proving your agent sent a message

**Summary.** You use OpenClaw with the moltyjacs plugin and need cryptographic proof that a specific message came from your agent. The agent signs outbound messages with `jacs_sign`; the recipient verifies with `jacs_verify_auto`. The signature travels with the message; no custom PKI is required.

See [USECASES.md § 5](https://github.com/HumanAssisted/JACS/blob/main/USECASES.md#5-openclaw-moltyjacs-proving-your-agent-actually-sent-a-message) for the full scenario.
