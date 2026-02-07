# JACS use cases

This document describes fictional but detailed scenarios for using JACS. Each section includes the situation, technical flow, and outcome. Use these as templates for your own workflows.

---

## 1. Verifying that JSON files came from a specific program

**Scenario.** Meridian Build Co. runs an internal pipeline that emits JSON artifacts: deployment configs, test reports, and compliance summaries. These files are consumed by other teams and by external auditors. The problem: anyone could drop a JSON file into a shared drive and claim it came from "the build service." Meridian needs a way for consumers to cryptographically verify that a given JSON file was produced by their official build program and has not been altered.

**Why JACS.** JACS gives the build program a single agent identity. Every artifact is signed at emission with `sign_message` or `sign_file`. Downstream systems and auditors verify with `verify()` (or `verify_by_id` when they have a storage ID). No central server is required; keys stay with the build environment.

**Technical flow.**

1. **One agent per program.** The build service runs with its own JACS config: `jacs.config.json` (or equivalent) and a dedicated key pair. Create the agent once (e.g. `jacs init` or `create()` in your language); thereafter the pipeline loads it with `load(config)`.
2. **Sign at emission.** When the pipeline produces a JSON artifact (e.g. `report.json` or an in-memory payload), it signs before writing or sending:
   - **Payload as JSON:** `sign_message(payload)` → signed document (e.g. `signed.raw`).
   - **File on disk:** `sign_file(path)` or `sign_file(path, embed: true)` → signed document that either references the file by hash or embeds its content.
3. **Verify at consumption.** Consumers receive the signed document (file or string). They call `verify(signed.raw)` (or `verify_by_id(id)` if they have the stored document ID). JACS resolves the signer’s public key (e.g. via `JACS_KEY_RESOLUTION=local,hai`), checks the signature and integrity, and returns validity and signer identity.
4. **Trust.** Consumers trust the build service’s public key (stored locally or discovered via HAI). A valid verification means the JSON came from that program and was not modified.

**Outcome.** Meridian’s consumers and auditors can prove that each JSON file they use was produced by the designated build program and is unaltered. Tampering or forgery is detected by failed verification.

---

## 2. Protecting your agent's identity on the internet

**Scenario.** A research lab runs a public-facing AI agent that answers questions and participates in open forums. They want the agent’s messages to be **verifiable** (recipients can cryptographically confirm that the message came from that agent and wasn’t changed) but they do **not** want to expose who operates the agent or where it runs. In other words: the agent has a stable, verifiable identity; the operator’s identity stays off the internet.

**Why JACS.** JACS provides a pseudonymous agent identity: a key pair and agent ID that are not tied to the operator’s name or infrastructure. The agent signs messages internally; only the **public** key is published (via DNS and optionally HAI). There is **no public sign endpoint**—signing happens only inside the agent’s environment. Recipients verify with the published public key (e.g. via `jacs_verify_auto`), so they get proof of origin and integrity without learning who runs the agent.

**Technical flow.**

1. **Create an agent identity.** Run `jacs init` (or equivalent) to generate a key pair and agent ID. Do not embed operator or organization details in the agent document; use a neutral name/description if needed.
2. **Sign only internally.** All signing is done inside your infrastructure. The agent calls `sign_message(...)` (or the moltyjacs `jacs_sign` tool) before sending any message. Never expose an API that allows external parties to request signatures.
3. **Publish only the public key.** Publish the agent’s public key so others can verify:
   - **DNS:** Publish a TXT record so that key discovery works for your domain (e.g. `agent.example.com`). Recipients can then resolve and verify without contacting your backend.
   - **Well-known endpoint:** Expose `GET /.well-known/jacs-pubkey.json` (and optionally `/jacs/status`, `/jacs/verify`, `/jacs/attestation`) so that anyone can fetch the public key and attestation status. Do **not** expose a sign endpoint.
   - **Optional HAI.ai:** Register the agent with HAI so others can discover the key via HAI’s key service; this still does not reveal who operates the agent.
4. **Recipients verify.** Recipients receive the signed message (over any channel: HTTP, MCP, etc.) and call `jacs_verify_auto(signed_document)`. JACS fetches the public key (from DNS, HAI, or a provided URL), verifies the signature and integrity, and returns the signer’s identity (agent ID / key hash). The recipient gets assurance that the message came from that agent and was not modified; they do not learn who runs it.

**Outcome.** The lab’s agent can participate in public conversations with verifiable, signed messages. Third parties can trust that messages are from that agent and unaltered, while the operator’s identity remains protected because signing is internal-only and only the public key is published.

---

## 3. Registering and testing your agent on HAI.ai

**Scenario.** The team at Grove Software is building an AI agent they plan to use with partners and eventually list on HAI.ai. They want to register the agent with HAI for attestation and discoverability, and to test that registration and verification work before going live.

**Why JACS.** JACS agents can be registered with HAI.ai. Registration publishes the agent’s public key and optional metadata to HAI’s key service, so other HAI users (and systems using `JACS_KEY_RESOLUTION=...,hai`) can discover and verify the agent. Attestation status (e.g. verified, verified_at) and verification claim (e.g. `verified-hai.ai`) give partners a clear trust level.

**Technical flow.**

1. **Create a JACS agent.** Locally create and configure the agent (e.g. `jacs init` or Python/Node/Go `create`/`load`). Ensure you have the agent’s public key and identity (e.g. agent ID, public key hash).
2. **Get an HAI API key.** Obtain an API key from HAI.ai (e.g. https://hai.ai or https://hai.ai/developers). Set `HAI_API_KEY` in the environment or pass it to the registration call.
3. **Register the agent.** Use the HAI registration flow:
   - **Python:** Use the `register_with_hai` example or `register_new_agent()` from `jacs.hai` (see `jacspy/examples/register_with_hai.py` and `jacspy/examples/hai_quickstart.py`). Quick path: `hai_quickstart.py` can create and register in one step.
   - **CLI / other languages:** If available, use the equivalent (e.g. `openclaw jacs register` when using moltyjacs). Pass the API key via `--api-key` or `HAI_API_KEY`.
   Registration sends the agent ID, public key, public key hash, and optional name to HAI’s API (`POST /v1/agents` or equivalent). HAI stores the key for discovery and may return attestation status.
4. **Check attestation.** After registration, verify that HAI shows the agent as attested (e.g. `openclaw jacs attestation` or the HAI client’s attestation/status call). Optionally set the verification claim to `verified-hai.ai` so that verifiers recognize the agent as HAI-registered.
5. **Test verification.** From another environment or as a partner, resolve the agent’s key with `JACS_KEY_RESOLUTION=local,hai` and verify a signed document from that agent. Confirm that `verify()` or `jacs_verify_auto()` succeeds and reports the expected signer.

**Outcome.** Grove’s agent is registered with HAI and discoverable. Partners can verify signed documents from the agent using HAI’s key service, and the team has validated attestation and verification before production.

---

## 4. A Go, Node, or Python agent with strong data provenance

**Scenario.** A compliance-sensitive application (e.g. in finance or healthcare) is implemented as an agent in Go, JavaScript/Node, or Python. Every output—recommendations, reports, or audit events—must be provable: the organization must be able to show exactly which agent produced the data and that it has not been altered. They need a simple, robust integration with JACS that works the same way across languages.

**Why JACS.** JACS’s simple API (`load`, `sign_message`, `verify`) is available in jacspy, jacsnpm, and jacsgo. Keys stay local; no central server is required. Optional HAI or DNS resolution allows external parties to verify without pre-sharing keys. The same patterns apply in all three languages.

**Technical flow.**

1. **Load the agent.** At startup, load the agent from config (e.g. `jacs.config.json`):
   - **Python:** `simple.load('./jacs.config.json')` (or `load()` with default path).
   - **Node:** `jacs.load('./jacs.config.json')`.
   - **Go:** `jacs.Load(nil)` or load from a config path.
   Ensure `JACS_PRIVATE_KEY_PASSWORD` is set in the environment for signing; never put the password in the config file.
2. **Sign every critical output.** Before returning or persisting any result that must be attributable and tamper-evident, sign it: `sign_message(payload)` (or the language equivalent). Attach or store the signed document (e.g. `signed.raw`) with the workflow or response.
3. **Verify when consuming.** Any consumer (internal or external) that receives a signed document calls `verify(signed.raw)`. For external signers, use key resolution (e.g. `JACS_KEY_RESOLUTION=local,hai` or `local,dns,hai`) so JACS can fetch the signer’s public key. The result includes `valid` and signer identity (e.g. `signer_id`).
4. **Air-gapped or locked-down.** For fully offline or high-security environments, set `JACS_KEY_RESOLUTION=local` and distribute public keys out-of-band. No network is required for verification once keys are in the local trust store.

**Outcome.** The organization has a single, language-agnostic pattern for data provenance: every important output is signed by a known agent and can be verified for origin and integrity. Compliance and audits can rely on cryptographic proof instead of trust-only logs.

---

## 5. OpenClaw (moltyjacs): proving your agent actually sent a message

**Scenario.** You run an OpenClaw agent with the moltyjacs plugin. You (or another agent) need to be sure that a specific message really came from your OpenClaw agent—for example, to enforce commitments, settle disputes, or satisfy an auditor. Without proof, anyone could claim "the agent said X."

**Why JACS and moltyjacs.** The moltyjacs plugin gives your OpenClaw agent a JACS identity and tools to sign and verify. When the agent sends a message, it signs it with `jacs_sign` before sending. The signed payload travels with the message; the recipient (human or agent) verifies with `jacs_verify_auto` (or with the agent’s public key). That provides cryptographic proof of origin and integrity.

**Technical flow.**

1. **Install and initialize.** Install the moltyjacs plugin (e.g. `openclaw plugins install moltyjacs` or from npm/ClawHub). Run `openclaw jacs init` to create the agent’s key pair and config. Optionally register with HAI (`openclaw jacs register`) so others can discover your key.
2. **Sign outbound messages.** When the agent sends a message that should be attributable, it uses the `jacs_sign` tool (or equivalent) to sign the message payload. The signed document (e.g. JACS JSON with signature and payload) is what gets sent—over HTTP, MCP, or any channel.
3. **Recipient verifies.** The recipient receives the signed document. They call `jacs_verify_auto(signed_document)`. Moltyjacs (or the JACS library) fetches the signer’s public key if needed (from DNS, HAI, or local store), verifies the signature and hash, and returns whether the document is valid and who signed it (agent ID / key hash).
4. **Proof of sending.** A valid verification means the message was signed by the private key corresponding to the published public key for that agent. So long as the private key is only used by your OpenClaw agent, you have proof that the agent sent that message and that it was not altered in transit.

**Outcome.** You and your partners can prove that a given message was sent by your OpenClaw agent. The signature travels with the message; no separate PKI or custom infra is required. For more on moltyjacs and OpenClaw, see the [moltyjacs repository](https://github.com/HumanAssisted/moltyjacs) and the [OpenClaw integration](https://humanassisted.github.io/JACS/integrations/openclaw.html) in the JACS docs.
