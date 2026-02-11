# Failure Modes

This page documents the error messages you will see when multi-agent agreements fail. Each scenario is validated by the chaos agreement tests in the JACS test suite.

## Partial Signing (Agent Crash)

**What happened:** An agreement was created for N agents but one or more agents never signed -- they crashed, timed out, or disconnected before calling `sign_agreement`.

**Error message:**

```
not all agents have signed: ["<unsigned-agent-id>"] { ... agreement object ... }
```

**What to do:** Identify the unsigned agent from the error, re-establish contact, and have them call `sign_agreement` on the document. The partially-signed document is still valid and can accept additional signatures -- signing is additive.

## Quorum Not Met

**What happened:** An agreement with an explicit quorum (M-of-N via `AgreementOptions`) received fewer than M signatures.

**Error message:**

```
Quorum not met: need 2 signatures, have 1 (unsigned: ["<agent-id>"])
```

**What to do:** Either collect more signatures to meet the quorum threshold, or create a new agreement with a lower quorum if appropriate. The unsigned agent IDs in the error tell you exactly who still needs to sign.

## Tampered Signature

**What happened:** A signature byte was modified after an agent signed the agreement. The cryptographic verification layer detects that the signature does not match the signed content.

**Error message:**

The exact message comes from the crypto verification layer and varies by algorithm, but it will always fail on the signature check rather than reporting missing signatures. You will not see "not all agents have signed" for this case -- the error is a cryptographic verification failure.

**What to do:** This indicates data corruption in transit or deliberate tampering. Discard the document and request a fresh copy from the signing agent. Do not attempt to re-sign a document with a corrupted signature.

## Tampered Document Body

**What happened:** The document content was modified after signatures were applied. JACS stores an integrity hash of the agreement-relevant fields at signing time, and any body modification causes a mismatch.

**Error message:**

```
Agreement verification failed: agreement hashes do not match
```

**What to do:** The document body no longer matches what the agents originally signed. Discard the modified document and go back to the last known-good version. If the modification was intentional (e.g., an amendment), create a new agreement on the updated document and collect fresh signatures from all parties.

## In-Memory Consistency After Signing

**What happened:** `sign_agreement` succeeded but `save()` was never called -- for example, a storage backend failure or process interruption before persistence.

**Error message:** None. This is not an error. After `sign_agreement` returns successfully, the signed document is immediately retrievable and verifiable from in-memory storage.

**What to do:** Retry the `save()` call to persist to disk. The in-memory state is consistent: you can retrieve the document with `get_document`, verify it with `check_agreement`, serialize it, and transfer it to other agents for additional signatures -- all without saving first.

## See Also

- [Creating and Using Agreements](../rust/agreements.md) - Agreement creation and signing workflow
- [Security Model](security.md) - Overall security architecture
- [Cryptographic Algorithms](crypto.md) - Algorithm details and signature verification
