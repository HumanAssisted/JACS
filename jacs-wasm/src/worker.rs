//! Web Worker bridge for `@jacs/wasm` (Task 019).
//!
//! pq2025 keygen + signing is CPU-intensive (PRD §3.1). Running it on
//! the main thread blocks the UI; we ship a separate JS entry point
//! (`@jacs/wasm/worker`) that posts messages to a worker-side bootstrap
//! and resolves promises. The Rust side here exposes
//! [`worker_handle_message`] — the dispatcher the worker bootstrap
//! invokes for every inbound `postMessage`.
//!
//! ## Protocol
//!
//! ```text
//! IN:  { id: number, op: "createEphemeral", args: { algorithm: "ed25519" | "pq2025" } }
//!     | { id: number, op: "signMessage",    args: { handleId: number, dataJson: string } }
//!     | { id: number, op: "verify",         args: { handleId: number, signedJson: string } }
//!     | { id: number, op: "importEncryptedAgent",
//!                                          args: { materialJson: string, password: string } }
//!     | { id: number, op: "clearSecrets",   args: { handleId: number } }
//! OUT: { id: number, ok: true,  result: ... }
//!     | { id: number, ok: false, error: JacsWasmError /* { code, message } */ }
//! ```
//!
//! Handles produced inside the worker live in a worker-local
//! `HashMap<u32, CoreAgentHandle>` ([`HANDLE_REGISTRY`]); the main
//! thread refers to them by `handleId`. The main thread never sees the
//! Rust `CoreAgentHandle` directly because wasm-bindgen handles cannot
//! cross worker boundaries.

use std::cell::RefCell;
use std::collections::HashMap;

use jacs_core::CoreError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

use crate::agent_handle::{
    CoreAgentHandle, create_ephemeral, create_human, generate_recovery_code,
    generate_transfer_code, import_encrypted_agent, import_encrypted_agent_pinned, import_recovery,
    reencrypt_transferred_agent,
};

// ---------------------------------------------------------------------------
// Worker-local handle registry. `RefCell` (not `Mutex`) because every
// worker thread is single-threaded; `wasm32` is single-threaded by
// default and `RefCell` keeps the implementation lighter.
// ---------------------------------------------------------------------------

thread_local! {
    static HANDLE_REGISTRY: RefCell<HashMap<u32, crate::agent_handle::CoreAgentHandle>> =
        RefCell::new(HashMap::new());
    static NEXT_HANDLE_ID: RefCell<u32> = const { RefCell::new(1) };
}

fn allocate_handle_id() -> u32 {
    NEXT_HANDLE_ID.with(|n| {
        let mut g = n.borrow_mut();
        let id = *g;
        // Wrap on overflow but skip 0 so `0` always means "none".
        *g = g.checked_add(1).unwrap_or(1);
        id
    })
}

fn store_handle(handle: crate::agent_handle::CoreAgentHandle) -> u32 {
    let id = allocate_handle_id();
    HANDLE_REGISTRY.with(|r| r.borrow_mut().insert(id, handle));
    id
}

fn with_handle<R>(
    id: u32,
    f: impl FnOnce(&crate::agent_handle::CoreAgentHandle) -> Result<R, WorkerError>,
) -> Result<R, WorkerError> {
    HANDLE_REGISTRY.with(|r| {
        let g = r.borrow();
        let handle = g.get(&id).ok_or_else(|| {
            WorkerError::new(
                "InvalidHandle",
                format!("worker handle id {} not found", id),
            )
        })?;
        f(handle)
    })
}

fn drop_handle(id: u32) {
    HANDLE_REGISTRY.with(|r| {
        let _ = r.borrow_mut().remove(&id);
    });
}

// ---------------------------------------------------------------------------
// Wire messages.
// ---------------------------------------------------------------------------

/// Inbound request shape. The main thread posts this as plain JSON;
/// `worker_handle_message` deserializes it via `serde_wasm_bindgen`.
#[derive(Debug, Deserialize)]
pub(crate) struct WorkerRequest {
    id: u64,
    op: String,
    args: Value,
}

/// Outbound reply shape.
#[derive(Debug, Serialize)]
pub(crate) struct WorkerReply {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

fn reply_to_js_value(reply: &WorkerReply) -> Result<JsValue, JsError> {
    reply
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&format!("serialize reply: {}", e)))
}

/// Error payload returned in `reply.error`. Same `{ code, message }`
/// wire contract as `CoreError` so JS callers can use a single
/// dispatcher across the synchronous and worker APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerError {
    code: String,
    message: String,
}

impl WorkerError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        WorkerError {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Lift a `CoreError` into a `WorkerError`, preserving the `{ code,
    /// message }` wire form so callers see the same dispatch surface
    /// across main-thread and worker calls.
    fn from_core(err: CoreError) -> Self {
        WorkerError {
            code: err.code().to_string(),
            message: err.to_string(),
        }
    }

    /// Preserve the core error discriminator across the worker boundary.
    fn from_js(err: JsError) -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            let value: JsValue = err.into();
            if let Ok(message) = js_sys::Reflect::get(&value, &JsValue::from_str("message"))
                && let Some(message) = message.as_string()
                && let Ok(error) = serde_json::from_str(&message)
            {
                return error;
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = err;
        Self::new("WorkerOperationFailed", "WASM operation failed")
    }

    fn malformed_input(message: impl Into<String>) -> Self {
        Self::new("MalformedDocument", message)
    }

    fn unsupported_op(op: &str) -> Self {
        Self::new(
            "UnsupportedOp",
            format!("worker op '{}' is not supported", op),
        )
    }
}

// ---------------------------------------------------------------------------
// Dispatcher — pure Rust, no JS imports. Tests call `dispatch_request`
// directly to validate the protocol without needing a Worker context.
// ---------------------------------------------------------------------------

/// Pure-Rust dispatcher. Takes the deserialized request, performs the
/// op, returns the reply payload. Callable from native tests so the
/// protocol logic is exercised independently of the wasm-bindgen layer.
pub(crate) fn dispatch_request(req: WorkerRequest) -> WorkerReply {
    let reply_id = req.id;
    let result = match req.op.as_str() {
        "createEphemeral" => op_create_ephemeral(req.args),
        "createHuman" => store_created_handle(create_human().map_err(WorkerError::from_js)),
        "importRecovery" => op_import_recovery(req.args),
        "generateRecoveryCode" => generate_recovery_code()
            .map(|code| json!({ "code": code }))
            .map_err(WorkerError::from_js),
        "signMessage" => op_sign_message(req.args),
        "verify" => op_verify(req.args),
        "importEncryptedAgent" => op_import_encrypted_agent(req.args),
        "importEncryptedAgentPinned" => op_import_encrypted_agent_pinned(req.args),
        "reencryptTransferredAgent" => op_reencrypt_transferred_agent(req.args),
        "generateTransferCode" => generate_transfer_code()
            .map(|code| json!({ "code": code }))
            .map_err(WorkerError::from_js),
        "signString"
        | "buildRequestAuthHeader"
        | "updateAgent"
        | "prepareAgentUpdate"
        | "commitAgentUpdate"
        | "exportAgent"
        | "exportEncryptedAgent"
        | "exportRecovery"
        | "getPublicKeyPem"
        | "getPublicKeyPemBase64"
        | "getPublicKeyHash" => op_agent_method(&req.op, req.args),
        "clearSecrets" => op_clear_secrets(req.args),
        "dropHandle" => op_drop_handle(req.args),
        other => Err(WorkerError::unsupported_op(other)),
    };

    match result {
        Ok(value) => WorkerReply {
            id: reply_id,
            ok: true,
            result: Some(value),
            error: None,
        },
        Err(err) => WorkerReply {
            id: reply_id,
            ok: false,
            result: None,
            error: Some(serde_json::to_value(err).unwrap_or(Value::Null)),
        },
    }
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, WorkerError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| WorkerError::malformed_input(format!("missing '{}' field", key)))
}

fn require_u32(args: &Value, key: &str) -> Result<u32, WorkerError> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| {
            WorkerError::malformed_input(format!("missing or out-of-range '{}' field", key))
        })
}

fn store_created_handle(
    handle: Result<CoreAgentHandle, WorkerError>,
) -> Result<Value, WorkerError> {
    let handle = handle?;
    let key = handle
        .get_public_key_base64()
        .map_err(WorkerError::from_js)?;
    let algorithm = handle.algorithm().map_err(WorkerError::from_js)?;
    Ok(json!({ "handleId": store_handle(handle), "publicKeyBase64": key, "algorithm": algorithm }))
}

fn op_import_recovery(args: Value) -> Result<Value, WorkerError> {
    store_created_handle(
        import_recovery(
            require_str(&args, "materialJson")?,
            require_str(&args, "code")?.to_string(),
            require_str(&args, "expectedAgentId")?,
            require_str(&args, "expectedPublicKeyBase64")?,
            require_str(&args, "expectedAlgorithm")?,
        )
        .map_err(WorkerError::from_js),
    )
}

fn op_create_ephemeral(args: Value) -> Result<Value, WorkerError> {
    let algorithm = require_str(&args, "algorithm")?;
    // `create_ephemeral` returns a `Result<CoreAgentHandle, JsError>`;
    // we can't decode JsError's body, so we re-run the algorithm parse
    // here to produce a structured `CoreError` for the failure path.
    let _algo = jacs_core::SigningAlgorithm::from_wire_str(algorithm).ok_or_else(|| {
        WorkerError::from_core(CoreError::UnsupportedAlgorithm(format!(
            "unknown signing algorithm '{}' (expected one of: ed25519, pq2025, es256)",
            algorithm
        )))
    })?;
    let handle = create_ephemeral(algorithm).map_err(|_| {
        WorkerError::new(
            "AgreementFailed",
            "ephemeral keygen failed in worker context",
        )
    })?;
    // Pull metadata out of the handle before we move it into the
    // registry — the worker reply includes the algorithm + public key
    // so the main thread doesn't need a follow-up roundtrip.
    let public_key_base64 = handle.get_public_key_base64().map_err(|_| {
        WorkerError::new("AgreementFailed", "failed to extract public key in worker")
    })?;
    let algorithm_out = handle.algorithm().map_err(|_| {
        WorkerError::new("AgreementFailed", "failed to extract algorithm in worker")
    })?;
    let handle_id = store_handle(handle);
    Ok(json!({
        "handleId": handle_id,
        "publicKeyBase64": public_key_base64,
        "algorithm": algorithm_out,
    }))
}

fn op_sign_message(args: Value) -> Result<Value, WorkerError> {
    let handle_id = require_u32(&args, "handleId")?;
    let data_json = require_str(&args, "dataJson")?.to_string();
    with_handle(handle_id, |handle| {
        let signed = handle.sign_message_json(&data_json).map_err(|_| {
            WorkerError::new("Locked", "signMessage failed (likely handle is locked)")
        })?;
        Ok(json!({ "signedJson": signed }))
    })
}

fn op_verify(args: Value) -> Result<Value, WorkerError> {
    let handle_id = require_u32(&args, "handleId")?;
    let signed_json = require_str(&args, "signedJson")?.to_string();
    with_handle(handle_id, |handle| {
        let outcome = handle.verify_json(&signed_json).map_err(|_| {
            WorkerError::new(
                "MalformedDocument",
                "verify failed (invalid signed document or missing fields)",
            )
        })?;
        Ok(json!({ "outcomeJson": outcome }))
    })
}

fn op_import_encrypted_agent(args: Value) -> Result<Value, WorkerError> {
    let material_json = require_str(&args, "materialJson")?.to_string();
    let password = require_str(&args, "password")?.to_string();
    let handle = import_encrypted_agent(&material_json, &password).map_err(|_| {
        WorkerError::new(
            "InvalidPassword",
            "importEncryptedAgent failed (wrong password or malformed material)",
        )
    })?;
    let public_key_base64 = handle.get_public_key_base64().map_err(|_| {
        WorkerError::new("AgreementFailed", "failed to extract public key in worker")
    })?;
    let algorithm = handle.algorithm().map_err(|_| {
        WorkerError::new("AgreementFailed", "failed to extract algorithm in worker")
    })?;
    let handle_id = store_handle(handle);
    Ok(json!({
        "handleId": handle_id,
        "publicKeyBase64": public_key_base64,
        "algorithm": algorithm,
    }))
}

fn op_import_encrypted_agent_pinned(args: Value) -> Result<Value, WorkerError> {
    let handle = import_encrypted_agent_pinned(
        require_str(&args, "materialJson")?,
        require_str(&args, "password")?.to_string(),
        require_str(&args, "expectedAgentId")?,
        require_str(&args, "expectedPublicKeyBase64")?,
        require_str(&args, "expectedAlgorithm")?,
    )
    .map_err(WorkerError::from_js)?;
    let public_key_base64 = handle
        .get_public_key_base64()
        .map_err(WorkerError::from_js)?;
    let algorithm = handle.algorithm().map_err(WorkerError::from_js)?;
    let handle_id = store_handle(handle);
    Ok(
        json!({ "handleId": handle_id, "publicKeyBase64": public_key_base64, "algorithm": algorithm }),
    )
}

fn op_reencrypt_transferred_agent(args: Value) -> Result<Value, WorkerError> {
    let material = reencrypt_transferred_agent(
        require_str(&args, "materialJson")?,
        require_str(&args, "code")?.to_string(),
        require_str(&args, "expectedAgentId")?,
        require_str(&args, "expectedPublicKeyBase64")?,
        require_str(&args, "expectedAlgorithm")?,
        require_str(&args, "storagePassword")?.to_string(),
    )
    .map_err(WorkerError::from_js)?;
    Ok(json!({ "materialJson": material }))
}

fn op_agent_method(op: &str, args: Value) -> Result<Value, WorkerError> {
    let handle_id = require_u32(&args, "handleId")?;
    with_handle(handle_id, |handle| {
        let value = match op {
            "signString" => handle.sign_string(require_str(&args, "message")?),
            "buildRequestAuthHeader" => {
                let body: Vec<u8> = serde_json::from_value(
                    args.get("body")
                        .cloned()
                        .ok_or_else(|| WorkerError::malformed_input("missing 'body' bytes"))?,
                )
                .map_err(|_| WorkerError::malformed_input("'body' must be an array of bytes"))?;
                handle.build_request_auth_header(
                    require_str(&args, "method")?,
                    require_str(&args, "url")?,
                    &body,
                    require_str(&args, "audience")?,
                )
            }
            "updateAgent" => handle.update_agent_json(require_str(&args, "agentJson")?),
            "prepareAgentUpdate" => {
                handle.prepare_agent_update_json(require_str(&args, "updatesJson")?)
            }
            "commitAgentUpdate" => {
                handle.commit_agent_update_json(require_str(&args, "preparedJson")?)
            }
            "exportAgent" => handle.export_agent(),
            "exportRecovery" => handle.export_recovery(),
            "exportEncryptedAgent" => {
                handle.export_encrypted_agent(require_str(&args, "password")?.to_string())
            }
            "getPublicKeyHash" => handle.get_public_key_hash(),
            "getPublicKeyPem" => handle.get_public_key_pem(),
            "getPublicKeyPemBase64" => handle.get_public_key_pem_base64(),
            other => return Err(WorkerError::unsupported_op(other)),
        }
        .map_err(WorkerError::from_js)?;
        Ok(json!({ "value": value }))
    })
}

fn op_clear_secrets(args: Value) -> Result<Value, WorkerError> {
    let handle_id = require_u32(&args, "handleId")?;
    with_handle(handle_id, |handle| {
        handle
            .clear_secrets()
            .map_err(|_| WorkerError::new("AgreementFailed", "clearSecrets failed in worker"))?;
        Ok(json!({ "ok": true }))
    })
}

fn op_drop_handle(args: Value) -> Result<Value, WorkerError> {
    let handle_id = require_u32(&args, "handleId")?;
    drop_handle(handle_id);
    Ok(json!({ "ok": true }))
}

// ---------------------------------------------------------------------------
// wasm-bindgen entry point — invoked from the worker bootstrap
// (`worker/jacs-worker.ts`).
// ---------------------------------------------------------------------------

/// Dispatch one inbound `postMessage` payload. Takes the JS value
/// `event.data`, returns the reply JSON-encoded as a `JsValue` (the
/// JS bootstrap then `postMessage`s it back).
///
/// The reply is *always* a structured `WorkerReply` — even errors are
/// returned as `{ id, ok: false, error }`, **never** as a thrown
/// exception. This keeps the protocol symmetrical and avoids losing
/// the `id` correlation when a handler throws.
#[wasm_bindgen(js_name = workerHandleMessage)]
pub fn worker_handle_message(message: JsValue) -> Result<JsValue, JsError> {
    // Lazy panic-hook install — the worker bootstrap may forget to
    // call `initJacsWasm` (PRD allows the worker to be self-bootstrapping).
    crate::init_jacs_wasm();

    // Try to deserialize as `WorkerRequest`. If that fails we still
    // need to produce a structured reply with `id: 0` so the main
    // thread sees a single uniform shape.
    let request: WorkerRequest = match serde_wasm_bindgen::from_value(message) {
        Ok(r) => r,
        Err(e) => {
            let reply = WorkerReply {
                id: 0,
                ok: false,
                result: None,
                error: Some(
                    serde_json::to_value(WorkerError::malformed_input(format!(
                        "invalid request envelope: {}",
                        e
                    )))
                    .unwrap_or(Value::Null),
                ),
            };
            return reply_to_js_value(&reply);
        }
    };

    let reply = dispatch_request(request);
    reply_to_js_value(&reply)
}

// ---------------------------------------------------------------------------
// Tests — exercise the dispatcher without a Worker context.
// ---------------------------------------------------------------------------

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(id: u64, op: &str, args: Value) -> WorkerRequest {
        WorkerRequest {
            id,
            op: op.to_string(),
            args,
        }
    }

    #[test]
    fn worker_human_recovery_preserves_first_version() {
        let created = dispatch_request(req(101, "createHuman", json!({})))
            .result
            .unwrap();
        let handle_id = created["handleId"].clone();
        let identity = dispatch_request(req(102, "exportAgent", json!({"handleId": handle_id})))
            .result
            .unwrap();
        let identity: Value = serde_json::from_str(identity["value"].as_str().unwrap()).unwrap();
        assert_eq!(identity["jacsAgentType"], "human");
        assert_eq!(identity["jacsVersion"], identity["jacsOriginalVersion"]);
        let backup = dispatch_request(req(103, "exportRecovery", json!({"handleId": handle_id})))
            .result
            .unwrap();
        let backup: Value = serde_json::from_str(backup["value"].as_str().unwrap()).unwrap();
        assert_eq!(backup["code"].as_str().unwrap().len(), 39);
        let imported = dispatch_request(req(104, "importRecovery", json!({
            "materialJson": backup["materialJson"], "code": backup["code"],
            "expectedAgentId": identity["jacsId"], "expectedPublicKeyBase64": created["publicKeyBase64"],
            "expectedAlgorithm": "pq2025"
        }))).result.unwrap();
        let restored = dispatch_request(req(
            105,
            "exportAgent",
            json!({"handleId": imported["handleId"]}),
        ))
        .result
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(restored["value"].as_str().unwrap()).unwrap(),
            identity
        );
        dispatch_request(req(106, "dropHandle", json!({"handleId": handle_id})));
        dispatch_request(req(
            107,
            "dropHandle",
            json!({"handleId": imported["handleId"]}),
        ));
    }

    #[test]
    fn create_ephemeral_returns_handle_id_and_public_key() {
        let reply = dispatch_request(req(1, "createEphemeral", json!({ "algorithm": "ed25519" })));
        assert!(reply.ok, "reply error: {:?}", reply.error);
        assert_eq!(reply.id, 1);
        let result = reply.result.expect("result present");
        assert!(result["handleId"].as_u64().unwrap() > 0);
        assert_eq!(result["algorithm"], Value::String("ed25519".into()));
        assert!(!result["publicKeyBase64"].as_str().unwrap().is_empty());
    }

    #[test]
    fn create_ephemeral_with_unknown_algorithm_returns_unsupported_algorithm() {
        let reply = dispatch_request(req(1, "createEphemeral", json!({ "algorithm": "rsa" })));
        assert!(!reply.ok);
        assert_eq!(
            reply.error.unwrap()["code"],
            Value::String("UnsupportedAlgorithm".into())
        );
    }

    #[test]
    fn sign_then_verify_through_dispatcher_roundtrips() {
        // 1) Create.
        let create_reply =
            dispatch_request(req(1, "createEphemeral", json!({ "algorithm": "ed25519" })));
        let handle_id = create_reply.result.unwrap()["handleId"].as_u64().unwrap() as u32;

        // 2) Sign.
        let sign_reply = dispatch_request(req(
            2,
            "signMessage",
            json!({ "handleId": handle_id, "dataJson": r#"{"x":1}"# }),
        ));
        assert!(sign_reply.ok, "sign error: {:?}", sign_reply.error);
        let signed = sign_reply.result.unwrap()["signedJson"]
            .as_str()
            .unwrap()
            .to_string();

        // 3) Verify.
        let verify_reply = dispatch_request(req(
            3,
            "verify",
            json!({ "handleId": handle_id, "signedJson": signed }),
        ));
        assert!(verify_reply.ok, "verify error: {:?}", verify_reply.error);
        let outcome_json = verify_reply.result.unwrap()["outcomeJson"]
            .as_str()
            .unwrap()
            .to_string();
        let outcome: Value = serde_json::from_str(&outcome_json).unwrap();
        assert_eq!(outcome["valid"], Value::Bool(true));
    }

    #[test]
    fn unknown_op_returns_unsupported_op_error() {
        let reply = dispatch_request(req(7, "doSomething", json!({})));
        assert!(!reply.ok);
        assert_eq!(reply.id, 7);
        assert_eq!(
            reply.error.unwrap()["code"],
            Value::String("UnsupportedOp".into())
        );
    }

    #[test]
    fn missing_handle_id_returns_invalid_handle() {
        // Sign references a handle that was never created.
        let reply = dispatch_request(req(
            5,
            "signMessage",
            json!({ "handleId": 99999, "dataJson": r#"{"x":1}"# }),
        ));
        assert!(!reply.ok);
        assert_eq!(
            reply.error.unwrap()["code"],
            Value::String("InvalidHandle".into())
        );
    }

    // `sign_message_json` constructs a `JsError` on the `Locked`
    // failure path; building a `JsError` panics on non-wasm targets
    // (wasm-bindgen 0.2 limitation, same reason as the
    // native_sanity.rs `#[ignore]`s). The browser-side test in
    // `tests/worker.rs` covers this path under `wasm-pack test`.
    #[test]
    #[ignore = "JsError construction panics on native targets; covered under wasm-pack test"]
    fn clear_secrets_then_sign_returns_locked() {
        let create_reply =
            dispatch_request(req(1, "createEphemeral", json!({ "algorithm": "ed25519" })));
        let handle_id = create_reply.result.unwrap()["handleId"].as_u64().unwrap() as u32;

        let clear_reply =
            dispatch_request(req(2, "clearSecrets", json!({ "handleId": handle_id })));
        assert!(clear_reply.ok);

        let sign_reply = dispatch_request(req(
            3,
            "signMessage",
            json!({ "handleId": handle_id, "dataJson": r#"{"x":1}"# }),
        ));
        assert!(!sign_reply.ok);
        assert_eq!(
            sign_reply.error.unwrap()["code"],
            Value::String("Locked".into())
        );
    }

    #[test]
    fn drop_handle_removes_from_registry() {
        let create_reply =
            dispatch_request(req(1, "createEphemeral", json!({ "algorithm": "ed25519" })));
        let handle_id = create_reply.result.unwrap()["handleId"].as_u64().unwrap() as u32;

        let drop_reply = dispatch_request(req(2, "dropHandle", json!({ "handleId": handle_id })));
        assert!(drop_reply.ok);

        // Subsequent ops on the same id return InvalidHandle.
        let sign_reply = dispatch_request(req(
            3,
            "signMessage",
            json!({ "handleId": handle_id, "dataJson": "{}" }),
        ));
        assert!(!sign_reply.ok);
        assert_eq!(
            sign_reply.error.unwrap()["code"],
            Value::String("InvalidHandle".into())
        );
    }

    #[test]
    fn malformed_args_return_malformed_document() {
        // sign with missing handleId.
        let reply = dispatch_request(req(1, "signMessage", json!({ "dataJson": "{}" })));
        assert!(!reply.ok);
        assert_eq!(
            reply.error.unwrap()["code"],
            Value::String("MalformedDocument".into())
        );
    }
}
