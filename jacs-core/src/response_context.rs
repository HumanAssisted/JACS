//! Closed response-v2 action contexts. Cryptographic verification stays in the
//! response-v2 verifier; this module validates the independently expected
//! transaction, recipient, and event channel before an application acts.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CoreError, identity::JacsTime};

/// Frozen response-v2 signature bytes. This excludes only the signature value;
/// unknown envelope fields remain signed for legacy wire compatibility.
pub fn response_signing_input(envelope: &Value) -> Result<String, CoreError> {
    let mut unsigned = envelope.clone();
    let signature = unsigned
        .get_mut("jacsSignature")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            CoreError::MalformedDocument("response envelope is missing the signature object".into())
        })?;
    signature.remove("signature");
    Ok(format!(
        "JACS-RESPONSE-V2\n{}",
        crate::canonical::canonicalize_json_try(&unsigned)?
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RequestBinding {
    RequestDigest(String),
    RequestNonce(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum EventTransport {
    Stream(String),
    Channel(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventCausation {
    None { id: () },
    Job { id: String },
    Event { id: String },
}

/// The operation is chosen by the authorized signing method, then checked
/// against the context class. A payload cannot relabel an operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseOperation {
    SignBoundResponse,
    SignAsyncEvent,
}

/// Exactly the signed `/data` object from TP-34. Event provenance is filled by
/// the signer from its own envelope metadata, never from unsigned wire labels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "contextClass",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ResponseData {
    DirectResponse {
        request_id: String,
        request_binding: RequestBinding,
        audience: String,
        response_type: String,
        payload: Value,
    },
    PrivateEvent {
        event_type: String,
        contract: String,
        contract_version: String,
        transport: EventTransport,
        issuer: String,
        tenant: String,
        audience: String,
        event_id: String,
        emitted_at: String,
        causation: EventCausation,
        payload: Value,
    },
    PublicBroadcast {
        event_type: String,
        contract: String,
        contract_version: String,
        channel: String,
        issuer: String,
        audience: String,
        event_id: String,
        emitted_at: String,
        payload: Value,
    },
}

/// Trusted application input. ExactContext is the entire signed context with
/// only `payload` removed. Stream expectations admit fresh server-assigned
/// event IDs/times while explicitly constraining the issuer and destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ResponseExpectation {
    ExactContext {
        value: Value,
    },
    DirectResponse {
        request_id: String,
        request_binding: RequestBinding,
        audience: String,
        response_type: String,
    },
    PrivateEvent {
        issuer: String,
        tenant: String,
        audience: String,
        transport: EventTransport,
        contract: String,
        contract_version: String,
        allowed_event_types: Vec<String>,
        causation: Option<EventCausation>,
    },
    PublicBroadcast {
        issuer: String,
        channel: String,
        contract: String,
        contract_version: String,
        allowed_event_types: Vec<String>,
    },
}

fn invalid(message: &str) -> CoreError {
    CoreError::MalformedDocument(format!("response context: {message}"))
}

fn nonempty(value: &str, name: &str) -> Result<(), CoreError> {
    if value.is_empty() {
        Err(invalid(&format!("{name} is empty")))
    } else {
        Ok(())
    }
}

impl ResponseData {
    pub fn operation(&self) -> ResponseOperation {
        match self {
            Self::DirectResponse { .. } => ResponseOperation::SignBoundResponse,
            Self::PrivateEvent { .. } | Self::PublicBroadcast { .. } => {
                ResponseOperation::SignAsyncEvent
            }
        }
    }

    pub fn payload(&self) -> &Value {
        match self {
            Self::DirectResponse { payload, .. }
            | Self::PrivateEvent { payload, .. }
            | Self::PublicBroadcast { payload, .. } => payload,
        }
    }

    /// Complete operation context used by verification intents and receipts.
    pub fn operation_context(&self) -> Result<Value, CoreError> {
        self.validate()?;
        let mut value = serde_json::to_value(self).map_err(|error| invalid(&error.to_string()))?;
        value
            .as_object_mut()
            .ok_or_else(|| invalid("context is not an object"))?
            .remove("payload");
        Ok(value)
    }

    /// Fill only envelope-owned event provenance before signing.
    pub fn bind_event_metadata(&mut self, issuer_value: &str, id_value: &str, time_value: &str) {
        match self {
            Self::DirectResponse { .. } => {}
            Self::PrivateEvent {
                issuer,
                event_id,
                emitted_at,
                ..
            }
            | Self::PublicBroadcast {
                issuer,
                event_id,
                emitted_at,
                ..
            } => {
                *issuer = issuer_value.into();
                *event_id = id_value.into();
                *emitted_at = time_value.into();
            }
        }
    }

    pub fn validate(&self) -> Result<(), CoreError> {
        crate::canonical::canonicalize_json_try(self.payload())?;
        match self {
            Self::DirectResponse {
                request_id,
                request_binding,
                audience,
                response_type,
                ..
            } => {
                nonempty(request_id, "requestId")?;
                nonempty(response_type, "responseType")?;
                match request_binding {
                    RequestBinding::RequestDigest(value) | RequestBinding::RequestNonce(value) => {
                        nonempty(value, "requestBinding.value")?
                    }
                }
                nonempty(audience, "audience")?;
                if audience == "public" {
                    return Err(invalid("direct response requires a private audience"));
                }
            }
            Self::PrivateEvent {
                event_type,
                contract,
                contract_version,
                transport,
                issuer,
                tenant,
                audience,
                event_id,
                emitted_at,
                causation,
                ..
            } => {
                validate_event(
                    event_type,
                    contract,
                    contract_version,
                    issuer,
                    event_id,
                    emitted_at,
                )?;
                nonempty(tenant, "tenant")?;
                nonempty(audience, "audience")?;
                if audience == "public" {
                    return Err(invalid("private event requires a private audience"));
                }
                match transport {
                    EventTransport::Stream(value) | EventTransport::Channel(value) => {
                        nonempty(value, "transport.value")?
                    }
                }
                match causation {
                    EventCausation::None { .. } => {}
                    EventCausation::Job { id } | EventCausation::Event { id } => {
                        nonempty(id, "causation.id")?
                    }
                }
            }
            Self::PublicBroadcast {
                event_type,
                contract,
                contract_version,
                channel,
                issuer,
                audience,
                event_id,
                emitted_at,
                ..
            } => {
                validate_event(
                    event_type,
                    contract,
                    contract_version,
                    issuer,
                    event_id,
                    emitted_at,
                )?;
                nonempty(channel, "channel")?;
                if audience != "public" {
                    return Err(invalid("public broadcast audience must equal public"));
                }
            }
        }
        Ok(())
    }

    pub fn validate_envelope_metadata(&self, envelope: &Value) -> Result<(), CoreError> {
        self.validate()?;
        let event = match self {
            Self::DirectResponse { .. } => return Ok(()),
            Self::PrivateEvent {
                issuer,
                event_id,
                emitted_at,
                ..
            }
            | Self::PublicBroadcast {
                issuer,
                event_id,
                emitted_at,
                ..
            } => (issuer, event_id, emitted_at),
        };
        for (pointer, expected) in [
            ("/metadata/issuer", event.0),
            ("/jacsSignature/agentID", event.0),
            ("/metadata/document_id", event.1),
            ("/metadata/created_at", event.2),
        ] {
            if envelope.pointer(pointer).and_then(Value::as_str) != Some(expected.as_str()) {
                return Err(invalid(&format!("event provenance differs from {pointer}")));
            }
        }
        Ok(())
    }

    pub fn matches_expected(&self, expected: &ResponseExpectation) -> Result<(), CoreError> {
        self.validate()?;
        let matches = match (self, expected) {
            (_, ResponseExpectation::ExactContext { value }) => self.operation_context()? == *value,
            (
                Self::DirectResponse {
                    request_id,
                    request_binding,
                    audience,
                    response_type,
                    ..
                },
                ResponseExpectation::DirectResponse {
                    request_id: id,
                    request_binding: binding,
                    audience: target,
                    response_type: kind,
                },
            ) => {
                request_id == id
                    && request_binding == binding
                    && audience == target
                    && response_type == kind
            }
            (
                Self::PrivateEvent {
                    event_type,
                    contract,
                    contract_version,
                    transport,
                    issuer,
                    tenant,
                    audience,
                    causation,
                    ..
                },
                ResponseExpectation::PrivateEvent {
                    issuer: source,
                    tenant: expected_tenant,
                    audience: target,
                    transport: expected_transport,
                    contract: expected_contract,
                    contract_version: version,
                    allowed_event_types,
                    causation: expected_causation,
                },
            ) => {
                issuer == source
                    && tenant == expected_tenant
                    && audience == target
                    && transport == expected_transport
                    && contract == expected_contract
                    && contract_version == version
                    && allowed_event_types.contains(event_type)
                    && expected_causation
                        .as_ref()
                        .is_none_or(|expected| expected == causation)
            }
            (
                Self::PublicBroadcast {
                    event_type,
                    contract,
                    contract_version,
                    channel,
                    issuer,
                    ..
                },
                ResponseExpectation::PublicBroadcast {
                    issuer: source,
                    channel: expected_channel,
                    contract: expected_contract,
                    contract_version: version,
                    allowed_event_types,
                },
            ) => {
                issuer == source
                    && channel == expected_channel
                    && contract == expected_contract
                    && contract_version == version
                    && allowed_event_types.contains(event_type)
            }
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(CoreError::SignatureInvalid(
                "response context does not match the expected transaction or recipient".into(),
            ))
        }
    }
}

fn validate_event(
    event_type: &str,
    contract: &str,
    version: &str,
    issuer: &str,
    event_id: &str,
    emitted_at: &str,
) -> Result<(), CoreError> {
    for (name, value) in [
        ("eventType", event_type),
        ("contract", contract),
        ("contractVersion", version),
        ("issuer", issuer),
        ("eventId", event_id),
    ] {
        nonempty(value, name)?;
    }
    JacsTime::parse(emitted_at)?;
    Ok(())
}

/// Legacy data remains inspectable, but yields no action context. Unknown or
/// incomplete new contexts are errors, never a legacy fallback.
pub fn inspect_response_context(envelope: &Value) -> Result<Option<ResponseData>, CoreError> {
    let data = envelope
        .get("data")
        .ok_or_else(|| invalid("missing data"))?;
    if data.get("contextClass").is_none() {
        return Ok(None);
    }
    let parsed: ResponseData =
        serde_json::from_value(data.clone()).map_err(|error| invalid(&error.to_string()))?;
    parsed.validate_envelope_metadata(envelope)?;
    Ok(Some(parsed))
}

pub fn require_response_context(
    envelope: &Value,
    expected: &ResponseExpectation,
) -> Result<ResponseData, CoreError> {
    let data = inspect_response_context(envelope)?.ok_or_else(|| {
        CoreError::SignatureInvalid(
            "legacy_event_context: response has no portable action context".into(),
        )
    })?;
    data.matches_expected(expected)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn direct_response_requires_exact_request_and_audience() {
        let data = ResponseData::DirectResponse {
            request_id: "request-1".into(),
            request_binding: RequestBinding::RequestNonce("nonce-1".into()),
            audience: "recipient-1".into(),
            response_type: "result".into(),
            payload: json!({"ok":true}),
        };
        let expected = ResponseExpectation::DirectResponse {
            request_id: "request-1".into(),
            request_binding: RequestBinding::RequestNonce("nonce-1".into()),
            audience: "recipient-1".into(),
            response_type: "result".into(),
        };
        assert!(data.matches_expected(&expected).is_ok());
        let mut context = data.operation_context().unwrap();
        context["audience"] = json!("recipient-2");
        assert!(
            data.matches_expected(&ResponseExpectation::ExactContext { value: context })
                .is_err()
        );
        assert_eq!(data.operation(), ResponseOperation::SignBoundResponse);
    }

    #[test]
    fn closed_union_rejects_unknown_fields_missing_null_and_legacy_action() {
        let invalid = json!({"contextClass":"direct_response","requestId":"r","requestBinding":{"type":"request_nonce","value":"n","extra":true},"audience":"a","responseType":"result","payload":null});
        assert!(serde_json::from_value::<ResponseData>(invalid).is_err());
        assert!(serde_json::from_value::<EventCausation>(json!({"type":"none"})).is_err());
        assert!(
            serde_json::from_value::<EventCausation>(json!({"type":"none","id":"not-null"}))
                .is_err()
        );
        let legacy = json!({"data":{"type":"heartbeat"}});
        assert!(inspect_response_context(&legacy).unwrap().is_none());
        assert!(
            require_response_context(
                &legacy,
                &ResponseExpectation::ExactContext { value: json!({}) }
            )
            .is_err()
        );
    }
}
