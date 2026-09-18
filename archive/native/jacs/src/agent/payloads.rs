use crate::agent::Agent;
use crate::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use crate::agent::document::DocumentTraits;
use crate::error::JacsError;
use crate::replay;
use serde_json::Value;
use std::time::Duration;
// use crate::agent::{AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME, Agent};
// use crate::crypt::KeyManager;
// use crate::crypt::hash::hash_string as jacs_hash_string;

/*
Payloads are data that is designed sent and received once.
There should be no versions of a payload

*/

fn validate_payload_freshness(date: &str, max_age_seconds: u64) -> Result<(), JacsError> {
    let timestamp = crate::time_utils::parse_rfc3339_to_timestamp(date)?;
    if timestamp < 0 {
        return Err(JacsError::ValidationError(
            "Payload signature timestamp is before the Unix epoch".to_string(),
        ));
    }

    crate::time_utils::validate_timestamp_not_future(date)?;
    if max_age_seconds == 0 {
        return Ok(());
    }
    let max_age_seconds = i64::try_from(max_age_seconds).map_err(|_| {
        JacsError::ValidationError(
            "Payload max replay time exceeds the supported timestamp range".to_string(),
        )
    })?;
    crate::time_utils::validate_timestamp_not_expired(date, max_age_seconds)
}

fn payload_replay_ttl(date: &str, max_age_seconds: u64) -> Result<Duration, JacsError> {
    crate::protocol::replay_ttl_from_rfc3339(date, max_age_seconds, "payload")
}

pub trait PayloadTraits {
    fn sign_payload(&mut self, document: Value) -> Result<String, JacsError>;

    fn verify_payload(
        &mut self,
        document_string: String,
        max_replay_time_delta: Option<u64>,
    ) -> Result<Value, JacsError>;

    fn verify_payload_with_agent_id(
        &mut self,
        document_string: String,
        max_replay_time_delta: Option<u64>,
    ) -> Result<(Value, String), JacsError>;
}

impl PayloadTraits for Agent {
    fn sign_payload(&mut self, jacs_payload: Value) -> Result<String, JacsError> {
        let wrapper_value = serde_json::json!({
            "jacs_payload": jacs_payload
        });

        let wrapper_string = serde_json::to_string(&wrapper_value)?;

        let outputfilename: Option<String> = None;
        let attachments: Option<String> = None;
        let no_save = true;
        let docresult = crate::shared::document_create(
            self,
            &wrapper_string,
            None,
            outputfilename,
            no_save,
            attachments.as_deref(),
            Some(false),
        )?;

        Ok(docresult)
    }

    fn verify_payload(
        &mut self,
        document_string: String,
        max_replay_time_delta: Option<u64>,
    ) -> Result<Value, JacsError> {
        let (payload, _) =
            self.verify_payload_with_agent_id(document_string, max_replay_time_delta)?;
        Ok(payload.clone())
    }

    fn verify_payload_with_agent_id(
        &mut self,
        document_string: String,
        max_replay_time_delta_seconds: Option<u64>,
    ) -> Result<(Value, String), JacsError> {
        let doc = self.load_document(&document_string)?;
        let document_key = doc.getkey();
        let value = doc.getvalue();
        self.verify_hash(value)?;
        self.verify_external_document_signature(&document_key)?;

        let payload = value
            .get("jacs_payload")
            .ok_or_else(|| JacsError::Internal {
                message: "'jacs_payload' field not found".to_string(),
            })?;
        let date = self.get_document_signature_date(&document_key)?;
        let agent_id = self.get_document_signature_agent_id(&document_key)?;

        // Default payload freshness window: 5 minutes.
        // Can be overridden per call, or globally with JACS_PAYLOAD_MAX_REPLAY_SECONDS.
        let max_replay_seconds =
            max_replay_time_delta_seconds.unwrap_or_else(replay::payload_replay_window_seconds);
        validate_payload_freshness(&date, max_replay_seconds)?;

        let jti = value
            .get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
            .and_then(|sig| sig.get("jti"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|nonce| !nonce.is_empty())
            .ok_or_else(|| JacsError::Internal {
                message: "Missing or invalid 'jacsSignature.jti' in payload document".to_string(),
            })?;
        if max_replay_seconds > 0 {
            // Retain through the credential's absolute inclusive expiry. An
            // accepted signer clock may be ahead of this verifier, so a fixed
            // `max_replay_seconds` TTL could expire while the payload remains
            // fresh and permit the same JTI again.
            let replay_ttl = payload_replay_ttl(&date, max_replay_seconds)?;
            replay::check_and_store_nonce_with_ttl(&agent_id, jti, replay_ttl)?;
        }

        Ok((payload.clone(), agent_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_freshness_rejects_pre_epoch_timestamps_without_integer_wraparound() {
        let error = validate_payload_freshness("1969-12-31T23:59:59Z", 300)
            .expect_err("negative Unix timestamps must fail closed");
        assert!(error.to_string().contains("before the Unix epoch"));
    }

    #[test]
    fn payload_freshness_rejects_far_future_timestamps() {
        let error = validate_payload_freshness("2999-01-01T00:00:00Z", 300)
            .expect_err("far-future payload timestamps must fail closed");
        assert!(error.to_string().contains("future"));
    }

    #[test]
    fn payload_replay_ttl_covers_accepted_future_clock_skew() {
        let future = (crate::time_utils::now_utc() + chrono::Duration::seconds(60)).to_rfc3339();
        let ttl = payload_replay_ttl(&future, 300).expect("future-dated payload TTL");

        assert!(
            ttl > Duration::from_secs(300),
            "nonce retention must run through issued_at + max_age, got {ttl:?}"
        );
    }
}
