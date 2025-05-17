use crate::agent::Agent;
use crate::agent::document::DocumentTraits;
use chrono;
use serde_json::Value;
use std::error::Error;
// use crate::agent::{AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME, Agent};
// use crate::crypt::KeyManager;
// use crate::crypt::hash::hash_string as jacs_hash_string;

/*
Payloads are data that is designed sent and received once.
There should be no versions of a payload

*/

pub trait PayloadTraits {
    fn sign_payload(&mut self, document: Value) -> Result<String, Box<dyn Error>>;

    fn verify_payload(
        &mut self,
        document_string: String,
        max_replay_time_delta: Option<u64>,
    ) -> Result<Value, Box<dyn Error>>;

    fn verify_payload_with_agent_id(
        &mut self,
        document_string: String,
        max_replay_time_delta: Option<u64>,
    ) -> Result<(Value, String), Box<dyn Error>>;
}

impl PayloadTraits for Agent {
    fn sign_payload(&mut self, jacs_payload: Value) -> Result<String, Box<dyn Error>> {
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
            attachments.as_ref(),
            Some(false),
        )?;

        Ok(docresult)
    }

    fn verify_payload(
        &mut self,
        document_string: String,
        max_replay_time_delta: Option<u64>,
    ) -> Result<Value, Box<dyn Error>> {
        let (payload, _) =
            self.verify_payload_with_agent_id(document_string, max_replay_time_delta)?;
        Ok(payload.clone())
    }

    fn verify_payload_with_agent_id(
        &mut self,
        document_string: String,
        max_replay_time_delta_seconds: Option<u64>,
    ) -> Result<(Value, String), Box<dyn Error>> {
        let doc = self.load_document(&document_string)?;
        let document_key = doc.getkey();
        let value = doc.getvalue();
        self.verify_hash(value)?;
        self.verify_external_document_signature(&document_key)?;

        let payload = value
            .get("jacs_payload")
            .ok_or_else(|| Box::<dyn Error>::from("'jacs_payload' field not found"))?;
        let date = self.get_document_signature_date(&document_key)?;
        let agent_id = self.get_document_signature_agent_id(&document_key)?;

        let max_replay_seconds = max_replay_time_delta_seconds.unwrap_or(1);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Parse ISO date string to timestamp
        let date_timestamp = chrono::DateTime::parse_from_rfc3339(&date)?.timestamp() as u64;

        // Check if signature is too old
        if current_time > date_timestamp && current_time - date_timestamp > max_replay_seconds {
            return Err(Box::<dyn Error>::from(format!(
                "Signature too old: {} seconds (max allowed: {})",
                current_time - date_timestamp,
                max_replay_seconds
            )));
        }

        Ok((payload.clone(), agent_id))
    }
}
