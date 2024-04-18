use crate::agent::document::{Document, JACSDocument};
use crate::agent::Agent;
use crate::agent::AGENT_AGREEMENT_FIELDNAME;
use crate::agent::JACS_PREVIOUS_VERSION_FIELDNAME;
use crate::agent::JACS_VERSION_DATE_FIELDNAME;
use crate::agent::JACS_VERSION_FIELDNAME;
use crate::crypt::hash::hash_string;
use serde::ser::StdError;
use serde_json::json;
use serde_json::Value;
use std::error::Error;

pub const DOCUMENT_AGREEMENT_HASH_FIELDNAME: &str = "agreementHash";

pub trait Agreement {
    /// given a document id and a list of agents, return an updated document with an agreement field
    /// fails if an agreement field exists
    /// no other fields can be modified or the agreement fails
    /// overwrites previous agreements
    fn create_agreement(
        &mut self,
        document_key: &String,
        agentids: &Vec<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn add_agents_to_agreement(
        &self,
        document_key: &String,
        agentids: &Vec<String>,
    ) -> Result<Value, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn remove_agents_from_agreement(
        &self,
        document_key: &String,
        agentids: &Vec<String>,
    ) -> Result<Value, Box<dyn Error>>;
    /// given a document id sign a document, return an updated document
    fn sign_agreement(&self, document_key: &String) -> Result<Value, Box<dyn Error>>;
    /// given a document, check all agreement signatures
    fn check_agreement(&self, document_key: &String) -> Result<bool, Box<dyn Error>>;
    fn get_signed_agents(&self, document_key: &String) -> Result<Vec<String>, Box<dyn Error>>;
    fn get_unsigned_agents(&self, document_key: &String) -> Result<Vec<String>, Box<dyn Error>>;

    /// agreements update documents
    /// however this updates the document, which updates, version, lastversion and version date
    /// the agreement itself needs it's own hash to track
    /// on a subset of fields
    /// the standard hash detects any changes at all
    fn agreement_hash(&self, value: Value) -> Result<String, Box<dyn Error>>;
}

impl Agreement for Agent {
    fn agreement_hash(&self, mut value: Value) -> Result<String, Box<dyn Error>> {
        // remove update document fields
        value.as_object_mut().map(|obj| {
            obj.remove(JACS_PREVIOUS_VERSION_FIELDNAME);
            obj.remove(JACS_VERSION_FIELDNAME);
            return obj.remove(JACS_VERSION_DATE_FIELDNAME);
        });

        let (values_as_string, _fields) =
            Agent::get_values_as_string(&value, None, &AGENT_AGREEMENT_FIELDNAME.to_string())?;
        Ok(hash_string(&values_as_string))
    }

    fn create_agreement(
        &mut self,
        document_key: &std::string::String,
        agentids: &Vec<String>,
    ) -> Result<JACSDocument, Box<(dyn StdError + 'static)>> {
        let document = self.get_document(document_key)?;
        let mut value = document.value;

        // todo error if value[AGENT_AGREEMENT_FIELDNAME] exists.validate
        let agreement_hash_value = json!(self.agreement_hash(value.clone())?);
        value[AGENT_AGREEMENT_FIELDNAME] = json!({
            // based on v1
            DOCUMENT_AGREEMENT_HASH_FIELDNAME: agreement_hash_value,
            "signatures": [],
            "agentIDs": agentids
        });
        let agreement_hash_value_after = json!(self.agreement_hash(value.clone())?);
        if agreement_hash_value != agreement_hash_value_after {
            return Err(format!(
                "Signature failed hashes don't match for document_key {}",
                document_key
            )
            .into());
        }
        return self.update_document(document_key, &serde_json::to_string(&value)?, None, None);
    }
    fn remove_agents_from_agreement(
        &self,
        document_key: &std::string::String,
        agentids: &Vec<String>,
    ) -> Result<serde_json::Value, Box<(dyn StdError + 'static)>> {
        todo!()
    }
    fn add_agents_to_agreement(
        &self,
        document_key: &std::string::String,
        agentids: &Vec<String>,
    ) -> Result<serde_json::Value, Box<(dyn StdError + 'static)>> {
        todo!()
    }
    fn sign_agreement(
        &self,
        document_key: &std::string::String,
    ) -> Result<serde_json::Value, Box<(dyn StdError + 'static)>> {
        todo!()
    }
    fn check_agreement(
        &self,
        document_key: &std::string::String,
    ) -> Result<bool, Box<(dyn StdError + 'static)>> {
        todo!()
    }

    fn get_signed_agents(&self, document_key: &String) -> Result<Vec<String>, Box<dyn Error>> {
        todo!()
    }
    fn get_unsigned_agents(&self, document_key: &String) -> Result<Vec<String>, Box<dyn Error>> {
        todo!()
    }
}
