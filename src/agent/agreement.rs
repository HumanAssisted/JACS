use crate::agent::document::{Document, JACSDocument};
use crate::agent::Agent;
use crate::agent::AGENT_AGREEMENT_FIELDNAME;
use serde::ser::StdError;
use serde_json::json;
use serde_json::Value;
use std::error::Error;

pub trait Agreement {
    /// given a document id and a list of agents, return an updated document with an agreement field
    /// fails if an agreement field exists
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
}

impl Agreement for Agent {
    fn create_agreement(
        &mut self,
        document_key: &std::string::String,
        agentids: &Vec<String>,
    ) -> Result<JACSDocument, Box<(dyn StdError + 'static)>> {
        let document = self.get_document(document_key)?;
        let mut value = document.value;

        // todo error if value[AGENT_AGREEMENT_FIELDNAME] exists.validate

        value[AGENT_AGREEMENT_FIELDNAME] = json!({
            // based on v1
            "signatures": [],
            "agentIDs": agentids
        });

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
}
