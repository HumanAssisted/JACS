use crate::agent::Agent;
use serde::ser::StdError;
use serde_json::Value;
use std::error::Error;
// use crate::agent::document::Document;

pub trait Agreement {
    /// given a document id and a list of agents, return an updated document with an agreement field
    /// fails if an agreement field exists
    fn create_agreement(
        &self,
        document_key: &String,
        agentids: &Vec<String>,
    ) -> Result<Value, Box<dyn Error>>;
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
        &self,
        document_key: &std::string::String,
        agentids: &Vec<String>,
    ) -> Result<serde_json::Value, Box<(dyn StdError + 'static)>> {
        todo!()
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
