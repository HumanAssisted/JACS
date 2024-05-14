use crate::agent::JACSDocument;
use log::debug;
use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;

pub trait Agreement {
    /// given a document id and a list of agents, return an updated document with an agreement field
    /// fails if an agreement field exists
    /// no other fields can be modified or the agreement fails
    /// overwrites previous agreements
    fn create_agreement(
        &mut self,
        document_key: &String,
        agentids: &Vec<String>,
        question: Option<&String>,
        context: Option<&String>,
        _agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn add_agents_to_agreement(
        &mut self,
        document_key: &String,
        agentids: &Vec<String>,
        _agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn remove_agents_from_agreement(
        &mut self,
        document_key: &String,
        agentids: &Vec<String>,
        _agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id sign a document, return an updated document
    fn sign_agreement(
        &mut self,
        document_key: &String,
        _agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document, check all agreement signatures
    fn check_agreement(
        &self,
        document_key: &String,
        _agreement_fieldname: Option<String>,
    ) -> Result<String, Box<dyn Error>>;

    /// agreements update documents
    /// however this updates the document, which updates, version, lastversion and version date
    /// the agreement itself needs it's own hash to track
    /// on a subset of fields
    /// the standard hash detects any changes at all
    fn agreement_hash(
        &self,
        value: Value,
        _agreement_fieldname: &String,
    ) -> Result<String, Box<dyn Error>>;

    /// remove fields that should not be used for agreement signature
    fn trim_fields_for_hashing_and_signing(
        &self,
        value: Value,
        _agreement_fieldname: &String,
    ) -> Result<(String, Vec<String>), Box<dyn Error>>;

    fn agreement_get_question_and_context(
        &self,
        document_key: &std::string::String,
        _agreement_fieldname: Option<String>,
    ) -> Result<(String, String), Box<dyn Error>>;
}

pub fn merge_without_duplicates(vec1: &Vec<String>, vec2: &Vec<String>) -> Vec<String> {
    let mut set: HashSet<String> = HashSet::new();

    for item in vec1 {
        set.insert(item.to_string());
    }
    for item in vec2 {
        set.insert(item.to_string());
    }
    set.into_iter().collect()
}

pub fn subtract_vecs(vec1: &Vec<String>, vec2: &Vec<String>) -> Vec<String> {
    debug!("subtract_vecs A {:?} {:?} ", vec1, vec2);

    let to_remove: HashSet<&String> = vec2.iter().collect();
    let return_vec1 = vec1
        .iter()
        .filter(|item| !to_remove.contains(item))
        .cloned()
        .collect();
    debug!("subtract_vecs B {:?}- {:?} = {:?}", vec1, vec2, return_vec1);
    return return_vec1;
}
