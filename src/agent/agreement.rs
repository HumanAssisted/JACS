use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::{Document, JACSDocument};
use crate::agent::Agent;
use crate::agent::JACS_VERSION_DATE_FIELDNAME;
use crate::agent::JACS_VERSION_FIELDNAME;
use crate::agent::{
    AGENT_AGREEMENT_FIELDNAME, DOCUMENT_AGREEMENT_HASH_FIELDNAME, JACS_PREVIOUS_VERSION_FIELDNAME,
    SHA256_FIELDNAME,
};
use crate::crypt::hash::hash_string;
use serde::ser::StdError;
use serde_json::json;
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
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn add_agents_to_agreement(
        &mut self,
        document_key: &String,
        agentids: &Vec<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn remove_agents_from_agreement(
        &mut self,
        document_key: &String,
        agentids: &Vec<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id sign a document, return an updated document
    fn sign_agreement(&mut self, document_key: &String) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document, check all agreement signatures
    fn check_agreement(&self, document_key: &String) -> Result<bool, Box<dyn Error>>;

    fn agreement_signed_agents(
        &mut self,
        document_key: &String,
    ) -> Result<Vec<String>, Box<dyn Error>>;
    fn agreement_unsigned_agents(
        &mut self,
        document_key: &String,
    ) -> Result<Vec<String>, Box<dyn Error>>;
    fn agreement_requested_agents(
        &mut self,
        document_key: &String,
    ) -> Result<Vec<String>, Box<dyn Error>>;

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
            obj.remove(DOCUMENT_AGREEMENT_HASH_FIELDNAME);
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
        value[DOCUMENT_AGREEMENT_HASH_FIELDNAME] = agreement_hash_value.clone();
        value[AGENT_AGREEMENT_FIELDNAME] = json!({
            // based on v1
            "signatures": [],
            "agentIDs": agentids
        });
        let updated_document =
            self.update_document(document_key, &serde_json::to_string(&value)?, None, None)?;

        let agreement_hash_value_after =
            json!(self.agreement_hash(updated_document.value.clone())?);
        // could be unit test, but want this in for safety
        if agreement_hash_value != agreement_hash_value_after {
            return Err(format!(
                "Agreement field hashes don't match for document_key {}",
                document_key
            )
            .into());
        }

        if value[SHA256_FIELDNAME] == updated_document.value[SHA256_FIELDNAME] {
            return Err(format!("document hashes should have changed {}", document_key).into());
        };

        Ok(updated_document)
    }

    /// TODO also remove their signature
    fn remove_agents_from_agreement(
        &mut self,
        document_key: &std::string::String,
        agentids: &Vec<String>,
    ) -> Result<JACSDocument, Box<(dyn StdError + 'static)>> {
        let document = self.get_document(document_key)?;
        let mut value = document.value;
        let binding = value[DOCUMENT_AGREEMENT_HASH_FIELDNAME].clone();

        if let Some(jacs_agreement) = value.get_mut(AGENT_AGREEMENT_FIELDNAME) {
            if let Some(agents) = jacs_agreement.get_mut("agentIDs") {
                if let Some(agents_array) = agents.as_array_mut() {
                    let merged_agents = subtract(
                        &agents_array
                            .iter()
                            .map(|v| v.as_str().unwrap().to_string())
                            .collect(),
                        agentids,
                    );
                    *agents = json!(merged_agents);
                } else {
                    return Err("no agreement  agents  present".into());
                }
            } else {
                return Err("no agreement  agents present".into());
            }
        } else {
            return Err("no agreement   present".into());
        }

        let updated_document =
            self.update_document(document_key, &serde_json::to_string(&value)?, None, None)?;

        Ok(updated_document)
    }

    fn add_agents_to_agreement(
        &mut self,
        document_key: &std::string::String,
        agentids: &Vec<String>,
    ) -> Result<JACSDocument, Box<(dyn StdError + 'static)>> {
        let document = self.get_document(document_key)?;
        let mut value = document.value;
        let binding = value[DOCUMENT_AGREEMENT_HASH_FIELDNAME].clone();

        if let Some(jacs_agreement) = value.get_mut(AGENT_AGREEMENT_FIELDNAME) {
            if let Some(agents) = jacs_agreement.get_mut("agentIDs") {
                if let Some(agents_array) = agents.as_array_mut() {
                    let merged_agents = merge_without_duplicates(
                        &agents_array
                            .iter()
                            .map(|v| v.as_str().unwrap().to_string())
                            .collect(),
                        agentids,
                    );
                    *agents = json!(merged_agents);
                } else {
                    *agents = json!(agentids);
                }
            } else {
                jacs_agreement["agentIDs"] = json!(agentids);
            }
        } else {
            value[AGENT_AGREEMENT_FIELDNAME] = json!({
                "agentIDs": agentids,
                "signatures": [],
            });
        }

        let updated_document =
            self.update_document(document_key, &serde_json::to_string(&value)?, None, None)?;

        Ok(updated_document)
    }

    // TODO Check if signing agent is already in agent_ids
    // if not ???
    fn sign_agreement(
        &mut self,
        document_key: &std::string::String,
    ) -> Result<JACSDocument, Box<(dyn StdError + 'static)>> {
        let document = self.get_document(document_key)?;
        let mut value = document.value;
        let binding = value[DOCUMENT_AGREEMENT_HASH_FIELDNAME].clone();
        let original_agreement_hash_value = binding.as_str();
        // todod use this
        let _calculated_agreement_hash_value = self.agreement_hash(value.clone())?;

        //  generate signature object
        let agents_signature: Value =
            self.signing_procedure(&value.clone(), None, &AGENT_AGREEMENT_FIELDNAME.to_string())?;

        println!(
            "agents_signature {}",
            serde_json::to_string_pretty(&agents_signature).expect("agents_signature print")
        );

        if let Some(jacs_agreement) = value.get_mut(AGENT_AGREEMENT_FIELDNAME) {
            if let Some(signatures) = jacs_agreement.get_mut("signatures") {
                if let Some(signatures_array) = signatures.as_array_mut() {
                    signatures_array.push(agents_signature);
                } else {
                    *signatures = json!([agents_signature]);
                }
            } else {
                jacs_agreement["signatures"] = json!([agents_signature]);
            }
        } else {
            value[AGENT_AGREEMENT_FIELDNAME] = json!({
                "agentIDs": [self.get_id().expect("agent id")],
                "signatures": [agents_signature]
            });
        }
        // add to doc
        let updated_document =
            self.update_document(document_key, &serde_json::to_string(&value)?, None, None)?;

        let agreement_hash_value_after = self.agreement_hash(updated_document.value.clone())?;

        // could be unit test, but want this in for safety
        if original_agreement_hash_value != Some(&agreement_hash_value_after) {
            return Err(format!(
                "aborting signature on agreement. field hashes don't match for document_key {} \n {} {}",
                document_key, original_agreement_hash_value.expect("original_agreement_hash_value"), agreement_hash_value_after
            )
            .into());
        }

        if value[SHA256_FIELDNAME] == updated_document.value[SHA256_FIELDNAME] {
            return Err(format!("document hashes should have changed {}", document_key).into());
        };

        Ok(updated_document)
    }

    // TODO move these to Jacs Document Itself
    fn check_agreement(
        &self,
        document_key: &std::string::String,
    ) -> Result<bool, Box<(dyn StdError + 'static)>> {
        todo!()
    }

    fn agreement_signed_agents(
        &mut self,
        document_key: &String,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        todo!()
    }
    fn agreement_unsigned_agents(
        &mut self,
        document_key: &String,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        todo!()
    }
    fn agreement_requested_agents(
        &mut self,
        document_key: &String,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let document = self.get_document(document_key)?;
        let mut value = document.value;
        if let Some(jacs_agreement) = value.get_mut(AGENT_AGREEMENT_FIELDNAME) {
            if let Some(agents) = jacs_agreement.get("agentIDs") {
                if let Some(agents_array) = agents.as_array() {
                    return Ok(agents_array
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect());
                }
            }
        }
        return Err("no agreement or agents in agreement".into());
    }
}

fn merge_without_duplicates(vec1: &Vec<String>, vec2: &Vec<String>) -> Vec<String> {
    let mut set: HashSet<String> = HashSet::new();

    for item in vec1 {
        set.insert(item.to_string());
    }
    for item in vec2 {
        set.insert(item.to_string());
    }
    set.into_iter().collect()
}

fn subtract(vec1: &Vec<String>, vec2: &Vec<String>) -> Vec<String> {
    let to_remove: HashSet<&String> = vec2.iter().collect();
    vec1.iter()
        .filter(|item| !to_remove.contains(item))
        .cloned()
        .collect()
}
