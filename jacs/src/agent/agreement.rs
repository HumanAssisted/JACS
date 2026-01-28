use crate::agent::Agent;
use crate::agent::JACS_VERSION_DATE_FIELDNAME;
use crate::agent::JACS_VERSION_FIELDNAME;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::agent::loaders::FileLoader;
use crate::agent::{
    AGENT_AGREEMENT_FIELDNAME, DOCUMENT_AGREEMENT_HASH_FIELDNAME, JACS_PREVIOUS_VERSION_FIELDNAME,
    SHA256_FIELDNAME,
};

use crate::crypt::hash::hash_public_key;
use crate::crypt::hash::hash_string;
use crate::schema::utils::ValueExt;
use serde::ser::StdError;
use serde_json::Value;
use serde_json::json;
use std::collections::HashSet;
use std::error::Error;
use tracing::debug;

pub trait Agreement {
    /// given a document id and a list of agents, return an updated document with an agreement field
    /// fails if an agreement field exists
    /// no other fields can be modified or the agreement fails
    /// overwrites previous agreements
    fn create_agreement(
        &mut self,
        document_key: &str,
        agentids: &[String],
        question: Option<&str>,
        context: Option<&str>,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn add_agents_to_agreement(
        &mut self,
        document_key: &str,
        agentids: &[String],
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn remove_agents_from_agreement(
        &mut self,
        document_key: &str,
        agentids: &[String],
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id sign a document, return an updated document
    fn sign_agreement(
        &mut self,
        document_key: &str,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document, check all agreement signatures
    fn check_agreement(
        &self,
        document_key: &str,
        agreement_fieldname: Option<String>,
    ) -> Result<String, Box<dyn Error>>;

    /// given a document, check all agreement signatures
    fn has_agreement(&self, document_key: &str) -> Result<bool, Box<dyn Error>>;

    /// agreements update documents
    /// however this updates the document, which updates, version, lastversion and version date
    /// the agreement itself needs it's own hash to track
    /// on a subset of fields
    /// the standard hash detects any changes at all
    fn agreement_hash(
        &self,
        value: Value,
        agreement_fieldname: &str,
    ) -> Result<String, Box<dyn Error>>;

    /// remove fields that should not be used for agreement signature
    fn trim_fields_for_hashing_and_signing(
        &self,
        value: Value,
        agreement_fieldname: &str,
    ) -> Result<(String, Vec<String>), Box<dyn Error>>;

    fn agreement_get_question_and_context(
        &self,
        document_key: &str,
        agreement_fieldname: Option<String>,
    ) -> Result<(String, String), Box<dyn Error>>;
}

impl Agreement for Agent {
    fn agreement_hash(
        &self,
        value: Value,
        agreement_fieldname: &str,
    ) -> Result<String, Box<dyn Error>> {
        let (values_as_string, _fields) =
            self.trim_fields_for_hashing_and_signing(value, agreement_fieldname)?;
        Ok(hash_string(&values_as_string))
    }

    /// ineffienct because it doesn't pull from the document
    fn has_agreement(&self, document_key: &str) -> Result<bool, Box<dyn Error>> {
        let document = self.get_document(document_key)?;
        let agreement_fieldname_key = AGENT_AGREEMENT_FIELDNAME.to_string();
        let agreement_field = document.value.get(&agreement_fieldname_key);
        if agreement_field.is_some() {
            return Ok(true);
        }
        Ok(false)
    }
    // ignore these extra fields will change
    fn trim_fields_for_hashing_and_signing(
        &self,
        value: Value,
        agreement_fieldname: &str,
    ) -> Result<(String, Vec<String>), Box<dyn Error>> {
        let mut new_obj: Value = value.clone();
        new_obj.as_object_mut().map(|obj| {
            obj.remove(DOCUMENT_AGREEMENT_HASH_FIELDNAME);
            obj.remove(JACS_PREVIOUS_VERSION_FIELDNAME);
            obj.remove(JACS_VERSION_FIELDNAME);
            obj.remove(JACS_VERSION_DATE_FIELDNAME)
        });

        let (values_as_string, fields) =
            Agent::get_values_as_string(&new_obj, None, agreement_fieldname)?;
        Ok((values_as_string, fields))
    }

    fn create_agreement(
        &mut self,
        document_key: &str,
        agentids: &[String],
        question: Option<&str>,
        context: Option<&str>,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn StdError + 'static>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(key) => key,
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };
        let document = self.get_document(document_key)?;
        let mut value = document.value;

        let context_string = match context {
            Some(cstring) => cstring,
            _ => "",
        };

        let question_string = match question {
            Some(qstring) => qstring,
            _ => "",
        };
        // todo error if value[AGENT_AGREEMENT_FIELDNAME] exists.validate
        let agreement_hash_value =
            json!(self.agreement_hash(value.clone(), &agreement_fieldname_key)?);
        value[DOCUMENT_AGREEMENT_HASH_FIELDNAME] = agreement_hash_value.clone();
        value[agreement_fieldname_key.clone()] = json!({
            // based on v1
            "signatures": [],
            "agentIDs": agentids,
            "question": question_string,
            "context": context_string
        });
        let updated_document =
            self.update_document(document_key, &serde_json::to_string(&value)?, None, None)?;

        let agreement_hash_value_after =
            json!(self.agreement_hash(updated_document.value.clone(), &agreement_fieldname_key)?);
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
        document_key: &str,
        agentids: &[String],
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn StdError + 'static>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(key) => key,
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };
        let document = self.get_document(document_key)?;
        let mut value = document.value;
        let _ = value[DOCUMENT_AGREEMENT_HASH_FIELDNAME].clone();

        if let Some(jacs_agreement) = value.get_mut(agreement_fieldname_key) {
            if let Some(agents) = jacs_agreement.get_mut("agentIDs") {
                if let Some(agents_array) = agents.as_array_mut() {
                    let merged_agents = subtract_vecs(
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
        document_key: &str,
        agentids: &[String],
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn StdError + 'static>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(key) => key,
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };
        let document = self.get_document(document_key)?;
        let mut value = document.value;
        let _ = value[DOCUMENT_AGREEMENT_HASH_FIELDNAME].clone();

        // Normalize agent IDs - ensure we're only using the base ID without version
        let normalized_agent_ids: Vec<String> = agentids
            .iter()
            .map(|id| {
                // If the ID contains a colon (indicating ID:version format), just take the part before the colon
                if let Some(pos) = id.find(':') {
                    id[0..pos].to_string()
                } else {
                    id.clone()
                }
            })
            .collect();

        if let Some(jacs_agreement) = value.get_mut(agreement_fieldname_key.clone()) {
            if let Some(agents) = jacs_agreement.get_mut("agentIDs") {
                if let Some(agents_array) = agents.as_array_mut() {
                    // Normalize existing agent IDs in the same way
                    let existing_agents: Vec<String> = agents_array
                        .iter()
                        .map(|v| {
                            let id_str = v.as_str().unwrap().to_string();
                            if let Some(pos) = id_str.find(':') {
                                id_str[0..pos].to_string()
                            } else {
                                id_str
                            }
                        })
                        .collect();

                    let merged_agents =
                        merge_without_duplicates(&existing_agents, &normalized_agent_ids);
                    *agents = json!(merged_agents);
                } else {
                    *agents = json!(normalized_agent_ids);
                }
            } else {
                jacs_agreement["agentIDs"] = json!(normalized_agent_ids);
            }
        } else {
            value[agreement_fieldname_key] = json!({
                "agentIDs": normalized_agent_ids,
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
        document_key: &str,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(ref key) => key.to_string(),
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };

        let document = self.get_document(document_key)?;
        let mut value = document.value;
        let binding = value[DOCUMENT_AGREEMENT_HASH_FIELDNAME].clone();
        let original_agreement_hash_value = binding.as_str();
        // todo use this
        let _calculated_agreement_hash_value =
            self.agreement_hash(value.clone(), &agreement_fieldname_key)?;
        let signing_agent_id = self.get_id().expect("agent id");
        //  generate signature object
        let (_values_as_string, fields) =
            self.trim_fields_for_hashing_and_signing(value.clone(), &agreement_fieldname_key)?;
        let agents_signature: Value = self.signing_procedure(
            &value.clone(),
            Some(&fields),
            &agreement_fieldname_key.to_string(),
        )?;

        // Normalize signing agent ID to avoid duplicates - extract just the ID part
        let normalized_agent_id = if let Some(pos) = signing_agent_id.find(':') {
            signing_agent_id[0..pos].to_string()
        } else {
            signing_agent_id.clone()
        };

        // Check if agent ID (normalized) is already in the agreement
        let mut agent_already_in_agreement = false;
        if let Some(jacs_agreement) = value.get(agreement_fieldname_key.clone())
            && let Some(agents) = jacs_agreement.get("agentIDs")
            && let Some(agents_array) = agents.as_array()
        {
            for agent in agents_array {
                let agent_str = agent.as_str().unwrap_or("");
                let agent_normalized = if let Some(pos) = agent_str.find(':') {
                    agent_str[0..pos].to_string()
                } else {
                    agent_str.to_string()
                };
                if agent_normalized == normalized_agent_id {
                    agent_already_in_agreement = true;
                    break;
                }
            }
        }

        // Only add the agent ID if it's not already in the agreement
        let agent_complete_document = if !agent_already_in_agreement {
            self.add_agents_to_agreement(
                document_key,
                &vec![normalized_agent_id.clone()],
                agreement_fieldname.clone(),
            )?
        } else {
            // Get a fresh copy of the document instead of using the moved one
            self.get_document(document_key)?
        };

        value = agent_complete_document.getvalue().clone();
        let agent_complete_key = agent_complete_document.getkey();
        debug!(
            "agents_signature {}",
            serde_json::to_string_pretty(&agents_signature).expect("agents_signature print")
        );

        if let Some(jacs_agreement) = value.get_mut(&agreement_fieldname_key) {
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
            value[agreement_fieldname_key.clone()] = json!({
                "agentIDs": [normalized_agent_id],
                "signatures": [agents_signature]
            });
        }
        // add to doc
        let updated_document = self.update_document(
            &agent_complete_key,
            &serde_json::to_string(&value)?,
            None,
            None,
        )?;

        let agreement_hash_value_after =
            self.agreement_hash(updated_document.value.clone(), &agreement_fieldname_key)?;

        // could be unit test, but want this in for safety
        if original_agreement_hash_value != Some(&agreement_hash_value_after) {
            return Err(format!(
                "aborting signature on agreement. field hashes don't match for document_key {} \n {} {}",
                agent_complete_key, original_agreement_hash_value.expect("original_agreement_hash_value"), agreement_hash_value_after
            )
            .into());
        }

        if value[SHA256_FIELDNAME] == updated_document.value[SHA256_FIELDNAME] {
            return Err(format!("document hashes should have changed {}", document_key).into());
        };

        Ok(updated_document)
    }

    /// get human readable fields
    fn agreement_get_question_and_context(
        &self,
        document_key: &std::string::String,
        agreement_fieldname: Option<String>,
    ) -> Result<(String, String), Box<dyn Error>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(key) => key,
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };

        let document = self.get_document(document_key)?;
        let error_message = format!("{} missing", DOCUMENT_AGREEMENT_HASH_FIELDNAME);
        let original_agreement_hash_value = document.value[DOCUMENT_AGREEMENT_HASH_FIELDNAME]
            .as_str()
            .expect(&error_message);
        let calculated_agreement_hash_value =
            self.agreement_hash(document.value.clone(), &agreement_fieldname_key)?;
        if original_agreement_hash_value != calculated_agreement_hash_value {
            return Err("check_agreement: agreement hashes don't match".into());
        }

        if let Some(jacs_agreement) = document.value.get(agreement_fieldname_key) {
            let question = jacs_agreement
                .get_str("question")
                .expect("agreement_get_question_and_context question field");
            let context = jacs_agreement
                .get_str("context")
                .expect("agreement_get_question_and_context question field");

            return Ok((question.to_string(), context.to_string()));
        }
        Err("check_agreement: document has no agreement".into())
    }

    /// checking agreements requires you have the public key of each signatory
    /// if the document hashes don't match or there are unsigned, it will fail
    fn check_agreement(
        &self,
        document_key: &std::string::String,
        agreement_fieldname: Option<String>,
    ) -> Result<String, Box<dyn StdError + 'static>> {
        let agreement_fieldname_key: String = match agreement_fieldname {
            Some(ref key) => key.to_string(),
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };

        let document = self.get_document(document_key)?;
        let local_doc_value = document.value.clone();
        let error_message = format!("{} missing", DOCUMENT_AGREEMENT_HASH_FIELDNAME);
        let original_agreement_hash_value = document.value[DOCUMENT_AGREEMENT_HASH_FIELDNAME]
            .as_str()
            .expect(&error_message);
        let calculated_agreement_hash_value =
            self.agreement_hash(document.value.clone(), &agreement_fieldname_key)?;
        if original_agreement_hash_value != calculated_agreement_hash_value {
            return Err("check_agreement: agreement hashes don't match".into());
        }

        let unsigned = document.agreement_unsigned_agents(agreement_fieldname.clone())?;
        if !unsigned.is_empty() {
            return Err(format!(
                "not all agents have signed: {:?} {:?}",
                unsigned,
                document.value.get(agreement_fieldname_key).unwrap()
            )
            .into());
        }

        if let Some(jacs_agreement) = document.value.get(agreement_fieldname_key.clone())
            && let Some(signatures) = jacs_agreement.get("signatures")
            && let Some(signatures_array) = signatures.as_array()
        {
            for signature in signatures_array {
                // todo validate each signature
                let agent_id_and_version = format!(
                    "{}:{}",
                    signature
                        .get_str("agentID")
                        .expect("REASON agreement signature agentID"),
                    signature
                        .get_str("agentVersion")
                        .expect("REASON agreement signature agentVersion")
                )
                .to_string();

                let noted_hash = signature
                    .get_str("publicKeyHash")
                    .expect("REASON noted_hash")
                    .to_string();

                let public_key_enc_type = signature
                    .get_str("signingAlgorithm")
                    .expect("REASON public_key_enc_type")
                    .to_string();
                let agents_signature = signature
                    .get_str("signature")
                    .expect("REASON public_key_enc_type")
                    .to_string();
                let agents_public_key = self.fs_load_public_key(&noted_hash)?;
                let new_hash = hash_public_key(agents_public_key.clone());
                if new_hash != noted_hash {
                    return Err(format!(
                        "wrong public key for {} , {}",
                        agent_id_and_version, noted_hash
                    )
                    .into());
                }
                debug!(
                    "testing agreement sig agent_id_and_version {} {} {} ",
                    agent_id_and_version, noted_hash, public_key_enc_type
                );
                let (_values_as_string, fields) = self.trim_fields_for_hashing_and_signing(
                    local_doc_value.clone(),
                    &agreement_fieldname_key,
                )?;
                self.signature_verification_procedure(
                    &document.value,
                    Some(&fields),
                    &agreement_fieldname_key.to_string(),
                    agents_public_key,
                    Some(public_key_enc_type.clone()),
                    Some(noted_hash.clone()),
                    Some(agents_signature),
                )?;
            }
            return Ok("All signatures passed".to_string());
        }
        Err("check_agreement: document has no agreement".into())
    }
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
    return_vec1
}
