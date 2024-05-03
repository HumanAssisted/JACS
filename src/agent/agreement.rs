use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::{Document, JACSDocument};
use crate::agent::loaders::FileLoader;
use crate::agent::Agent;
use crate::agent::JACS_VERSION_DATE_FIELDNAME;
use crate::agent::JACS_VERSION_FIELDNAME;
use crate::agent::{
    AGENT_AGREEMENT_FIELDNAME, DOCUMENT_AGREEMENT_HASH_FIELDNAME, JACS_PREVIOUS_VERSION_FIELDNAME,
    SHA256_FIELDNAME,
};

use crate::crypt::hash::hash_public_key;
use crate::crypt::hash::hash_string;
use crate::schema::utils::ValueExt;
use log::debug;
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
        question: Option<&String>,
        context: Option<&String>,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn add_agents_to_agreement(
        &mut self,
        document_key: &String,
        agentids: &Vec<String>,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id and a list of agents, return an updated document
    fn remove_agents_from_agreement(
        &mut self,
        document_key: &String,
        agentids: &Vec<String>,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document id sign a document, return an updated document
    fn sign_agreement(
        &mut self,
        document_key: &String,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<dyn Error>>;
    /// given a document, check all agreement signatures
    fn check_agreement(
        &self,
        document_key: &String,
        agreement_fieldname: Option<String>,
    ) -> Result<String, Box<dyn Error>>;

    /// agreements update documents
    /// however this updates the document, which updates, version, lastversion and version date
    /// the agreement itself needs it's own hash to track
    /// on a subset of fields
    /// the standard hash detects any changes at all
    fn agreement_hash(
        &self,
        value: Value,
        agreement_fieldname: &String,
    ) -> Result<String, Box<dyn Error>>;

    /// remove fields that should not be used for agreement signature
    fn trim_fields_for_hashing_and_signing(
        &self,
        value: Value,
        agreement_fieldname: &String,
    ) -> Result<(String, Vec<String>), Box<dyn Error>>;

    fn agreement_get_question_and_context(
        &self,
        document_key: &std::string::String,
        agreement_fieldname: Option<String>,
    ) -> Result<(String, String), Box<dyn Error>>;
}

impl Agreement for Agent {
    fn agreement_hash(
        &self,
        value: Value,
        agreement_fieldname: &String,
    ) -> Result<String, Box<dyn Error>> {
        let (values_as_string, _fields) =
            self.trim_fields_for_hashing_and_signing(value, agreement_fieldname)?;
        Ok(hash_string(&values_as_string))
    }

    // ignore these extra fields will change
    fn trim_fields_for_hashing_and_signing(
        &self,
        value: Value,
        agreement_fieldname: &String,
    ) -> Result<(String, Vec<String>), Box<dyn Error>> {
        let mut new_obj: Value = value.clone();
        new_obj.as_object_mut().map(|obj| {
            obj.remove(DOCUMENT_AGREEMENT_HASH_FIELDNAME);
            obj.remove(JACS_PREVIOUS_VERSION_FIELDNAME);
            obj.remove(JACS_VERSION_FIELDNAME);
            return obj.remove(JACS_VERSION_DATE_FIELDNAME);
        });

        let (values_as_string, fields) =
            Agent::get_values_as_string(&new_obj, None, &agreement_fieldname)?;
        return Ok((values_as_string, fields));
    }

    fn create_agreement(
        &mut self,
        document_key: &std::string::String,
        agentids: &Vec<String>,
        question: Option<&String>,
        context: Option<&String>,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<(dyn StdError + 'static)>> {
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
        document_key: &std::string::String,
        agentids: &Vec<String>,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<(dyn StdError + 'static)>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(key) => key,
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };
        let document = self.get_document(document_key)?;
        let mut value = document.value;
        let _binding = value[DOCUMENT_AGREEMENT_HASH_FIELDNAME].clone();

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
        document_key: &std::string::String,
        agentids: &Vec<String>,
        agreement_fieldname: Option<String>,
    ) -> Result<JACSDocument, Box<(dyn StdError + 'static)>> {
        let agreement_fieldname_key = match agreement_fieldname {
            Some(key) => key,
            _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
        };
        let document = self.get_document(document_key)?;
        let mut value = document.value;
        let _binding = value[DOCUMENT_AGREEMENT_HASH_FIELDNAME].clone();

        if let Some(jacs_agreement) = value.get_mut(agreement_fieldname_key.clone()) {
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
            value[agreement_fieldname_key] = json!({
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

        // redundant but make sure agent is listed as a signatory
        let agent_complete_document = self.add_agents_to_agreement(
            document_key,
            &vec![signing_agent_id.clone()],
            agreement_fieldname,
        )?;
        value = agent_complete_document.getvalue();
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
                "agentIDs": [signing_agent_id],
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
        return Err("check_agreement: document has no agreement".into());
    }

    /// checking agreements requires you have the public key of each signatory
    /// if the document hashes don't match or there are unsigned, it will fail
    fn check_agreement(
        &self,
        document_key: &std::string::String,
        agreement_fieldname: Option<String>,
    ) -> Result<String, Box<(dyn StdError + 'static)>> {
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
        if unsigned.len() > 0 {
            return Err(format!(
                "not all agents have signed: {:?} {:?}",
                unsigned,
                document.value.get(agreement_fieldname_key).unwrap()
            )
            .into());
        }

        if let Some(jacs_agreement) = document.value.get(agreement_fieldname_key.clone()) {
            if let Some(signatures) = jacs_agreement.get("signatures") {
                if let Some(signatures_array) = signatures.as_array() {
                    for signature in signatures_array {
                        // todo validate each signature
                        let agent_id_and_version = format!(
                            "{}:{}",
                            signature
                                .get_str("agentID")
                                .expect("REASON agreement signature agentID")
                                .to_string(),
                            signature
                                .get_str("agentVersion")
                                .expect("REASON agreement signature agentVersion")
                                .to_string()
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
                        let (_values_as_string, fields) = self
                            .trim_fields_for_hashing_and_signing(
                                local_doc_value.clone(),
                                &agreement_fieldname_key,
                            )?;
                        let _result = self.signature_verification_procedure(
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
            }
        }
        return Err("check_agreement: document has no agreement".into());
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
    return return_vec1;
}
