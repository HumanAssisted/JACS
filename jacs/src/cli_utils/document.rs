use crate::agent::AGENT_AGREEMENT_FIELDNAME;
use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::cli_utils::get_storage_default_for_cli;
use crate::cli_utils::set_file_list;
use crate::shared::document_add_agreement;
use crate::shared::document_check_agreement;
use crate::shared::document_create;
use crate::shared::document_load_and_save;
use crate::shared::document_sign_agreement;
use std::error::Error;

pub fn create_agreement(
    mut agent: Agent,
    agentids: Vec<String>,
    filename: Option<&String>,
    schema: Option<&String>,
    no_save: bool,
    directory: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let storage = get_storage_default_for_cli();
    let files: Vec<String> = set_file_list(storage.as_ref().unwrap(), filename, directory, None)
        .expect("Failed to determine file list");
    for file in &files {
        // Use storage to read the input document file
        let content_bytes = storage
            .as_ref()
            .expect("Storage must be initialized for this command")
            .get_file(file, None)
            .expect(&format!("Failed to load document file: {}", file));
        let document_string = String::from_utf8(content_bytes)
            .expect(&format!("Document file {} is not valid UTF-8", file));
        let result = document_add_agreement(
            &mut agent,
            &document_string,
            agentids.clone(),
            schema.cloned(),
            None,
            None,
            None,
            None,
            None,
            no_save,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("reason");
        println!("{}", result);
    }
    Ok(())
}

pub fn check_agreement(
    mut agent: Agent,
    schema: Option<&String>,
    filename: Option<&String>,
    directory: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let storage = get_storage_default_for_cli();
    let files: Vec<String> = set_file_list(storage.as_ref().unwrap(), filename, directory, None)
        .expect("Failed to determine file list");
    for file in &files {
        // Use storage to read the input document file
        let content_bytes = storage
            .as_ref()
            .expect("Storage must be initialized for this command")
            .get_file(file, None)
            .expect(&format!("Failed to load document file: {}", file));
        let document_string = String::from_utf8(content_bytes)
            .expect(&format!("Document file {} is not valid UTF-8", file));
        let result = document_check_agreement(
            &mut agent,
            &document_string,
            schema.cloned(),
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("reason");
        println!("{}", result);
    }
    Ok(())
}
