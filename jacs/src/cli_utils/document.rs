use crate::agent::AGENT_AGREEMENT_FIELDNAME;
use crate::agent::Agent;
use crate::agent::document::DocumentTraits;
use crate::cli_utils::get_storage_default_for_cli;
use crate::cli_utils::set_file_list;
use crate::shared::document_add_agreement;
use crate::shared::document_check_agreement;
use crate::shared::document_create;
use crate::shared::document_load_and_save;
use crate::shared::document_sign_agreement;
use std::error::Error;
use std::process;

#[allow(clippy::too_many_arguments)]
pub fn create_documents(
    agent: &mut Agent,
    filename: Option<&String>,
    directory: Option<&String>,
    outputfilename: Option<&String>,
    attachments: Option<&str>,
    embed: Option<bool>,
    no_save: bool,
    schema: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let storage = get_storage_default_for_cli();
    if outputfilename.is_some() && directory.is_some() {
        eprintln!(
            "Error: if there is a directory you can't name the file the same for multiple files."
        );
        process::exit(1);
    }

    // Allow attachments-only for create command
    if filename.is_none() && directory.is_none() && attachments.is_none() {
        return Err(
            "You must specify either a filename (-f), directory (-d), or attachments (--attach)."
                .into(),
        );
    }

    // Use updated set_file_list with storage
    let files: Vec<String> =
        set_file_list(storage.as_ref().unwrap(), filename, directory, attachments)
            .expect("Failed to determine file list");

    // Handle attachment-only case: if files is empty but attachments provided,
    // we need to run the loop once with an empty file to create a document
    let files_to_process = if files.is_empty() && attachments.is_some() {
        println!("DEBUG: Attachment-only mode detected, creating empty document");
        vec![String::new()] // Empty string will trigger "{}" document creation
    } else {
        println!("DEBUG: Using files list: {:?}", files);
        files
    };

    println!("DEBUG: Processing {} files", files_to_process.len());
    // iterate over filenames
    for file in &files_to_process {
        println!("DEBUG: Processing file: '{}'", file);
        let document_string: String =
            if filename.is_none() && directory.is_none() && attachments.is_some() {
                println!("DEBUG: Creating empty document string");
                "{}".to_string()
            } else if !file.is_empty() {
                println!("DEBUG: Reading document file: {}", file);
                // Use storage to read the input document file
                let content_bytes = storage
                    .as_ref()
                    .expect("Storage must be initialized for this command")
                    .get_file(file, None)
                    .unwrap_or_else(|_| panic!("Failed to load document file: {}", file));
                String::from_utf8(content_bytes)
                    .unwrap_or_else(|_| panic!("Document file {} is not valid UTF-8", file))
            } else {
                eprintln!("Warning: Empty file path encountered in loop.");
                "{}".to_string()
            };
        println!("DEBUG: Document string: {}", document_string);
        println!(
            "DEBUG: Calling document_create with attachments: {:?}",
            attachments
        );
        let result = document_create(
            agent,
            &document_string,
            schema.cloned(),
            outputfilename.cloned(),
            no_save,
            attachments,
            embed,
        )
        .expect("document_create");
        println!(
            "DEBUG: document_create succeeded, result length: {}",
            result.len()
        );
        if no_save {
            println!("{}", result);
        } else {
            println!("DEBUG: Document saved (no_save=false)");
        }
    } // end iteration

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn update_documents(
    agent: &mut Agent,
    new_filename: &String,
    original_filename: &String,
    outputfilename: Option<&String>,
    attachment_links: Option<Vec<String>>,
    embed: Option<bool>,
    no_save: bool,
    schema: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let storage = get_storage_default_for_cli();
    if let Some(schema_file) = schema {
        // Use storage to read the schema file
        let schema_bytes = storage
            .as_ref()
            .expect("Storage must be initialized for this command")
            .get_file(schema_file, None)
            .unwrap_or_else(|_| panic!("Failed to load schema file: {}", schema_file));
        let _schemastring = String::from_utf8(schema_bytes)
            .unwrap_or_else(|_| panic!("Schema file {} is not valid UTF-8", schema_file));
        let schemas = [schema_file.clone()]; // Still need the path string for agent
        agent.load_custom_schemas(&schemas)?;
    }

    // Use storage to read the document files
    let new_doc_bytes = storage
        .as_ref()
        .expect("Storage must be initialized for this command")
        .get_file(new_filename, None)
        .unwrap_or_else(|_| panic!("Failed to load new document file: {}", new_filename));
    let new_document_string = String::from_utf8(new_doc_bytes)
        .unwrap_or_else(|_| panic!("New document file {} is not valid UTF-8", new_filename));

    let original_doc_bytes = storage
        .as_ref()
        .expect("Storage must be initialized for this command")
        .get_file(original_filename, None)
        .unwrap_or_else(|_| {
            panic!(
                "Failed to load original document file: {}",
                original_filename
            )
        });
    let original_document_string = String::from_utf8(original_doc_bytes).unwrap_or_else(|_| {
        panic!(
            "Original document file {} is not valid UTF-8",
            original_filename
        )
    });

    let original_doc = agent
        .load_document(&original_document_string)
        .expect("document parse of original");
    let original_doc_key = original_doc.getkey();
    let updated_document = agent
        .update_document(
            &original_doc_key,
            &new_document_string,
            attachment_links.clone(),
            embed,
        )
        .expect("update document");

    let new_document_key = updated_document.getkey();
    let new_document_filename = format!("{}.json", new_document_key.clone());

    let intermediate_filename = match outputfilename {
        Some(filename) => filename,
        None => &new_document_filename,
    };

    if let Some(schema_file) = schema {
        //let document_ref = agent.get_document(&document_key).unwrap();

        let validate_result =
            agent.validate_document_with_custom_schema(schema_file, updated_document.getvalue());
        match validate_result {
            Ok(_doc) => {
                println!("document specialised schema {} validated", new_document_key);
            }
            Err(e) => {
                eprintln!(
                    "document specialised schema {} validation failed {}",
                    new_document_key, e
                );
            }
        }
    }

    if no_save {
        println!("{}", &updated_document.getvalue());
    } else {
        agent
            .save_document(
                &new_document_key,
                intermediate_filename.to_string().into(),
                None,
                None,
            )
            .expect("save document");
        println!("created doc {}", intermediate_filename);
    }
    Ok(())
}

pub fn extract_documents(
    agent: &mut Agent,
    schema: Option<&String>,
    filename: Option<&String>,
    directory: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let storage = get_storage_default_for_cli();
    let files: Vec<String> = set_file_list(storage.as_ref().unwrap(), filename, directory, None)
        .expect("Failed to determine file list");
    let load_only = false;
    for file in &files {
        // Use storage to read the input document file
        let content_bytes = storage
            .as_ref()
            .expect("Storage must be initialized for this command")
            .get_file(file, None)
            .unwrap_or_else(|_| panic!("Failed to load document file: {}", file));
        let document_string = String::from_utf8(content_bytes)
            .unwrap_or_else(|_| panic!("Document file {} is not valid UTF-8", file));
        let result = document_load_and_save(
            agent,
            &document_string,
            schema.cloned(),
            None,
            Some(true),
            Some(true),
            load_only,
        )
        .expect("reason");
        println!("{}", result);
    }

    Ok(())
}
pub fn verify_documents(
    agent: &mut Agent,
    schema: Option<&String>,
    filename: Option<&String>,
    directory: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let storage = get_storage_default_for_cli();
    let files: Vec<String> = set_file_list(storage.as_ref().unwrap(), filename, directory, None)
        .expect("Failed to determine file list");
    for file in &files {
        let load_only = true;
        // Use storage to read the input document file
        let content_bytes = storage
            .as_ref()
            .expect("Storage must be initialized for this command")
            .get_file(file, None)
            .unwrap_or_else(|_| panic!("Failed to load document file: {}", file));
        let document_string = String::from_utf8(content_bytes)
            .unwrap_or_else(|_| panic!("Document file {} is not valid UTF-8", file));
        let result = document_load_and_save(
            agent,
            &document_string,
            schema.cloned(),
            None,
            None,
            None,
            load_only,
        )
        .expect("reason");
        println!("{}", result);
    }
    Ok(())
}

pub fn sign_documents(
    agent: &mut Agent,
    schema: Option<&String>,
    filename: Option<&String>,
    directory: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let storage = get_storage_default_for_cli();
    let files: Vec<String> = set_file_list(storage.as_ref().unwrap(), filename, directory, None)
        .expect("Failed to determine file list");
    let no_save = false;
    for file in &files {
        // Use storage to read the input document file
        let content_bytes = storage
            .as_ref()
            .expect("Storage must be initialized for this command")
            .get_file(file, None)
            .unwrap_or_else(|_| panic!("Failed to load document file: {}", file));
        let document_string = String::from_utf8(content_bytes)
            .unwrap_or_else(|_| panic!("Document file {} is not valid UTF-8", file));
        let result = document_sign_agreement(
            agent,
            &document_string,
            schema.cloned(),
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

pub fn create_agreement(
    agent: &mut Agent,
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
            .unwrap_or_else(|_| panic!("Failed to load document file: {}", file));
        let document_string = String::from_utf8(content_bytes)
            .unwrap_or_else(|_| panic!("Document file {} is not valid UTF-8", file));
        let result = document_add_agreement(
            agent,
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
    agent: &mut Agent,
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
            .unwrap_or_else(|_| panic!("Failed to load document file: {}", file));
        let document_string = String::from_utf8(content_bytes)
            .unwrap_or_else(|_| panic!("Document file {} is not valid UTF-8", file));
        let result = document_check_agreement(
            agent,
            &document_string,
            schema.cloned(),
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("reason");
        println!("{}", result);
    }
    Ok(())
}
