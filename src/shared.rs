use crate::agent::agreement::Agreement;
use crate::agent::document::Document;
use crate::agent::AGENT_AGREEMENT_FIELDNAME;
use crate::custom_error::CustomError;

use crate::Agent;
use log::debug;
use log::info;

use std::error::Error;
use std::fs;
use std::path::Path;

pub fn get_file_list(filepath: String) -> Result<Vec<String>, Box<dyn Error>> {
    let mut files: Vec<String> = Vec::new();
    let is_dir = path_is_dir(filepath.clone())?;
    if is_dir {
        for entry in fs::read_dir(filepath).expect("Failed to read directory") {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                    files.push(path.to_str().unwrap().to_string());
                }
            }
        }
    } else {
        files.push(filepath.to_string());
    }
    return Ok(files);
}

pub fn document_create(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
    outputfilename: Option<String>,
    no_save: bool,
    attachments: Option<&String>,
    embed: Option<bool>,
) -> Result<String, Box<dyn Error>> {
    let attachment_links = agent.parse_attachement_arg(attachments);
    if let Some(ref _schema_file) = custom_schema {
        let _ = agent.load_custom_schemas();
    }

    // Removed redundant initial assignment of doc_id

    {
        // Scope to limit the mutable borrow of `agent` within the `create_document_and_load` call
        let create_result =
            agent.create_document_and_load(&document_string, attachment_links.clone(), embed);

        // Handle the result of document creation
        let doc_id = match create_result {
            Ok(doc) => doc.id, // Assign the actual ID if successful
            Err(e) => {
                // Convert the error into a CustomError to avoid lifetime issues with the borrow of `agent`
                return Err(CustomError::from(e.to_string()).into());
            }
        };
    } // End of the scope for mutable borrow of `agent`

    // Ensure `doc_id` is not empty before attempting to save the document
    if doc_id.is_empty() {
        return Err(CustomError::from(
            "Document ID is empty, indicating an error occurred during document creation.",
        )
        .into());
    }

    // Check if the document needs to be saved
    if !no_save {
        // Since `agent` is no longer borrowed, it's safe to call `save_document`
        save_document(agent, doc_id, custom_schema, outputfilename, None, None)
    } else {
        // If no save is needed, return the document ID
        Ok(doc_id)
    }
}

pub fn document_load_and_save(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
    save_filename: Option<String>,
    export_embedded: Option<bool>,
    extract_only: Option<bool>,
    load_only: bool,
) -> Result<String, Box<dyn Error>> {
    if let Some(ref _schema_file) = custom_schema {
        let _ = agent.load_custom_schemas();
    }
    let docresult = agent.load_document(&document_string);
    if !load_only {
        return save_document(
            agent,
            docresult?.getkey(),
            custom_schema,
            save_filename,
            export_embedded,
            extract_only,
        );
    } else {
        return Ok(docresult?.to_string());
    }
}

// Functions removed to clean up the codebase and address compiler warnings

// todo do start and end for task
pub fn document_check_agreement(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
    agreement_fieldname: Option<String>,
) -> Result<String, Box<dyn Error>> {
    if let Some(ref _schema_file) = custom_schema {
        let _ = agent.load_custom_schemas();
    }
    let agreement_fieldname_key = match agreement_fieldname {
        Some(ref key) => key.to_string(),
        _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
    };

    let docresult = agent.load_document(&document_string)?;
    let document_key = docresult.getkey();
    let result = agent.check_agreement(&document_key, Some(agreement_fieldname_key));
    match result {
        Err(err) => Err(format!("{}", err).into()),
        Ok(_) => {
            return Ok(format!(
                "both_signed_document agents requested {:?} unsigned {:?} signed {:?}",
                docresult
                    .agreement_requested_agents(agreement_fieldname.clone())
                    .unwrap(),
                docresult
                    .agreement_unsigned_agents(agreement_fieldname.clone())
                    .unwrap(),
                docresult
                    .agreement_signed_agents(agreement_fieldname)
                    .unwrap()
            ));
        }
    }
}

pub fn document_sign_agreement(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
    save_filename: Option<String>,
    export_embedded: Option<bool>,
    extract_only: Option<bool>,
    load_only: bool,
    agreement_fieldname: Option<String>,
) -> Result<String, Box<dyn Error>> {
    let agreement_fieldname_key = match agreement_fieldname {
        Some(ref key) => key.to_string(),
        _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
    };
    if let Some(ref _schema_file) = custom_schema {
        let _ = agent.load_custom_schemas();
    }
    let docresult = agent.load_document(&document_string)?;
    let document_key = docresult.getkey();

    let signed_document = agent.sign_agreement(&document_key, Some(agreement_fieldname_key))?;
    let _signed_document_key = signed_document.getkey();
    if !load_only {
        return save_document(
            agent,
            signed_document.getkey(),
            custom_schema,
            save_filename,
            export_embedded,
            extract_only,
        );
    } else {
        return Ok(signed_document.value.to_string());
    }
}

pub fn document_add_agreement(
    agent: &mut Agent,
    document_string: &String,
    agentids: Vec<String>,
    custom_schema: Option<String>,
    save_filename: Option<String>,
    question: Option<String>,
    context: Option<String>,
    export_embedded: Option<bool>,
    extract_only: Option<bool>,
    load_only: bool,
    agreement_fieldname: Option<String>,
) -> Result<String, Box<dyn Error>> {
    let _agreement_fieldname_key = match agreement_fieldname {
        Some(ref key) => key.to_string(),
        _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
    };
    if let Some(ref _schema_file) = custom_schema {
        let _ = agent.load_custom_schemas();
    }
    let docresult = agent.load_document(&document_string)?;
    let document_key = docresult.getkey();
    // agent one creates agreement document
    let unsigned_doc = agent.create_agreement(
        &document_key,
        &agentids,
        question.as_ref(),
        context.as_ref(),
        agreement_fieldname,
    )?;

    let _unsigned_doc_key = unsigned_doc.getkey();

    if !load_only {
        return save_document(
            agent,
            unsigned_doc.getkey(),
            custom_schema,
            save_filename,
            export_embedded,
            extract_only,
        );
    } else {
        return Ok(unsigned_doc.value.to_string());
    }
}

// todo make private again
/// helper function
pub fn save_document(
    agent: &mut Agent,
    doc_id: String,
    custom_schema: Option<String>,
    save_filename: Option<String>,
    export_embedded: Option<bool>,
    extract_only: Option<bool>,
) -> Result<String, Box<dyn Error>> {
    let document = agent.get_document(&doc_id)?;
    debug!("document {} validated", doc_id);

    if let Some(schema_file) = custom_schema {
        // todo don't unwrap but warn instead
        let result = agent.validate_document_with_custom_schema(&schema_file, &document.getvalue());
        match result {
            Ok(_) => {
                info!("document specialised schema {} validated", doc_id);
            }
            Err(e) => {
                return Err(format!(
                    "document specialised schema {} validation failed {}",
                    doc_id, e
                )
                .into());
            }
        }
    }
    //after validation do export of contents
    agent.save_document(&doc_id, save_filename, export_embedded, extract_only)?;
    return Ok(format!("saved  {}", doc_id));
}

fn path_is_dir<P: AsRef<Path>>(path: P) -> Result<bool, Box<dyn Error>> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if metadata.is_dir() {
                return Ok(true);
            } else if metadata.is_file() {
                return Ok(false);
            } else {
                return Err(format!("It is neither a file nor a directory.").into());
            }
        }
        Err(e) => Err(format!("path_is_dir Failed to retrieve metadata: {}", e).into()),
    }
}
