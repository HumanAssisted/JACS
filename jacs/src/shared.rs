use crate::Agent;
use crate::agent::AGENT_AGREEMENT_FIELDNAME;
use crate::agent::TASK_END_AGREEMENT_FIELDNAME;
use crate::agent::TASK_START_AGREEMENT_FIELDNAME;
use crate::agent::agreement::Agreement;
use crate::agent::document::DocumentTraits;
use crate::agent::document::JACSDocument;
use log::debug;
use log::info;
use std::error::Error;

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
    if let Some(ref schema_file) = custom_schema {
        let schemas = [schema_file.clone()];
        let _ = agent.load_custom_schemas(&schemas);
    }

    // let loading_filename_string = loading_filename.to_string();
    let export_embedded = None;
    let extract_only = None;
    let docresult =
        agent.create_document_and_load(&document_string, attachment_links.clone(), embed);
    if !no_save {
        return save_document(
            agent,
            docresult,
            custom_schema,
            outputfilename,
            export_embedded,
            extract_only,
        );
    } else {
        return Ok(docresult?.value.to_string());
    }
}

// pub fn validate_document_with_custom_schema

// pub fn save_document

pub fn document_load_and_save(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
    save_filename: Option<String>,
    export_embedded: Option<bool>,
    extract_only: Option<bool>,
    load_only: bool,
) -> Result<String, Box<dyn Error>> {
    if let Some(ref schema_file) = custom_schema {
        let schemas = [schema_file.clone()];
        agent.load_custom_schemas(&schemas);
    }
    let docresult = agent.load_document(&document_string);
    if !load_only {
        return save_document(
            agent,
            docresult,
            custom_schema,
            save_filename,
            export_embedded,
            extract_only,
        );
    } else {
        return Ok(docresult?.to_string());
    }
}

fn create_task_start(
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
) -> Result<String, Box<dyn Error>> {
    let _ = agent.schema.validate_task(document_string)?;

    return document_add_agreement(
        agent,
        document_string,
        agentids,
        custom_schema,
        save_filename,
        question,
        context,
        export_embedded,
        extract_only,
        load_only,
        Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    );
}

fn create_task_complete(
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
) -> Result<String, Box<dyn Error>> {
    let _ = agent.schema.validate_task(document_string)?;
    return document_add_agreement(
        agent,
        document_string,
        agentids,
        custom_schema,
        save_filename,
        question,
        context,
        export_embedded,
        extract_only,
        load_only,
        Some(TASK_END_AGREEMENT_FIELDNAME.to_string()),
    );
}

fn agree_task_start(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
    save_filename: Option<String>,
    export_embedded: Option<bool>,
    extract_only: Option<bool>,
    load_only: bool,
) -> Result<String, Box<dyn Error>> {
    let _ = agent.schema.validate_task(document_string)?;
    return document_sign_agreement(
        agent,
        document_string,
        custom_schema,
        save_filename,
        export_embedded,
        extract_only,
        load_only,
        Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    );
}

fn agree_task_complete(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
    save_filename: Option<String>,
    export_embedded: Option<bool>,
    extract_only: Option<bool>,
    load_only: bool,
) -> Result<String, Box<dyn Error>> {
    let _ = agent.schema.validate_task(document_string)?;
    return document_sign_agreement(
        agent,
        document_string,
        custom_schema,
        save_filename,
        export_embedded,
        extract_only,
        load_only,
        Some(TASK_END_AGREEMENT_FIELDNAME.to_string()),
    );
}

fn check_task_complete(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
) -> Result<String, Box<dyn Error>> {
    let _ = agent.schema.validate_task(document_string)?;
    return document_check_agreement(
        agent,
        document_string,
        custom_schema,
        Some(TASK_END_AGREEMENT_FIELDNAME.to_string()),
    );
}

fn check_task_start(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
) -> Result<String, Box<dyn Error>> {
    let _ = agent.schema.validate_task(document_string)?;
    return document_check_agreement(
        agent,
        document_string,
        custom_schema,
        Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    );
}

// todo do start and end for task
pub fn document_check_agreement(
    agent: &mut Agent,
    document_string: &String,
    custom_schema: Option<String>,
    agreement_fieldname: Option<String>,
) -> Result<String, Box<dyn Error>> {
    if let Some(ref schema_file) = custom_schema {
        let schemas = [schema_file.clone()];
        agent.load_custom_schemas(&schemas);
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
    if let Some(ref schema_file) = custom_schema {
        let schemas = [schema_file.clone()];
        agent.load_custom_schemas(&schemas);
    }
    let docresult = agent.load_document(&document_string)?;
    let document_key = docresult.getkey();

    let signed_document = agent.sign_agreement(&document_key, Some(agreement_fieldname_key))?;
    let signed_document_key = signed_document.getkey();
    if !load_only {
        return save_document(
            agent,
            Ok(signed_document),
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
    let agreement_fieldname_key = match agreement_fieldname {
        Some(ref key) => key.to_string(),
        _ => AGENT_AGREEMENT_FIELDNAME.to_string(),
    };
    if let Some(ref schema_file) = custom_schema {
        let schemas = [schema_file.clone()];
        agent.load_custom_schemas(&schemas);
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
            Ok(unsigned_doc),
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
    docresult: Result<JACSDocument, Box<dyn Error>>,
    custom_schema: Option<String>,
    save_filename: Option<String>,
    export_embedded: Option<bool>,
    extract_only: Option<bool>,
) -> Result<String, Box<dyn Error>> {
    match docresult {
        Ok(ref document) => {
            let document_key = document.getkey();
            debug!("document {} validated", document_key);

            if let Some(schema_file) = custom_schema {
                // todo don't unwrap but warn instead
                let document_key = document.getkey();
                let result =
                    agent.validate_document_with_custom_schema(&schema_file, &document.getvalue());
                match result {
                    Ok(_) => {
                        info!("document specialised schema {} validated", document_key);
                    }
                    Err(e) => {
                        return Err(format!(
                            "document specialised schema {} validation failed {}",
                            document_key, e
                        )
                        .into());
                    }
                }
            }
            //after validation do export of contents
            agent.save_document(&document_key, save_filename, export_embedded, extract_only)?;
            return Ok(format!("saved  {}", document_key));
        }
        Err(ref e) => {
            return Err(format!("document  validation failed {}", e).into());
        }
    }
}
