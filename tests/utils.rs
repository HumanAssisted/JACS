use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::agent::Agent;
use log::debug;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use std::env;

#[cfg(test)]
pub fn generate_new_docs_with_attachments(save: bool) {
    let mut agent = load_test_agent_one();
    let mut document_string =
        load_local_document(&"examples/raw/embed-xml.json".to_string()).unwrap();
    let mut document = agent
        .create_document_and_load(
            &document_string,
            vec![
                "examples/raw/plants.xml".to_string(),
                "examples/raw/breakfast.xml".to_string(),
            ]
            .into(),
            Some(false),
        )
        .unwrap();
    let mut document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    _ = agent.save_document(&document_key, None, None, None);

    document_string = load_local_document(&"examples/raw/image-embed.json".to_string()).unwrap();
    document = agent
        .create_document_and_load(
            &document_string,
            vec!["examples/raw/mobius.jpeg".to_string()].into(),
            Some(true),
        )
        .unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    if save {
        let export_embedded = true;
        _ = agent.save_document(&document_key, None, Some(export_embedded), None);
    }
}

#[cfg(test)]
pub fn generate_new_docs() {
    static SCHEMA: &str = "examples/documents/my-custom-doctype.schema.json";
    let mut agent = load_test_agent_one();
    let mut document_string =
        load_local_document(&"examples/raw/favorite-fruit.json".to_string()).unwrap();
    let mut document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    let mut document_key = document.getkey();
    println!("document_key {}", document_key);
    // let mut document_ref = agent.get_document(&document_key).unwrap();
    let _ = agent.save_document(&document_key, None, None, None);

    document_string = load_local_document(&"examples/raw/gpt-lsd.json".to_string()).unwrap();
    document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    let _ = agent.save_document(&document_key, None, None, None);

    document_string = load_local_document(&"examples/raw/json-ld.json".to_string()).unwrap();
    document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    _ = agent.save_document(&document_key, None, None, None);
}

#[cfg(test)]
pub fn load_test_agent_one() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid =
        "49c48c7a-db1d-4e8c-9133-4c27f73737b8:06a9a142-ef51-4980-b29a-576ab2b3aadb".to_string();
    let result = agent.load_by_id(Some(agentid), None);
    match result {
        Ok(_) => {
            debug!(
                "AGENT ONE LOADED {} {} ",
                agent.get_id().unwrap(),
                agent.get_version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
        }
    }
    agent
}

#[cfg(test)]
pub fn load_test_agent_two() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let _ = agent.fs_preload_keys(
        &"agent-two.private.pem".to_string(),
        &"agent-two.public.pem".to_string(),
    );
    let result = agent.load_by_id(
        Some(
            "350d80d4-2a81-4c5e-ac40-1acc5c682fae:fd2b2e0a-84db-43da-8f7f-50f80f1a28f1".to_string(),
        ),
        None,
    );
    match result {
        Ok(_) => {
            debug!(
                "AGENT TWO LOADED {} {} ",
                agent.get_id().unwrap(),
                agent.get_version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
        }
    }
    agent
}

#[cfg(test)]
pub fn load_local_document(filepath: &String) -> Result<String, Box<dyn Error>> {
    let current_dir = env::current_dir()?;
    let document_path: PathBuf = current_dir.join(filepath);
    let json_data = fs::read_to_string(document_path);
    match json_data {
        Ok(data) => {
            debug!("testing data {}", data);
            Ok(data.to_string())
        }
        Err(e) => {
            panic!("Failed to find file: {} {}", filepath, e);
        }
    }
}
