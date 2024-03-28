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
pub fn generate_new_docs() {
    static SCHEMA: &str = "examples/documents/my-custom-doctype.schema.json";
    let mut agent = load_test_agent_one();
    let mut document_string =
        load_local_document(&"examples/raw/favorite-fruit.json".to_string()).unwrap();
    let mut document = agent.create_document_and_load(&document_string).unwrap();
    let mut document_key = document.getkey();
    println!("document_key {}", document_key);
    let mut document_ref = agent.get_document(&document_key).unwrap();
    let _ = agent.save_document(&document_key);

    document_string = load_local_document(&"examples/raw/gpt-lsd.json".to_string()).unwrap();
    document = agent.create_document_and_load(&document_string).unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    document_ref = agent.get_document(&document_key).unwrap();
    let _ = agent.save_document(&document_key);

    document_string = load_local_document(&"examples/raw/json-ld.json".to_string()).unwrap();
    document = agent.create_document_and_load(&document_string).unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    document_ref = agent.get_document(&document_key).unwrap();
    _ = agent.save_document(&document_key);
}

#[cfg(test)]
pub fn load_test_agent_one() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid =
        "fe00bb15-8c7f-43ac-9413-5a7bd5bb039d:1f639f69-b3a7-45d5-b814-bc7b91fb3b97".to_string();
    let result = agent.load_by_id(agentid, None);
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
        "396155ad-484a-4659-a4e7-341ef52aa63d:a3efb91b-1245-4852-9934-fde8a2cfe6d8".to_string(),
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
pub fn set_test_env_vars() {
    // to get reliable test outputs, use consistent keys
    env::set_var("JACS_DATA_DIRECTORY", "./examples/");
    env::set_var("JACS_KEY_DIRECTORY", "./examples/keys/");
    env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "agent-one.private.pem");
    env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "agent-one.public.pem");
    env::set_var("JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");
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
