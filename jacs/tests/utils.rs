use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::agent::loaders::FileLoader;
use log::debug;
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

pub static TESTFILE_MODIFIED: &str = "tests/fixtures/documents/MODIFIED_f89b737d-9fb6-417e-b4b8-e89150d69624:913ce948-3765-4bd4-9163-ccdbc7e11e8e.json";

pub static DOCTESTFILE: &str = "tests/fixtures/documents/f89b737d-9fb6-417e-b4b8-e89150d69624:913ce948-3765-4bd4-9163-ccdbc7e11e8e.json";
pub static DOCTESTFILECONFIG: &str = "tests/fixtures/documents/f89b737d-9fb6-417e-b4b8-e89150d69624:913ce948-3765-4bd4-9163-ccdbc7e11e8e.json";

pub static AGENTONE: &str =
    "ddf35096-d212-4ca9-a299-feda597d5525:b57d480f-b8d4-46e7-9d7c-942f2b132717";
pub static AGENTTWO: &str =
    "0f6bb6e8-f27c-4cf7-bb2e-01b647860680:a55739af-a3c8-4b4a-9f24-200313ee4229";

#[cfg(test)]
pub fn generate_new_docs_with_attachments(save: bool) {
    let mut agent = load_test_agent_one();
    let mut document_string =
        load_local_document(&"tests/fixtures/raw/embed-xml.json".to_string()).unwrap();
    let mut document = agent
        .create_document_and_load(
            &document_string,
            vec![
                "raw/plants.xml".to_string(),
                "raw/breakfast.xml".to_string(),
            ]
            .into(),
            Some(false),
        )
        .unwrap();
    let mut document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    _ = agent.save_document(&document_key, None, None, None);

    document_string =
        load_local_document(&"tests/fixtures/raw/image-embed.json".to_string()).unwrap();
    document = agent
        .create_document_and_load(
            &document_string,
            vec!["raw/mobius.jpeg".to_string()].into(),
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
    static SCHEMA: &str = "tests/fixtures/raw/custom.schema.json";
    let mut agent = load_test_agent_one();
    let mut document_string =
        load_local_document(&"tests/fixtures/raw/favorite-fruit.json".to_string()).unwrap();
    let mut document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    let mut document_key = document.getkey();
    println!("document_key {}", document_key);
    // let mut document_ref = agent.get_document(&document_key).unwrap();
    let _ = agent.save_document(&document_key, None, None, None);

    document_string = load_local_document(&"tests/fixtures/raw/gpt-lsd.json".to_string()).unwrap();
    document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    let _ = agent.save_document(&document_key, None, None, None);

    document_string = load_local_document(&"tests/fixtures/raw/json-ld.json".to_string()).unwrap();
    document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    _ = agent.save_document(&document_key, None, None, None);
}

fn set_min_test_env_vars() {
    unsafe {
        env::set_var("JACS_PRIVATE_KEY_PASSWORD", "secretpassord");
    }
}

#[cfg(test)]
pub fn load_test_agent_one() -> Agent {
    set_min_test_env_vars();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid = AGENTONE.to_string();
    let result = agent.load_by_id(agentid);
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
    set_min_test_env_vars();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    debug!("load_test_agent_two: function called");
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    debug!("load_test_agent_two: agent instantiated");

    // let _ = agent.fs_preload_keys(
    //     &"agent-two.private.pem".to_string(),
    //     &"agent-two.public.pem".to_string(),
    //     Some("RSA-PSS".to_string()),
    // );

    // created agent two with agent one keys
    let _ = agent.fs_preload_keys(
        &"agent-one.private.pem".to_string(),
        &"agent-one.public.pem".to_string(),
        Some("RSA-PSS".to_string()),
    );

    debug!("load_test_agent_two: keys preloaded");
    let result = agent.load_by_id(AGENTTWO.to_string());
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

#[cfg(test)]
pub fn set_test_env_vars() {
    unsafe {
        env::set_var("JACS_USE_SECURITY", "false");
        env::set_var("JACS_DATA_DIRECTORY", ".");
        env::set_var("JACS_KEY_DIRECTORY", ".");
        env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "rsa_pss_private.pem");
        env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "rsa_pss_public.pem");
        env::set_var("JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");
        env::set_var("JACS_PRIVATE_KEY_PASSWORD", "test_password");
        env::set_var(
            "JACS_AGENT_ID_AND_VERSION",
            "123e4567-e89b-12d3-a456-426614174000:123e4567-e89b-12d3-a456-426614174001",
        );
    }
}

#[cfg(test)]
pub fn clear_test_env_vars() {
    unsafe {
        env::remove_var("JACS_USE_SECURITY");
        env::remove_var("JACS_DATA_DIRECTORY");
        env::remove_var("JACS_KEY_DIRECTORY");
        env::remove_var("JACS_AGENT_PRIVATE_KEY_FILENAME");
        env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
        env::remove_var("JACS_AGENT_KEY_ALGORITHM");
        env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
        env::remove_var("JACS_AGENT_ID_AND_VERSION");
    }
}
