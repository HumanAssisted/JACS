use jacs::agent::Agent;
use jacs::agent::TASK_END_AGREEMENT_FIELDNAME;
use jacs::agent::TASK_START_AGREEMENT_FIELDNAME;
use jacs::agent::agreement::Agreement;
use jacs::schema::action_crud::create_minimal_action;
use jacs::schema::message_crud::create_message;
use jacs::schema::task_crud::{add_action_to_task, create_minimal_task};
use serde_json::json;
use serial_test::serial;

use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::hash::hash_public_key;
use serde_json::Value;
mod utils;
use utils::{
    create_owned_config_fixture_document, load_test_agent_one_ed25519, load_test_agent_two_ed25519,
    raw_fixture,
};
// use color_eyre::eyre::Result;
use chrono::{Duration, Utc};

#[test]
#[serial(jacs_env)]
fn test_hai_fields_custom_schema_and_custom_document() {
    // cargo test   --test task_tests test_hai_fields_custom_schema_and_custom_document -- --nocapture
    let mut agent = load_test_agent_one_ed25519();
    let schema_path = raw_fixture("custom.schema.json")
        .to_string_lossy()
        .to_string();
    let schemas = [schema_path.clone()];
    agent
        .load_custom_schemas(&schemas)
        .expect("Failed to load custom schemas");
    let document_key = create_owned_config_fixture_document(&mut agent);
    println!("loaded valid {}", document_key);
    let document_copy = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&schema_path, document_copy.getvalue())
        .unwrap();

    let value = document_copy.getvalue();
    println!("found schema {}", value["$schema"]);
    print_fields(&agent, value.clone())
}

#[test]
#[serial(jacs_env)]
fn test_create_task_with_actions() {
    // cargo test   --test task_tests test_create_task_with_actions -- --nocapture
    let mut agent = load_test_agent_one_ed25519();
    let mut agent_two = load_test_agent_two_ed25519();
    let start_in_a_week = Utc::now() + Duration::weeks(1);
    let action = create_minimal_action("go to mars", " how to go to mars", None, None);
    let actions: Vec<Value> = vec![action];
    let mut task =
        create_minimal_task(Some(actions), None, Some(start_in_a_week), None).expect("reason");
    let action = create_minimal_action("terraform mars", " how to terraform mars", None, None);
    add_action_to_task(&mut task, action).expect("reason");

    //create jacs task
    let task_doc = agent
        .create_document_and_load(&task.to_string(), None, None)
        .unwrap();
    let task_doc_key = task_doc.getkey();

    let attachments = vec![raw_fixture("mobius.jpeg").to_string_lossy().to_string()];
    // create a message
    let content = json!("lets goooo");
    let to: Vec<String> = vec!["me@hai.ai".to_string()];
    let from: Vec<String> = vec![agent.get_id().expect("REASON")];
    let _message = create_message(
        &mut agent,
        content,
        to,
        from,
        Some(false),
        Some(attachments),
        Some(false),
    )
    .expect("REASON");

    // add agreement to completionAgreement
    let agentids: Vec<String> = vec![
        agent.get_id().expect("REASON"),
        agent_two.get_id().expect("REASON"),
    ];

    let agent_one_public_key = agent.get_public_key().unwrap();
    let agent_one_public_key_hash = hash_public_key(&agent_one_public_key);
    let agent_two_public_key = agent_two.get_public_key().unwrap();
    let agent_two_public_key_hash = hash_public_key(&agent_two_public_key);
    for receiver in [&agent, &agent_two] {
        receiver
            .fs_save_remote_public_key(
                &agent_one_public_key_hash,
                &agent_one_public_key,
                b"ring-Ed25519",
            )
            .expect("cache agent one public key");
        receiver
            .fs_save_remote_public_key(
                &agent_two_public_key_hash,
                &agent_two_public_key,
                b"ring-Ed25519",
            )
            .expect("cache agent two public key");
    }

    let unsigned_doc = agent
        .create_agreement(
            &task_doc_key,
            &agentids,
            Some("Is this done?"),
            Some("want to know if this is done"),
            Some(TASK_END_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("create_agreement");

    let unsigned_doc2 = agent
        .create_agreement(
            &unsigned_doc.getkey(),
            &agentids,
            Some("can we start?"),
            Some("want to know if this is started"),
            Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("create_agreement");

    // agent one  tries and fails to creates agreement document
    // sign completion argreement

    let signed_document = agent
        .sign_agreement(
            &unsigned_doc2.getkey(),
            Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("signed_document ");
    let signed_document_key = signed_document.getkey();
    let signed_document_string =
        serde_json::to_string_pretty(&signed_document.value).expect("pretty print");

    let _ = agent_two.load_document(&signed_document_string).unwrap();
    let both_signed_document = agent_two
        .sign_agreement(
            &signed_document_key,
            Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("signed_document ");

    // print_fields(&agent, both_signed_document.value.clone());

    let (question, context) = agent_two
        .agreement_get_question_and_context(
            &both_signed_document.getkey(),
            Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
        )
        .unwrap();
    println!(" question {}, context {}", question, context);
    println!(
        " schema {}, short {}",
        both_signed_document.getschema().expect("long schema"),
        both_signed_document.getshortschema().expect("short schema")
    );
    let result = agent_two.check_agreement(
        &both_signed_document.getkey(),
        Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    );

    if let Err(err) = result {
        panic!(
            "agent {} check failed: {}",
            TASK_START_AGREEMENT_FIELDNAME, err
        );
    }
}

fn print_fields(agent: &Agent, value: Value) {
    let extracted_fields_result = agent.schema.extract_hai_fields(&value, "base");
    match extracted_fields_result {
        Err(error) => panic!("extract_hai_fields base failed: {}", error),
        Ok(extracted_fields) => println!(
            "BASE {}\n {}",
            get_field_count(&extracted_fields),
            serde_json::to_string_pretty(&extracted_fields).unwrap()
        ),
    }

    let extracted_fields_result = agent.schema.extract_hai_fields(&value, "meta");
    match extracted_fields_result {
        Err(error) => panic!("extract_hai_fields meta failed: {}", error),
        Ok(extracted_fields) => println!(
            "meta  {}\n{}",
            get_field_count(&extracted_fields),
            serde_json::to_string_pretty(&extracted_fields).unwrap()
        ),
    }

    let extracted_fields_result = agent.schema.extract_hai_fields(&value, "agent");
    match extracted_fields_result {
        Err(error) => panic!("extract_hai_fields agent failed: {}", error),
        Ok(extracted_fields) => println!(
            "Agent {}\n{}",
            get_field_count(&extracted_fields),
            serde_json::to_string_pretty(&extracted_fields).unwrap()
        ),
    }
}

fn get_field_count(value: &Value) -> usize {
    match value.as_object() {
        Some(obj) => obj.len(), // If it's an object, return the number of key-value pairs
        None => 0,              // If it's not an object, return 0
    }
}
