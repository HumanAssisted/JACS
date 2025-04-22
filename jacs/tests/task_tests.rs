use jacs::agent::Agent;
use jacs::agent::TASK_END_AGREEMENT_FIELDNAME;
use jacs::agent::TASK_START_AGREEMENT_FIELDNAME;
use jacs::agent::agreement::Agreement;
use jacs::schema::action_crud::create_minimal_action;
use jacs::schema::message_crud::create_message;
use jacs::schema::task_crud::{add_action_to_task, create_minimal_task};
use serde_json::json;

use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use serde_json::Value;
mod utils;
use utils::DOCTESTFILE;
use utils::{load_local_document, load_test_agent_one, load_test_agent_two};
// use color_eyre::eyre::Result;
static SCHEMA: &str = "raw/custom.schema.json";
use chrono::{Duration, Utc};

#[test]
fn test_hai_fields_custom_schema_and_custom_document() {
    // cargo test   --test task_tests test_hai_fields_custom_schema_and_custom_document -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent
        .load_custom_schemas(&schemas)
        .expect("Failed to load custom schemas");
    let document_string = load_local_document(&DOCTESTFILE.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    println!("loaded valid {}", document_key);
    let document_copy = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document_copy.getvalue())
        .unwrap();

    let value = document_copy.getvalue();
    println!("found schema {}", value["$schema"]);
    print_fields(&agent, value.clone())
}

#[test]
fn test_create_task_with_actions() {
    // cargo test   --test task_tests test_create_task_with_actions -- --nocapture
    let mut agent = load_test_agent_one();
    let mut agent_two = load_test_agent_two();
    let mut actions: Vec<Value> = Vec::new();
    let start_in_a_week = Utc::now() + Duration::weeks(1);
    let action = create_minimal_action(
        &"go to mars".to_string(),
        &" how to go to mars".to_string(),
        None,
        None,
    );
    actions.push(action);
    let mut task =
        create_minimal_task(Some(actions), None, Some(start_in_a_week), None).expect("reason");
    let action = create_minimal_action(
        &"terraform mars".to_string(),
        &" how to terraform mars".to_string(),
        None,
        None,
    );
    add_action_to_task(&mut task, action).expect("reason");

    //create jacs task
    let task_doc = agent
        .create_document_and_load(&task.to_string(), None, None)
        .unwrap();
    let task_doc_key = task_doc.getkey();

    let attachments = vec!["raw/mobius.jpeg".to_string()];
    // create a message
    let content = json!("lets goooo");
    let mut to: Vec<String> = Vec::new();
    let mut from: Vec<String> = Vec::new();
    to.push("me@hai.ai".to_string());
    from.push(agent.get_id().expect("REASON"));
    let message = create_message(
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
    let mut agentids: Vec<String> = Vec::new();
    agentids.push(agent.get_id().expect("REASON"));
    agentids.push(agent_two.get_id().expect("REASON"));

    let unsigned_doc = agent
        .create_agreement(
            &task_doc_key,
            &agentids,
            Some(&"Is this done?".to_string()),
            Some(&"want to know if this is done".to_string()),
            Some(TASK_END_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("create_agreement");

    let unsigned_doc2 = agent
        .create_agreement(
            &unsigned_doc.getkey(),
            &agentids,
            Some(&"can we start?".to_string()),
            Some(&"want to know if this is started".to_string()),
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

    match result {
        Err(err) => {
            println!(
                "agent {} check failed {}",
                TASK_START_AGREEMENT_FIELDNAME, err
            );
            assert!(false)
        }
        Ok(_) => assert!(true),
    }
}

fn print_fields(agent: &Agent, value: Value) {
    let extracted_fields_result = agent.schema.extract_hai_fields(&value, "base");
    match extracted_fields_result {
        Err(error) => {
            println!(" ERROR {}", error.to_string());
            assert!(false);
        }
        Ok(extracted_fields) => println!(
            "BASE {}\n {}",
            get_field_count(&extracted_fields),
            serde_json::to_string_pretty(&extracted_fields).unwrap()
        ),
    }

    let extracted_fields_result = agent.schema.extract_hai_fields(&value, "meta");
    match extracted_fields_result {
        Err(error) => {
            println!(" ERROR {}", error.to_string());
            assert!(false);
        }
        Ok(extracted_fields) => println!(
            "meta  {}\n{}",
            get_field_count(&extracted_fields),
            serde_json::to_string_pretty(&extracted_fields).unwrap()
        ),
    }

    let extracted_fields_result = agent.schema.extract_hai_fields(&value, "agent");
    match extracted_fields_result {
        Err(error) => {
            println!(" ERROR {}", error.to_string());
            assert!(false);
        }
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
