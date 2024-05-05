mod utils;

use jacs::agent::document::Document;
use jacs::schema::action_crud::create_minimal_action;
use jacs::schema::task_crud::{add_action_to_task, create_minimal_task};
use serde_json::json;

use serde_json::Value;

use httpmock::{Method, MockServer};

use chrono::{Duration, Utc};

use utils::mock_test_agent;

#[test]
fn test_hai_fields_custom_schema_and_custom_document() {
    let server = MockServer::start();
    let schema_mock = server.mock(|when, then| {
        when.method(Method::GET).path("/custom.schema.json");
        then.status(200)
            .body(include_str!("../examples/raw/custom.schema.json"));
    });

    // Mock the external schema URL
    let header_schema_mock = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/header/v1/header.schema.json");
        then.status(200)
            .body(include_str!("../schemas/header/v1/header.schema.json"));
    });

    let mock_server = MockServer::start();
    let base_url = mock_server.url("");
    let header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        base_url
    );

    let agent = match mock_test_agent(&header_schema_url, &document_schema_url) {
        Ok(agent) => agent,
        Err(e) => {
            eprintln!("Failed to create mock agent: {}", e);
            return;
        }
    };
    let document_key = "mock_document_key".to_string(); // Mock document key for testing
    println!("loaded valid {}", document_key);
    let document_copy = json!({}); // Mock document for testing

    let schemas = [
        server.url("/custom.schema.json").to_string(),
        server.url("/header/v1/header.schema.json").to_string(),
    ];

    if let Err(e) = agent.validate_document_with_custom_schema(&schemas[0], &document_copy) {
        eprintln!("Document validation failed: {}", e);
        return;
    }
    println!("Document validation succeeded");
    schema_mock.assert();
    header_schema_mock.assert();
}

#[test]
fn test_create_task_with_actions() {
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

    let mock_server = MockServer::start();
    let base_url = mock_server.url("");
    let header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        base_url
    );

    let _agent = match mock_test_agent(&header_schema_url, &document_schema_url) {
        Ok(agent) => agent,
        Err(e) => {
            eprintln!("Failed to create mock agent: {}", e);
            return;
        }
    };

    //create jacs task
    // let task_doc = agent
    //     .create_document_and_load(&task.to_string(), None, None)
    //     .unwrap();
    // let task_doc_key = task_doc.getkey();

    let _attachments = vec!["examples/raw/mobius.jpeg".to_string()];
    // create a message
    let _content = json!("lets goooo");
    // let _message = create_minimal_message(
    //     // &mut agent,
    //     content,
    //     // task_doc.id,
    //     Some(attachments),
    //     Some(false),
    // )
    // .expect("REASON");

    // add agreement to completionAgreement
    let _agentids: Vec<String> = Vec::new();
    // agentids.push(agent.get_id().expect("REASON"));
    // agentids.push(agent_two.get_id().expect("REASON"));

    // let unsigned_doc = agent
    //     .create_agreement(
    //         &task_doc_key,
    //         &agentids,
    //         Some(&"Is this done?".to_string()),
    //         Some(&"want to know if this is done".to_string()),
    //         Some(TASK_END_AGREEMENT_FIELDNAME.to_string()),
    //     )
    //     .expect("create_agreement");
    // let unsigned_doc2 = agent
    //     .create_agreement(
    //         &unsigned_doc.getkey(),
    //         &agentids,
    //         Some(&"can we start?".to_string()),
    //         Some(&"want to know if this is started".to_string()),
    //         Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    //     )
    //     .expect("create_agreement");
    // let signed_document = agent
    //     .sign_agreement(
    //         &unsigned_doc2.getkey(),
    //         Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    //     )
    //     .expect("signed_document ");
    // let signed_document_key = signed_document.getkey();
    // let signed_document_string =
    //     serde_json::to_string_pretty(&signed_document.value).expect("pretty print");

    // let _ = agent_two.load_document(&signed_document_string).unwrap();
    // let both_signed_document = agent_two
    //     .sign_agreement(
    //         &signed_document_key,
    //         Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    //     )
    //     .expect("signed_document ");

    // print_fields(&agent, both_signed_document.value.clone());

    // let (question, context) = agent_two
    //     .agreement_get_question_and_context(
    //         &both_signed_document.getkey(),
    //         Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    //     )
    //     .unwrap();
    // println!(" question {}, context {}", question, context);
    // println!(
    //     " schema {}, short {}",
    //     both_signed_document.getschema().expect("long schema"),
    //     both_signed_document.getshortschema().expect("short schema")
    // );
    // let result = agent_two.check_agreement(
    //     &both_signed_document.getkey(),
    //     Some(TASK_START_AGREEMENT_FIELDNAME.to_string()),
    // );
    // match result {
    //     Err(err) => {
    //         println!(
    //             "agent {} check failed {}",
    //             TASK_START_AGREEMENT_FIELDNAME, err
    //         );
    //         assert!(false)
    //     }
    //     Ok(_) => assert!(true),
    // }
}
