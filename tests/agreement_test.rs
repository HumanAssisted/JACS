use jacs::agent::agreement::Agreement;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::agent::AGENT_AGREEMENT_FIELDNAME;
use jacs::crypt::KeyManager;
use secrecy::ExposeSecret;
mod utils;

use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use utils::{load_local_document, load_test_agent_one, load_test_agent_two};

static DOCID: &str = "3f2b7816-2200-4b66-b13e-d9522a05ceb8:40a60489-45d9-4e46-9b25-870d0c3ff9a6";

#[test]
fn test_create_agreement() {
    let DOCUMENT_PATH = format!("examples/documents/{}.json", DOCID);
    // cargo test   --test agreement_test -- --nocapture test_create_agreement
    let mut agent = load_test_agent_one();
    let mut agent_two = load_test_agent_two();
    let mut agentids: Vec<String> = Vec::new();
    agentids.push(agent.get_id().expect("REASON"));
    agentids.push(agent_two.get_id().expect("REASON"));

    let document_string = load_local_document(&DOCUMENT_PATH).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    // agent one creates agreement document
    let unsigned_doc = agent
        .create_agreement(
            &document_key,
            &agentids,
            None,
            None,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("create_agreement");

    println!("{}", unsigned_doc.to_string());

    // agent one  tries and fails to creates agreement document
    let _result = agent.create_agreement(
        &document_key,
        &agentids,
        None,
        None,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );

    // agent two signs document

    // agent one checks document

    // agent one signs document

    // agent one checks document

    // agent two checks document
}

#[test]
fn test_add_and_remove_agents() {
    let DOCUMENT_PATH = format!("examples/documents/{}.json", DOCID);
    // cargo test   --test agreement_test -- --nocapture test_add_and_remove_agents
    let mut agent = load_test_agent_one();
    let agents_orig: Vec<String> = vec!["mariko".to_string(), "takeda".to_string()];
    let agents_to_add: Vec<String> = vec!["gaijin".to_string()];
    let agents_to_remove: Vec<String> = vec!["mariko".to_string()];

    let document_string = load_local_document(&DOCUMENT_PATH).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let mut doc_v1 = agent
        .create_agreement(
            &document_key,
            &agents_orig,
            None,
            None,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("create_agreement");
    let doc_v1_key = doc_v1.getkey();
    println!(
        "doc_v1_key agents requested {:?} unsigned {:?}",
        doc_v1.agreement_requested_agents().unwrap(),
        doc_v1.agreement_unsigned_agents().unwrap()
    );
    let mut doc_v2 = agent
        .add_agents_to_agreement(
            &doc_v1_key,
            &agents_to_add,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("add_agents_to_agreement");
    let doc_v2_key = doc_v2.getkey();
    println!(
        "doc_v2_key agents {:?}",
        doc_v2.agreement_requested_agents().unwrap()
    );
    let mut doc_v3 = agent
        .remove_agents_from_agreement(
            &doc_v2_key,
            &agents_to_remove,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("remove_agents_from_agreement");
    let doc_v3_key = doc_v3.getkey();
    println!(
        "doc_v3 agents {:?}",
        doc_v3.agreement_requested_agents().unwrap()
    );

    // println!(
    //     "final signature requests were\n {}",
    //     serde_json::to_string_pretty(&doc_v3.value).expect("pretty print")
    // );
    let result = agent.check_agreement(
        &doc_v3.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    match result {
        Err(_) => assert!(true),
        Ok(_) => assert!(false),
    }
}

#[test]
fn test_sign_agreement() {
    let DOCUMENT_PATH = format!("examples/documents/{}.json", DOCID);
    // cargo test   --test agreement_test -- --nocapture test_sign_agreement
    let mut agent = load_test_agent_one();
    let mut agent_two = load_test_agent_two();

    let a1k = agent.get_private_key().unwrap();
    let a2k = agent_two.get_private_key().unwrap();
    let borrowed_key = a1k.expose_secret();
    let key_vec = borrowed_key.use_secret();

    let borrowed_key2 = a2k.expose_secret();
    let key_vec2 = borrowed_key2.use_secret();

    // println!(
    //     "public \n {:?}\n{:?}\nprivate\n{:?}\n{:?}",
    //     String::from_utf8(agent.get_public_key().unwrap()).unwrap(),
    //     String::from_utf8(agent_two.get_public_key().unwrap()).unwrap(),
    //     String::from_utf8(key_vec).unwrap(),
    //     String::from_utf8(key_vec2).unwrap()
    // );

    let mut agentids: Vec<String> = Vec::new();
    agentids.push(agent.get_id().expect("REASON"));
    agentids.push(agent_two.get_id().expect("REASON"));

    let document_string = load_local_document(&DOCUMENT_PATH).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    // agent one creates agreement document
    let unsigned_doc = agent
        .create_agreement(
            &document_key,
            &agentids,
            None,
            None,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("create_agreement");

    let unsigned_doc_key = unsigned_doc.getkey();

    let signed_document = agent
        .sign_agreement(
            &unsigned_doc_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("signed_document ");
    let signed_document_key = signed_document.getkey();
    let signed_document_string =
        serde_json::to_string_pretty(&signed_document.value).expect("pretty print");

    let _ = agent_two.load_document(&signed_document_string).unwrap();
    let both_signed_document = agent_two
        .sign_agreement(
            &signed_document_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("signed_document ");

    println!(
        "SIGNED DOCUMENT was {} now {}, then {} \n {}",
        unsigned_doc_key,
        signed_document_key,
        both_signed_document.getkey(),
        serde_json::to_string_pretty(&both_signed_document.value).expect("pretty print")
    );

    println!(
        "both_signed_document agents requested {:?} unsigned {:?} signed {:?}",
        both_signed_document.agreement_requested_agents().unwrap(),
        both_signed_document.agreement_unsigned_agents().unwrap(),
        both_signed_document.agreement_signed_agents().unwrap()
    );

    let result = agent_two.check_agreement(
        &both_signed_document.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    match result {
        Err(err) => {
            println!("{}", err);
            assert!(false)
        }
        Ok(_) => assert!(true),
    }

    let both_signed_document_string =
        serde_json::to_string_pretty(&both_signed_document.value).expect("pretty print");

    let agent_one_both_signed_document = agent.load_document(&both_signed_document_string).unwrap();
    let agent_one_both_signed_document_key = agent_one_both_signed_document.getkey();
    let result = agent.check_agreement(
        &agent_one_both_signed_document_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    match result {
        Err(err) => {
            println!("{}", err);
            assert!(false)
        }
        Ok(_) => assert!(true),
    }
    let (question, context) = agent
        .agreement_get_question_and_context(
            &agent_one_both_signed_document_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .unwrap();
    println!(" question {}, context {}", question, context);
}
