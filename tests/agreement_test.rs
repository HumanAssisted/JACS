use jacs::agent::agreement::Agreement;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
mod utils;

use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use utils::{load_local_document, load_test_agent_one, load_test_agent_two};

#[test]
fn test_create_agreement() {
    // cargo test   --test agreement_test -- --nocapture test_create_agreement
    let mut agent = load_test_agent_one();
    let mut agent_two = load_test_agent_two();
    let mut agentids: Vec<String> = Vec::new();
    agentids.push(agent.get_id().expect("REASON"));
    agentids.push(agent_two.get_id().expect("REASON"));

    let document_string =
        load_local_document(&"examples/documents/e957d062-d684-456b-8680-14a1c4edcb2a:5599ac70-a3d6-429b-85ae-c9b17c78d2c5.json".to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    // agent one creates agreement document
    let unsigned_doc = agent
        .create_agreement(&document_key, &agentids)
        .expect("create_agreement");

    println!("{}", unsigned_doc.to_string());

    // agent one  tries and fails to creates agreement document
    let result = agent.create_agreement(&document_key, &agentids);
    // agent two signs document

    // agent one checks document

    // agent one signs document

    // agent one checks document

    // agent two checks document
}
