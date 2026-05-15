use jacs::agent::AGENT_AGREEMENT_FIELDNAME;
use jacs::agent::agreement::Agreement;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::hash::hash_public_key;
use secrecy::ExposeSecret;
use serial_test::serial;
mod utils;

use utils::{
    create_owned_config_fixture_document, load_test_agent_one_ed25519, load_test_agent_two_ed25519,
};

#[test]
#[serial(jacs_env)]
fn test_create_agreement() {
    // cargo test   --test agreement_test -- --nocapture test_create_agreement
    let mut agent = load_test_agent_one_ed25519();
    let agent_two = load_test_agent_two_ed25519();
    let agentids: Vec<String> = vec![
        agent.get_id().expect("REASON"),
        agent_two.get_id().expect("REASON"),
    ];

    let document_key = create_owned_config_fixture_document(&mut agent);
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

    println!("{}", unsigned_doc);

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
#[serial(jacs_env)]
fn test_add_and_remove_agents() {
    // cargo test   --test agreement_test -- --nocapture test_add_and_remove_agents
    let mut agent = load_test_agent_one_ed25519();
    let agents_orig: Vec<String> = vec!["mariko".to_string(), "takeda".to_string()];
    let agents_to_add: Vec<String> = vec!["gaijin".to_string()];
    let agents_to_remove: Vec<String> = vec!["mariko".to_string()];

    let document_key = create_owned_config_fixture_document(&mut agent);
    let doc_v1 = agent
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
        doc_v1
            .agreement_requested_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()),)
            .unwrap(),
        doc_v1
            .agreement_unsigned_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()),)
            .unwrap()
    );
    let doc_v2 = agent
        .add_agents_to_agreement(
            &doc_v1_key,
            &agents_to_add,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("add_agents_to_agreement");
    let doc_v2_key = doc_v2.getkey();
    println!(
        "doc_v2_key agents {:?}",
        doc_v2
            .agreement_requested_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()),)
            .unwrap()
    );
    let doc_v3 = agent
        .remove_agents_from_agreement(
            &doc_v2_key,
            &agents_to_remove,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .expect("remove_agents_from_agreement");
    let _doc_v3_key = doc_v3.getkey();
    println!(
        "doc_v3 agents {:?}",
        doc_v3
            .agreement_requested_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()),)
            .unwrap()
    );

    // println!(
    //     "final signature requests were\n {}",
    //     serde_json::to_string_pretty(&doc_v3.value).expect("pretty print")
    // );
    let result = agent.check_agreement(
        &doc_v3.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(
        result.is_err(),
        "check_agreement should fail for incomplete agreement"
    );
}

#[test]
#[serial(jacs_env)]
fn test_sign_agreement() -> Result<(), Box<dyn std::error::Error>> {
    // cargo test   --test agreement_test -- --nocapture test_sign_agreement
    let mut agent = load_test_agent_one_ed25519();
    let mut agent_two = load_test_agent_two_ed25519();

    let a1k = agent.get_private_key().unwrap();
    let a2k = agent_two.get_private_key().unwrap();
    assert!(
        !a1k.expose_secret().is_empty(),
        "agent one private key should be loaded"
    );
    assert!(
        !a2k.expose_secret().is_empty(),
        "agent two private key should be loaded"
    );

    // println!(
    //     "public \n {:?}\n{:?}\nprivate\n{:?}\n{:?}",
    //     String::from_utf8(agent.get_public_key().unwrap()).unwrap(),
    //     String::from_utf8(agent_two.get_public_key().unwrap()).unwrap(),
    //     String::from_utf8(key_vec).unwrap(),
    //     String::from_utf8(key_vec2).unwrap()
    // );

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

    let document_key = create_owned_config_fixture_document(&mut agent);
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
    let pending_for_agent_one = agent.check_agreement(
        &signed_document_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(
        pending_for_agent_one.is_err(),
        "agreement should be incomplete until all requested agents sign"
    );

    let signed_document_string =
        serde_json::to_string_pretty(&signed_document.value).expect("pretty print");

    let _ = agent_two.load_document(&signed_document_string).unwrap();
    let pending_for_agent_two = agent_two.check_agreement(
        &signed_document_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    assert!(
        pending_for_agent_two.is_err(),
        "agreement should remain incomplete for other agents before they sign"
    );

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
        both_signed_document
            .agreement_requested_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()))
            .unwrap(),
        both_signed_document
            .agreement_unsigned_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()),)
            .unwrap(),
        both_signed_document
            .agreement_signed_agents(Some(AGENT_AGREEMENT_FIELDNAME.to_string()),)
            .unwrap()
    );

    let result = agent_two.check_agreement(
        &both_signed_document.getkey(),
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    if let Err(err) = result {
        panic!("agent_two check_agreement failed: {}", err);
    }

    let both_signed_document_string =
        serde_json::to_string_pretty(&both_signed_document.value).expect("pretty print");

    let agent_one_both_signed_document = agent.load_document(&both_signed_document_string).unwrap();
    let agent_one_both_signed_document_key = agent_one_both_signed_document.getkey();
    let result = agent.check_agreement(
        &agent_one_both_signed_document_key,
        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
    );
    if let Err(err) = result {
        panic!("agent_one check_agreement failed: {}", err);
    }
    let (question, context) = agent
        .agreement_get_question_and_context(
            &agent_one_both_signed_document_key,
            Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
        )
        .unwrap();
    println!(" question {}, context {}", question, context);

    Ok(())
}
