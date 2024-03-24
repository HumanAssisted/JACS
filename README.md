# JACS - JSON Ai Communication Standard

Welcome to JACS.

The JACS documents enable trusted data sharing between AI agents and Human UIs. It does this by making JSON documents verifiable.

 - verifiable as to their source
 - verifiable as to their schema
 - verifiable in a state and version


The core Rust library provides data validation, cryptography tooling that might useful for both human interfaces and AI.

To use, you create JSON documents and then sign them with your agent. Then share the docs with other agents and services. When those other services have modified the document, you can verifiy the agent, and sign the changes.

JACS started as [OSAP](https://github.com/HumanAssistedIntelligence/OSAP) used and developed by [HAI.AI (Human Assisted Intelligence)](https://hai.ai) to allow more secure communications between hetrogeneous AI agents and human UIs.


## trust

Documents are meant to be omnipotent.

When data is changed documents are versioned and the version is cryptographically signed by your agent.
Changes can be verified and approved by other agents using your public key, allowing for creation and exchange of trusted data.

Any person or software can modify a doc, but only agents can sign the changes.
If you are familiar with [JWTs](https://jwt.io/), PGP, sha256 hashes on files, then you have a good idea of how JACS works.

## extensible

Any JSON document can be used as a JACS doc as long as it has the JACS header, which just means some required fields about the creator and version.
Enforcement of schemas relies on [JSON Schema's](https://json-schema.org/) as a basic formalization.

## open source

Use JACS as is, embed in other projects or libraries, commercial or otherwise.
Decentralized but trusted data sharing is key to building the apps of the future.

# Usage

To use JACS you create an `Agent` and then use it to create docoments that conform to the JACS `Header` format.

To use, just create a json document that follows the schema for an agent, and use it in the library to start building other things.

Here's all it takes to create your agent.

```
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent-schema.json",
  "name": "Agent Smith",
  "agenttype": "ai",
  "description": "An agent without keys, id or version",
  "favorite-snack": "mango"
}

```

An id, version etc, will be created for you when you use it.
Here's a rust example.

```
use std::fs;
use std::env;


env::set_var("JACS_KEY_DIRECTORY", ".");
env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "rsa_pss_private.pem");
env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "rsa_pss_public.pem");
env::set_var("JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");


#[test]
fn test_validate_agent_creation() {
    set_test_env_vars();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    let json_data = fs::read_to_string("examples/agents/myagent.new.json").expect("REASON");
    let _ = agent.create_agent_and_load(&json_data, false, None);


```

Your agent will now look this this

```
agent-signature": {
    "agentid": "b6a7fcb4-a6e0-413b-9f5d-48a42a8e9d14",
    "agentversion": "b6a7fcb4-a6e0-413b-9f5d-48a42a8e9d14-erweowoeuir",
    "date": "2024-03-24T09:14:03.028576+00:00",
    "fields": [
      "favorite-snack",
      "id",
      "lastVersion",
      "originalVersion",
      "version",
      "versionDate",
      "name",
      "agentype",
      "description"
    ],
    "public-key-hash": "975f6dbe685a186deabab958b30c7c5aa97c144e3cb4357e34440783669e9815",
    "signature": "C/NQGYlR8zoYu/0rngi12lpG32lkPGPqP1y10u5lAgr5LsvBsfvk6v3xYXvWf4e+hX1sf4YxRbolawXE0wfqRXiLazhBA2zpz0Yn4i4bfaqBd7S8+ARoWyiolXa3tcAaxdXTRiu9VWwdfBhh4Nuku+LY/Q1XkRvwCuGf0MVZmbhX9JhfPTJMK+V2zCnzWOFX15IJBUnKcSY5847Sn/aDESuu7GpRN9XJej2gIQock1iVCITr0OCp9DZryMPARWoSWGdsFZBoUiGEkKtcExcZDaKZbDSfwTXauV2yd2VrhwRhl2eu8MICWui3j7KCIHSBJ+eLTELuUFkurNuffol+aw==",
    "signing_algorithm": "RSA-PSS"
  },
  "favorite-snack": "mango",
  "id": "b6a7fcb4-a630-413b-9f5d-48a42a8e9d14",
  "lastVersion": "b6a7f3b4-a6e0-413b-9f5d-48a42a8e9d14",
  "originalVersion": "b6a7fcb4-a6e0-413b-9f5d-48a42a8e9d14",
  "sha256": "19585c7a77b8416711a298e5c02056d5ed864a11218c563b3b4ef83563831fea",
  "version": "003f2cf6-6fc1-4f09-9877-ff42d5c0170e",
  "versionDate": "2024-03-24T09:14:02.966765+00:00",
  "name": "Agent Smith",
  "agenttype": "ai",
  "description": "An agent without keys, id or version"
}

```

The agent is self-signed and all the fields are hashed.
There is also a public and private key created in the directory set with `JACS_KEY_DIRECTORY`.

Now you can create, update, and sign documents with your agent. If you share your public key, other agents can verify the document is from your agent.

```
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = agent
        .load_local_document(&"examples/documents/my-special-document.json".to_string())
        .unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let modified_document_string = agent
        .load_local_document(&"examples/documents/my-special-document-modified.json".to_string())
        .unwrap();

    let new_document = agent
        .update_document(&document_key, &modified_document_string)
        .unwrap();

    let new_document_key = new_document.getkey();

    let new_document_ref = agent.get_document(&new_document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();

    println!("updated {} {}", new_document_key, new_document_ref);
    agent
        .verify_document_signature(
            &new_document_key,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
            None,
            None,
        )
        .unwrap();

    let agent_one_public_key = agent.get_public_key().unwrap();
    let mut agent2 = load_test_agent_two();
    let new_document_string = new_document_ref.to_string();
    let copy_newdocument = agent2.load_document(&new_document_string).unwrap();
    let copy_newdocument_key = copy_newdocument.getkey();
    println!("new document with sig: /n {}", new_document_string);
    agent2
        .verify_document_signature(
            &copy_newdocument_key,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
            None,
            Some(agent_one_public_key),
        )
        .unwrap();
```

## IDs and Versions vs Signatures

IDs of agents and documents should be unique to your agent as they are a combination of ID and Version. However, if you share your documents, and we expect that you will, documents can be copied by other agents at any time and they can forge IDs and sign their docs.

The solution to this is the value of the signature and where the signature is registered.


## Schemas: basic types

Every JACS doc has a header. These are created automatically.

You only need to use the agents and header to record and verify permissions on any type of document

 - [Header](./docs/schema/header.md) -  the signature along with permissions
 - [Agents](./docs/schema/agent.md) - a type of resource that can take action
 - [Signatures](./docs/schema/components/signature.md) - cryptographically signed signature of the version of the document
 - [Permission](./docs/schema/components/permission.md) -  the signature along with  access rules for the document fields

For the schema files see [schemas](./schemas).
For examples see [examples](./examples).





