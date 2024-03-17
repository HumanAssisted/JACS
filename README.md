# JACS - JSON Ai Communication Standard

JACS allows for trusted sharing between AI agents and Human UIs.
The library provides data validation, cryptography tooling, and authorization for admin, edit, and viewing of documents that might be useful for both humans and AI.

To use, you create JSON documents and then sign them with your agent. Then share the docs with other agents and services. When those other services have modified the document, you can verifiy the agent, and sign the changes.

JACS is both a JSON Schema and Reference implementation of [OSAP](https://github.com/HumanAssistedIntelligence/OSAP) used and developed by [HAI.AI (Human Assisted Intelligence)](https://hai.ai) to allow more secure communications between hetrogeneous AI agents and human UIs.



## trust

When data is changed documents are versioned and the version is cryptographically signed. Changes can be verified and approved by other agents, allowing for creation and exchange of trusted data.

Importantly, the verification can be done be third parties with root certificates, much like the signing authorities SSL.


## extensible

Any JSON document can be used as a JACS doc as long as it has the JACS header.

For example, you have a complex project with a schema that's difficult


## open source


# Usage

Like JWT, these documents may become bublic

To use JACS you only really need to use the Headers in a JSON doc and your agent. The reset are optional.

Conversations, tasks, documents, and agents are some of the things represented in JSON. To use, just create a json document that follows the schema for an agent, and use it in the library to start building other things.

Here's an sample agent

```
```


## Schemas: basic types

every JACS doc has a header.

You only need to use the agents and header to record and verify permissions on any type of document

 - [Header](./docs/schema/header.md) -  the signature along with permissions
 - [Agents](./docs/schema/agent.md) - a type of resource that can take action
 - [Signatures](./docs/schema/components/signature.md) - cryptographically signed signature of the version of the document
 - [Permission](./docs/schema/components/permission.md) -  the signature along with  access rules for the document fields

For the schema files see [schemas](./schemas).
For examples see [schemas](./examples).


## building

If you were to import this package in Rust for example.

    cargo add jacs

for python (planned)

    pip install jacs

for node/typescript (planned)

    yarn add jacs

for golang (planned)

You don't need to know cryptography to use the library, but knowing the basics helps.

## using agents

Now you can create agents

```
    use jacs::{Agent, Resource, Task, Message}

    // load your local agent
    let json_data = fs::read_to_string("examples/myagent.json");

    // you can also implement a trait to load agents

    // create your jacs agent object with schema version
    let myagent = Agent::new("v1");

    // load your agent without an id, if there is no id one will be assigned
    let (ready, OK) = myagent.create(json_data);

    // if not ready, create id, version, and signature
    if ready {
        // create keys for the agent and save the to the path
        let public_key_pem, private_key_pem = myagent.newkeys("algorithm");
        // save your keys

        // now self sign the agent
        myagent.selfsign();
        // now register the public key and agent somewhere (a trait must be implemented to use this)

        // now save the agent whether from the trait or saving the string manually
        let _ = myagent.to_json_string();
        // save to "path/to/save/myagent.json"
        let _ = myagent.save();
    }

```

Now that the agent is created, we can use it.


```

    // my private key (assumes you've already decrypted)
    let private_key = fs::read_to_string("examples/private_key.pem");
    // my public key
    let public_key = fs::read_to_string("examples/publick_key.pem");

    // load your local agent
    let json_data = fs::read_to_string("examples/myagent.json");

    // create your jacs agent object with schema version
    let myagent = Agent::new("v1");

    // load verifies the agent by signature
    let (ready, OK) = myagent.load(json_data, public_key, private_key);

    // if the trait is implemented you can load by id
    let (ready, OK) = myagent.load_by_id(agent_id: String);

    // check that your agent is ready again
    let ready = myagent.ready();

    // printyour id
    println!("id {:?} version {}", myagent.id(), myagent.version());






```

Now that your agent is ready we can start creating documents

```

    // create a custom document

    // sign task as owner

    // save task

    // update task



```

You can also interact with other agents with messages, tasks, and plans

```
create second agent
first agent grants permissions to second agent

second agent makes some edits and adds a  message


now you can verify everychange in the task

```

What is hapening under the hood is that

1. the first agent, when adding a second agent must have admin permissions
2. the second agent must have permissions
3. the changes are signed
4. the first agent can verify the changes




Registering your agent will be provided by HAI.AI and other third parties.
These third parties can be used to verify that a version and change to a task or agent is legit



## usage with JWT


# Background

The web and html
Semantic Web and


Features include

 - an extensible JSON Schema for sharing information between agents and human UIs
 - cryptographic signing of messages
 - cryptographic hashing of chains of messages

## process

JACS runs by

1. creating/loading a private key
2. creating/loading public key into agent file
3. validating an agent or task schema
4. validating signature of agent an agent or task data
5. validating chain of signatures

## Usage

### from rust


### from python



### extending the schema

You can both extend just the schema file or the library in your own project.


# Roadmap



### advanced/future

 - full external audit
 - use post quantum signing tools. [pg crypto dilithium](https://docs.rs/pqcrypto-dilithium/0.5.0/pqcrypto_dilithium/) via https://github.com/pqclean/pqclean/
 - [json-ld](https://json-ld.org/) and  [https://crates.io/crates/sophia](https://crates.io/crates/sophia) integration

