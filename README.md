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

To use JACS you only really need to use the Headers in a JSON doc and your agent. The reset are optional.

Conversations, tasks, documents, and agents are some of the things represented in JSON. To use, just create a json document that follows the schema for an agent, and use it in the library to start building other things.

Here's an sample agent

```
```


## Schemas: basic types


You only need to use the agents and header to record and verify any type of document, but some basic types are provided.

 - [Resources](./docs/schema/resource.md) -  references to things
 - [Agents](./docs/schema/agent.md) - a type of resource that can take action
 - [Units](./docs/schema/unit.md) - measurements that can change based on actions
 - [Signatures](./docs/schema/signature.md) - cryptographically signed signature of the version of the document
 - [Files](./docs/schema/files.md) - attachements with mime types or external references, checksummed

Meta things.
 - [Header](./docs/schema/header.md) -  the signature along with permissions
 - [Permission](./docs/schema/header.md) -  the signature along with  access rules for the document fields
 - [Actions](./docs/schema/action.md) - a description of things that can be done to and by resources
 - [Tasks](./docs/schema/task.md) -a set of actions and a desired outcome as well as state management, can reference other tasks
 - [Plan](./docs/schema/plan.md) - a set of tasks wth a desired outcome. can reference other plans
 - [Contract](./docs/schema/contract.md) - set of plans. a proposal until signed
 - [Messages](./docs/schema/message.md) - signed messages between users

 - [Decisions](./docs/schema/decision.md) - changes to tasks


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

Now you can create agents

```
    use jacs::{Agent, Resource, Task, Message}

    // create your local agent
    let json_data = fs::read_to_string("examples/myagent.json");

    // create your jacs agent object with schema version
    let myagent = Agent::new("v1");

    // load your agent without an id, if there is no id one will be assigned
    let (ready, OK) = myagent.load(json_data, privatekeypath:None);

    // if not ready, create id, version, and signature
    if ready {
        // create keys for the agent and save the to the path
        let _ = myagent.newkeys("algorithm", "file/path");
    }

    // load the keys
    let _ = myagent.loadkeys("file/path");
    // generate signature for your agent
    let _ = myagent.selfsign();
    let _ = myagent.save("path/to/save/myagent.json");

    // here is where you might want to register this version of your agent
    // registration is left for services to implement

    // printyour id
    println!("id {:?} version {}", myagent.id(), myagent.version());

    // add some actions to your agent
    // create action
    // add actions to agent
    // save updated agent
    let _ = myagent.save("path/to/save/myagent.json");

    // check that your agent is ready
    let ready = myagent.ready();

    hash the id, version, name/title
    sign the hash




```

Now that you'e created an agent you can create a task and add attributes to it

```

    // create a task

    // sign task as owner

    // save task

    // update task



```

Now that you'e created an agent, you can create another agent and have that agent
add messages and edits to the task

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

## todo

 - version not updated until everything signed
 - signature verification
 - add signature types enum so implementations can check
 - auto doc rust
 - push docs github pages


### advanced/future

 - full audit
 - use post quantum signing tools. [pg crypto dilithium](https://docs.rs/pqcrypto-dilithium/0.5.0/pqcrypto_dilithium/) via https://github.com/pqclean/pqclean/
 - [json-ld](https://json-ld.org/) and  [https://crates.io/crates/sophia](https://crates.io/crates/sophia) integration

