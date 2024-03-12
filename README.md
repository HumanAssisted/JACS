# JACS - JSON Ai Communication Standard

JACS allows for trusted sharing between AI agents and Human UIs, enabling infrastructure for where the internet is headed.
Just make JSON documents, sign them with your agent, and share the docs with other agents and services.
When those other services have modified the document, you can verifiy the agent, and sign the changes.

JACS is both a JSON Schema and Reference implementation of [OSAP](https://github.com/HumanAssistedIntelligence/OSAP) used and developed by HAI.AI to allow more secure communications between hetrogeneous AI agents and UIs. When changed, agents, tasks and other resources represented are versioned and the version is cryptographically signed. Changes can be verified and approved by other agents, allowing for  creation and exchange of trusted data.

Importantly, the verification can be done be third parties, much like the signing authorities for certificates.

# usage

If you were to import this package in Rust for example.

    cargo add jacs

Now you can create agents

```
    use jacs::{Agent, Resource, Task}

    // create your local agent
    let json_data = fs::read_to_string("examples/myagent.json");

    // create your jacs agent object with schema version
    let myagent = Agent::new("v1");

    // load your agent without an id, if there is no id one will be assigned
    myagent.load(json_data, privatekeypath:None);

    // create keys for the agent and save the to the path
    let pubkey, privatekey = myagent.newkeys("algorithm", "file/path");
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





# objects

The main objects are

Stateful things. Nouns.

 - [Resources](./docs/schema/resource.md) - things in the world that will be transformed
 - [Agents](./docs/schema/agent.md) - things that can take actions, a type of resource
 - [Units](./docs/schema/unit.md) - labels for quantitative numbers
 - [Signatures](./docs/schema/signature.md) - public key verifiable signatures
 - [Files](./docs/schema/files.md) - files

Meta things.

 - [Actions](./docs/schema/action.md) - as set of things that can happen to a resource, and a set of things that an Agent is capable of
 - [Tasks](./docs/schema/task.md) - set of desired actions, agents, resources
 - [Decisions](./docs/schema/decision.md) - changes to tasks


For the schema files see [schemas](./schemas).
For examples see [schemas](./examples).


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

 - signature verification
 - add signature types enum so implementations can check
 - auto doc rust
 - auto doc json schema
 - push to github pages


## interest

 - use post quantum signing tools. [pg crypto dilithium](https://docs.rs/pqcrypto-dilithium/0.5.0/pqcrypto_dilithium/) via https://github.com/pqclean/pqclean/
 - [json-ld](https://json-ld.org/) and  [https://crates.io/crates/sophia](https://crates.io/crates/sophia) integration

