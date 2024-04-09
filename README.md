# JACS

Welcome to JACS. JSON Agent Communication Standard.

NOTE: Current version 0.2.2 *ALPHA*.

The JACS documents enable trusted data sharing between AI agents and Human UIs. It does this by making JSON documents verifiable:

 -  source
 -  schema
 -  state and version

The library provides data validation, cryptography tooling that might useful for both human interfaces and AI. JACS  is a format for creating secure, verifiable JSON documents that AI agents can exchange and process. The goal of JACS is to ensure that these documents remain unchanged (immutable), produce the same verification result every time (idempotent), and can be used flexibly by the software or people processing them.

With JACS, data can be securely stored or shared, and different versions of the data can be tracked. One of the key features of JACS is its ability to provide instant verification of document ownership. Each version of a JACS document is signed with a unique digital signature, allowing an AI agent to prove its data claims. This enables trusted interactions between agents and provides flexibility in how documents are versioned and exchanged.

By using JACS, AI agents can have confidence in the integrity and authenticity of the data received, making it easier to build secure, reliable agents.

NOTE: Doesn’t *require* central key authority yet, but this does mean that anyone can spoof anyone.
Until then, use for self signing only, or exchange public keys only with trusted services.

## JSON is all you need!

Documents are in a format already widely adopted and enjoyed: JSON.
Therefore, they are independent of network protocols or database formats and an be shared and stand-alone.
JACS can sign any type of document that can be checksummed, and any JSON document can be an embedded JACS document.

All you need is the JACS lib and an agent to validate a document. To use, you create JSON documents and then sign them with your agent.
When those other services have modified the document, you can verifiy the agent, verify the changes, and sign the changes.

Flexible for developers - store, index, and search the docouments how you like.
Any JSON document can be used as a JACS doc as long as it has the JACS header, which are some required fields about the creator and version.
Enforcement of schemas relies on [JSON Schema's](https://json-schema.org/) as a basic formalization.

Most devs building connected Agent Apps will want to use [Sophon](https://github.com/HumanAssistedIntelligence/sophon).

Check out the [presentation on JACS.](https://docs.google.com/presentation/d/18mO-tftG-9JnKd7rBtdipcX5t0dm4VfBPReKyWvrmXA/edit#slide=id.p)
See also  [Rust docs](https://humanassisted.github.io/JACS/).

## trust

JACS documents are meant to be immutable and idempotent.

When data is changed documents are versioned and the version is cryptographically signed by your agent.
Changes can be verified and approved by other agents using your public key, allowing for creation and exchange of trusted data.

Any person or software can modify a doc, but only agents with the private key can sign the changes.
If you are familiar with [JWTs](https://jwt.io/) or PGP from email, then you have a good idea of how JACS works.

Signature options are "ring-Ed25519", "RSA-PSS", and "pq-dilithium".
These are all open source projects and JACS is not an encryption library in itself.


## extensible

Use any type of json document, and you can enforce any type of document using
[JSON Schema](https://json-schema.org/). If you are just getting started with JSON schema

 1. [checkout their introduction](https://json-schema.org/understanding-json-schema)
 2. [github page](https://github.com/json-schema-org)
 3. [youtube channel](https://www.youtube.com/@JSONSchemaOrgOfficial)


## open source

In addition, JACS depends on the work of great open source efforts in standards and encryption.
See the [Cargo.toml](./Cargo.toml)

Decentralized but trusted data sharing is key to building the apps of the future.
Use JACS as is, embed in other projects or libraries, commercial or otherwise.
[Sophon](https://github.com/HumanAssistedIntelligence/sophon) will make it easy to use, but also imposes a lot of opinions.


# Usage

To install the command line tool for creating and verifying agents and documents

    cargo install jacs

To add the lib to your project

    cargo add jacs


## setting up

First, configure your configuration which are loaded as envirornment variables.
Create a `jacs.config.json` from [the example](./jacs.config.example.json)
For an explanation see [the schema for the config.](./schemas/jacs.config.schema.json)

Note: Do not use `jacs_private_key_password` in production. Use the environment variable `JACS_PRIVATE_KEY_PASSWORD` in a secure manner. This encrypts a private key needed for signing documents. You can create a new version of your agent with a new key, but this is not ideal.


To use JACS you create an `Agent`  and then use it to create docoments that conform to the JACS `Header` format.

First, create a json document that follows the schema for an agent, and use it in the library to start building other things.



```
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent-schema.json",
  "name": "Agent Smith",
  "agentType": "ai",
  "description": "An agent without keys, id or version",
  "favorite-snack": "mango"
}

```

An id, version etc, will be created  when you load the file from the command line

    jacs agent create ./examples/raw/mysecondagent.new.json --create-keys true

Your agent will look something like this and you will have also created keys. The agent is self-signed and all the fields are hashed.
There is also a public and private key created in the directory set with `jacs_key_directory`. DO NOT use the keys included in the repo.


```
agent-signature": {
    "agentID": "b6a7fcb4-a6e0-413b-9f5d-48a42a8e9d14",
    "agentVersion": "b6a7fcb4-a6e0-413b-9f5d-48a42a8e9d14-erweowoeuir",
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
    "publicKeyHash": "975f6dbe685a186deabab958b30c7c5aa97c144e3cb4357e34440783669e9815",
    "signature": "C/NQGYlR8zoYu/0rngi12lpG32lkPGPqP1y10u5lAgr5LsvBsfvk6v3xYXvWf4e+hX1sf4YxRbolawXE0wfqRXiLazhBA2zpz0Yn4i4bfaqBd7S8+ARoWyiolXa3tcAaxdXTRiu9VWwdfBhh4Nuku+LY/Q1XkRvwCuGf0MVZmbhX9JhfPTJMK+V2zCnzWOFX15IJBUnKcSY5847Sn/aDESuu7GpRN9XJej2gIQock1iVCITr0OCp9DZryMPARWoSWGdsFZBoUiGEkKtcExcZDaKZbDSfwTXauV2yd2VrhwRhl2eu8MICWui3j7KCIHSBJ+eLTELuUFkurNuffol+aw==",
    "signingAlgorithm": "RSA-PSS"
  },
  "favorite-snack": "mango",
  "id": "b6a7fcb4-a630-413b-9f5d-48a42a8e9d14",
  "lastVersion": "b6a7f3b4-a6e0-413b-9f5d-48a42a8e9d14",
  "originalVersion": "b6a7fcb4-a6e0-413b-9f5d-48a42a8e9d14",
  "sha256": "19585c7a77b8416711a298e5c02056d5ed864a11218c563b3b4ef83563831fea",
  "version": "003f2cf6-6fc1-4f09-9877-ff42d5c0170e",
  "versionDate": "2024-03-24T09:14:02.966765+00:00",
  "name": "Agent Smith",
  "agentType": "ai",
  "description": "An agent without keys, id or version"
}

```

You can verify you are set up with this command:

    jacs agent verify  -a ./examples/agent/fe00bb15-8c7f-43ac-9413-5a7bd5bb039d\:1f639f69-b3a7-45d5-b814-bc7b91fb3b97.json

To make it easier to use, add `jacs_agent_id_and_version` to your config and you can just run

    jacs agent verify

Now you can create, update, and sign documents with your agent.

To create create documents, select a file or directory and the documents will be copied to `jacs_data_directory` and renamed.


    jacs document create -d ./examples/raw/


Now you can verify a document is valid, even with custom JSON schema, and verify the signature of the document.

    jacs document verify -f ./examples/documents/MODIFIED_e4b3ac57-71f4-4128-b0c4-a44a3bb4d98d\:975f4523-e2e0-4b64-9c31-c718796fbdb1.json

Or a whole directory

    jacs document verify -d ./examples/documents/


You can also verify using a custom JSON Schema

     jacs document verify -f ./examples/documents/05f0c073-9df5-483b-aa77-2c3259f02c7b\:17d73042-a7dd-4536-bfd1-2b7f18c3503f.json -s ./examples/documents/custom.schema.json

If you share your public key, other agents can verify the document is from your agent , but is not available in the command line yet. Also, note that the command line doesn't yet allow for the modification of documents or agents.


For more examples, see the repo for different use cases:
https://github.com/HumanAssisted/jacs-examples

## Schemas IDs and Versions vs Signatures

IDs of agents and documents should be unique to your agent as they are a combination of ID and Version. However, if you share your documents, and we expect that you will, documents can be copied by other agents at any time and they can forge IDs and sign their docs.

Semantic versioning would break if the document forks because multiple agents will work on a single document. So each id/version is a UUID, and the previous version is stored so a trace can be constructed. (In itself, it's not a blockchain such that each version can be verified in the context of the previous version).


## Schemas: basic types

Every JACS doc has a header. These are created automatically.

You only need to use the agents and header to record and verify permissions on any type of document

 - [Header](./docs/schema/header.md) -  the signature along with permissions
 - [Agents](./docs/schema/agent.md) - a type of resource that can take action
 - [Signatures](./docs/schema/components/signature.md) - cryptographically signed signature of the version of the document

For the schema files see [schemas](./schemas).
For examples see [examples](./examples).

## security

JACS goal is to introduce no safety vulnerabilities to systems where it is integrated.
Open to ideas on what cryptography to add next: https://cryptography.rs/, like https://doc.dalek.rs/bulletproofs/index.html.

A little more abotu how signing works can be found at [Header Validation](./HEADER_VALIDATION.md)

### filesystem

However, filesystem acces can also be turned off completely for documents. This means your app passing strings in and out of JACS but can not save().

By default a directory is used that is configured.  JACS should not touch any files outside the key directory JACS_KEY_DIRECTORY and the JACS_DIRECTORY.

### private keys

Private keys are stored in memory with https://docs.rs/secrecy/latest/secrecy/
The are also encrypted when on the filesystem if you have set the password with the keys are created.

## background

JACS started as [OSAP](https://github.com/HumanAssistedIntelligence/OSAP) and stands for - JSON Agent Communication Standard.

HumanAssistedIntelligence/OSAP) used and developed by [HAI.AI (Human Assisted Intelligence)](https://hai.ai) to allow more secure communications between hetrogeneous AI agents and human UIs.





