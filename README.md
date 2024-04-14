# JACS

Welcome to JACS. JSON Agent Communication Standard.
by https://hai.ai

** NOTE: Current version 0.2.3 *ALPHA* .

The JACS documents enable more trusted data sharing between AI agents and Human UIs.

JACS is a JSON document format for creating secure, verifiable documents that AI agents, ML pipelines, SaaS services, and UIs can exchange and process. The goal of JACS is to ensure that these documents remain unchanged (immutable), produce the same verification result every time (idempotent), and can be used flexibly by software.

With JACS, data can be securely stored or shared, and different versions of the data can be tracked. One of the key features of JACS is its ability to provide instant verification of document ownership. Each version of a JACS document is signed with a unique digital signature, allowing an AI agent to prove its data claims. This enables trusted interactions between agents and provides flexibility in how documents are versioned and exchanged.

Any person or software can modify a doc, but only agents with the private key can sign new versions, and only holders of the public key can verify.

Decentralized but trusted data sharing is key to building the apps of the future.
Use JACS as is, embed in other projects or libraries, commercial or otherwise.


## Documentation

 - [Usage Docs] (https://humanassisted.github.io/JACS/)
 - [API docs](https://docs.rs/jacs/latest/jacs/)
 - [Schema docs](./schemas)
 - [example files](./examples)
 - [use case examples](https://github.com/HumanAssisted/jacs-examples)
 - [presentation on JACS](https://docs.google.com/presentation/d/18mO-tftG-9JnKd7rBtdipcX5t0dm4VfBPReKyWvrmXA/edit#slide=id.p)


** As of version 0.2, you can create and verify internal documents, when the public and private key are known between internal services.

## extensible

Use any type of JSON document, and you can enforce structure of type of JSON document using
[JSON Schema](https://json-schema.org/). If you are just getting started with JSON schema

 1. [introduction](https://json-schema.org/understanding-json-schema)
 2. [github page](https://github.com/json-schema-org)
 3. [youtube channel](https://www.youtube.com/@JSONSchemaOrgOfficial)

You can also embed any document, so if you want to sign a gif or .csv, you can link or embed that document with JACS.

## open source

In addition, JACS depends on the work of great open source efforts in standards and encryption.

See the [Cargo.toml](./Cargo.toml)

# Quick Start

To install the command line tool for creating and verifying agents and documents

    $ cargo install jacs
    $ jacs --help

If you are working in Rust, add the rust lib to your project

    cargo add jacs

Then start reading the [usage docs] (https://humanassisted.github.io/JACS/)

## background

JACS is used and developed by [HAI.AI (Human Assisted Intelligence)](https://hai.ai) to allow more secure communications between hetrogeneous AI agents and human UIs.





