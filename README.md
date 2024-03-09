# JACS - JSON Ai Communication Standard

JACS is both a JSON Schema and Reference implementation of [OSAP](https://github.com/HumanAssistedIntelligence/OSAP) used by HAI.AI to allow more secure communications between hetrogeneous AI agents and UIs.


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
 - signature types
 - auto doc rust
 - auto doc json schema
 - push to github pages

## broader goals

 - secure post quantum
 - extensible sub schemas
 - json-ld integration

# References

