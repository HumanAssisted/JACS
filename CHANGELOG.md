# PLANNED
- encrypt files at rest
- refine schema usage
- more getters and setters for documents recognized by schemas
- WASM builds

# COMPLETED

## 0.3.0
- added jacsType - free naming, but required field for end-user naming of file type, with defaults to "document"
- TODO update jsonschema library
- updated strum, criterion
- updated reqwest library
- fixed bug EmbeddedSchemaResolver not used for custom schemas
- added load_all() for booting up  
- WIP move all fileio to object_store 
- WIP way to mark documents as not active - separate folder, or just reference them from other docs
- fixed issue with filepaths for agents and keys
- added jacsType to to jacs document as required
- added archive old version, to move older versions of docs to different folder
- added jacsEmbedding to headers, which allow persistance of vector embeddings iwth jacs docs. 
- default to only loading most recent version of document in load_all
- fixed bug with naming file on update

## 0.2.13
- save public key to local fs
- restricted signingAlgorithm in schema
- refresh schema for program, program node/consent/action/tool

## 0.2.12

- Let Devin.ai have a go at looking for issues with missing documentation, unsafe calles, and uncessary copies of data, updated some libs
- Fixed an issue with the schema resolver to handle more cases in tests.


## 0.2.11

- bringing some documentation up to date
- adding evaluations schemas
- adding agree/disagree to signature
- adding evaluation helpers **
- incremental documentation work **
- make github repo public **
- proper cargo categories

## 0.2.10

- decouple message from task so they can arrive out of order. can be used to create context for task
- parameteraize agreement field
- task start and end agreements functions
- fixed issue with schema path not being found, so list of fields returned incorrect
- retrieve long and short schema name from docs - mostly for task and agent


## 0.2.9

- tests for task and actions creation
- handle case of allOf in JSON schema when recursively retrieving "hai" print level
- add message to task
- fixed issue with type=array/items in JSON schema when recursively retrieving "hai" print level


## 0.2.8

 - add question and context to agreement, useful to UIs and prompting
 - adding "hai", fields to schema denote which fields are useful for agents "base", "meta", "agent"

## 0.2.7

 - crud operations for agent, service, message, task - lacking tests
 - more complete agent and cli task creation

## 0.2.6
 - doc include image


## 0.2.5
 - filesystem security module
 - unit, action, tool, contact, and service schemas
 - tasks and message schemas

## 0.2.4

- add jacsRegistration signature field
- add jacsAgreement field
- tests for issue with public key hashing because of \r
- add agreement functions in trait for agent
- fixes with cli for agent and config creation


## 0.2.3

 - add config creation and viewing to CLI
 - added gzip to content embedding
 - added extraction for embedded content
 - started mdbook documentation


## 0.2.2 - April 12 2024

 - prevent name collisions with jacs as prefix on required header fields
 - add "jacsFiles" schema to embed files or sign files that can't be embedded



## 0.2.1

 - build cli app (bulk creation and verification) and document
 - encrypt private key on disk

## 0.2.0

 - encrypt private key in memory, wipe
 - check and verify signatures
 - refactors
 - allow custom json schema verification