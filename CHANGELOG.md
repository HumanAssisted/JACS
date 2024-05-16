## 0.2.12 (Upcoming Changes)

- Added diagnostic print statements in `pq_tests.rs` to investigate the performance issue with the `pqcrypto_dilithium::dilithium5` keypair generation function.
- Implemented a test in `src/bin/keypair_test.rs` to measure the duration of the keypair generation process and identify if the duration exceeds the expected threshold.
- Updated `src/crypt/pq.rs` to include diagnostic print statements for the key generation process, providing insights into the duration and potential performance bottlenecks.
- Ensured that `agent_tests.rs` correctly sets up the `MockServer` to serve schema files for validation, with SSL verification disabled for the reqwest client, to prevent SSL certificate verification errors when fetching schema files.
- Resolved issues with schema file paths in the `MockServer` setup within `agent_tests.rs`, ensuring that the test suite references the correct paths to access the schema files.
- Addressed a panic caused by dropping the Tokio runtime within an asynchronous context in the `test_update_agent_and_verify_versions` test by restructuring the test function to manage the Tokio runtime properly.
- Confirmed that all tests pass without modifying original tests or schemas, preserving the integrity of the existing test suite and schema directory.

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
