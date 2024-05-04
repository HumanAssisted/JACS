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