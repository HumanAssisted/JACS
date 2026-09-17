# JSON schemas


## Schemas IDs and Versions vs Signatures

IDs of agents and documents should be unique to your agent as they are a combination of ID and Version. However, if you share your documents, and we expect that you will, documents can be copied by other agents at any time and they can forge IDs and sign their docs.

Semantic versioning would break if the document forks because multiple agents will work on a single document. So each id/version is a UUID, and the previous version is stored so a trace can be constructed. (In itself, it's not a blockchain such that each version can be verified in the context of the previous version).


## Schemas: basic types

Every JACS doc has a header. These are created automatically.

You only need to use the agents and header to record and verify permissions on any type of document. Here are the basic types.

 - [Header](https://github.com/HumanAssisted/JACS/tree/main/docs/schema/header.md) -  the signature along with permissions
 - [Agents](https://github.com/HumanAssisted/JACS/tree/main/docs/schema/agent.md) - a type of resource that can take action
 - [Tasks](https://github.com/HumanAssisted/JACS/tree/main/docs/schema/task.md) -a set of actions and a desired outcome as well as state management, can reference other tasks
 - [Signatures](https://github.com/HumanAssisted/JACS/tree/main/docs/schema/components/signature.md) - cryptographically signed signature of the version of the document
 - [Files](https://github.com/HumanAssisted/JACS/tree/main/docs/schema/components/files.md) - documents you can sign and "attach"


