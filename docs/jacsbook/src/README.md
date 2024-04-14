# JSON is all you need! **

JACS docs are in a format already widely adopted and enjoyed: JSON. However, JACS can sign any type of document that can be checksummed, and any JSON document can be an embedded JACS document. The documents with signatures are always JSON. Therefore, they are independent of network protocols or database formats and can be shared and stand-alone.

You will use JACS lib and an agent to validate a document. To use, you create JSON documents and then sign them with your agent.

When those other services have modified the document, you can verifiy the agent, verify the changes, and sign the changes.

Flexible for developers - store, index, and search the docouments how you like.
Any JSON document can be used as a JACS doc as long as it has the JACS header, which are some required fields about the creator and version.
Enforcement of schemas relies on [JSON Schema's](https://json-schema.org/) as a basic formalization.

Most devs building connected Agent Apps will want to use [Sophon](https://github.com/HumanAssistedIntelligence/sophon). [Sophon](https://github.com/HumanAssistedIntelligence/sophon) will make it easy to use, but also imposes a lot of opinions.

JACS started as [OSAP](https://github.com/HumanAssistedIntelligence/OSAP) and stands for - JSON Agent Communication Standard.