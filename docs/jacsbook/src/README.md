# JSON is all you need! **

As a developer, this is a good place to start, or review the code at [JACS on github](https://github.com/HumanAssisted/JACS), or watch our tutorials on [YouTube](https://www.youtube.com/@HAI_AI)

JACS docs are in a format already widely adopted and enjoyed: JSON. However, JACS can sign any type of document that can be checksummed, and any JSON document can be an embedded JACS document. The documents with signatures are always JSON. Therefore, they are independent of network protocols or database formats and can be shared and stand-alone.

You will use JACS lib and an agent to validate a document. To use, you create JSON documents and then sign them with your agent.

When those other services have modified the document, you can verifiy the agent, verify the changes, and sign the changes.


# Installation

To install the command line tool for creating and verifying agents and documents

    $ cargo install jacs
    $ jacs --help

If you are working in Rust, add the rust lib to your project

    cargo add jacs

# Flexible

Flexible for developers - store, index, and search the docouments how you like.


Any JSON document can be used as a JACS doc as long as it has the JACS header, which are some required fields about the creator and version.
Enforcement of schemas relies on [JSON Schema's](https://json-schema.org/) as a basic formalization.


For ease of use and safety of sharing documents (tasks) devs building connected Agent Apps will want to use services provided by https://hai.ai

