# JSON is all you need! **

As a developer, this is a good place to start. For deeper dives, review the code at [JACS on github](https://github.com/HumanAssisted/JACS). For misc, watch our tutorials on [YouTube](https://www.youtube.com/@HAI_AI)

JACS docs are in a format already widely adopted and enjoyed: JSON. However, JACS can sign any type of document that can be checksummed, and any JSON document can be an embedded JACS document. The documents with signatures are always JSON. Therefore, they are independent of network protocols or database formats and can be shared and stand-alone.

You will use JACS lib and an agent to validate a document. To use, you create JSON documents and then sign them with your agent. Maybe this doesn't seem incredibily important at first.
When agents start automating and exchanging large amounts of data, quality, consent are only possible with identity. There are good arguments about why identity should be centralized or decentralized. JACS is neutral in that discusssion, except that generating a private key for your agent is a form of decentralization.


JACS is for general documents, but focuses on the idea of Agents, Tasks and Messages, making it easier to create an audit trail of modifications to tasks, agreements, resoutions, etc.


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

# Ease of use

JACS is not meant to be the easiest to use, but it should be useful as is for some specific applicaitons. More importantly it is open source.

If your focus is building an AI business, or selling data to AI, there's quite a lot of work to do. For ease of use and safety of sharing documents (tasks) devs building connected Agent Apps will want to use services provided by https://hai.ai

