# HEADER VALIDATION

The following is a brief explanation of documents are created, signed, and verified.


1. a json document is loaded as a "new" document
2. as a new document it must not have an id, version etc
3. an id and version uuid is created, along with date, etc
4. all the fields are hashed and put into a field that is not part of the hash
5. all the fields are used to sign with the agent's private key, and the public keys sha256 is aded to the document, as well as the signing agent's id and version


