# working with documents


Now that your agent is set up can create, update, and sign documents with your agent.

## CLI

To create create documents, select a file or directory and the documents will be copied to `jacs_data_directory` and renamed.


    jacs document create -d ./examples/raw/


Now you can verify a document is valid, even with custom JSON schema, and verify the signature of the document.

    jacs document verify -f ./examples/documents/MODIFIED_e4b3ac57-71f4-4128-b0c4-a44a3bb4d98d\:975f4523-e2e0-4b64-9c31-c718796fbdb1.json

Or a whole directory

    jacs document verify -d ./examples/documents/


You can also verify using a custom JSON Schema

     jacs document verify -f ./examples/documents/05f0c073-9df5-483b-aa77-2c3259f02c7b\:17d73042-a7dd-4536-bfd1-2b7f18c3503f.json -s ./examples/documents/custom.schema.json

If you share your public key, other agents can verify the document is from your agent , but is not available in the command line yet. Also, note that the command line doesn't yet allow for the modification of documents or agents.

To modify a document, copy the original and modify how you'd like, and then JACS can update the version and signature

    jacs document update -f ./examples/documents/05f0c073-9df5-483b-aa77-2c3259f02c7b\:17d73042-a7dd-4536-bfd1-2b7f18c3503f.json -n examples/raw/howtoupdate-05f0c073-9df5-483b-aa77-2c3259f02c7b.json -o updatedfruit.json

Filenames will always end with "jacs.json", so the -o

You can embed external files

    jacs document create -f ./examples/raw/not-fruit.json --attach ./examples/raw/mobius.jpeg --embed true


## API

