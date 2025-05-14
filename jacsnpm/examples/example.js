const jacs = require('./index.js');

async function example() {
    try {
        // Create a config
        const config = await jacs.create_config(
            "true",                    // jacs_use_security
            "./data",                  // jacs_data_directory
            "./keys",                  // jacs_key_directory
            "private_key.pem",         // jacs_agent_private_key_filename
            "public_key.pem",          // jacs_agent_public_key_filename
            "RSA",                     // jacs_agent_key_algorithm
            "password123",             // jacs_private_key_password
            "agent1:1.0.0",           // jacs_agent_id_and_version
            "file"                     // jacs_default_storage
        );
        console.log("Created config:", config);

        // Load the agent with the config
        await jacs.load("./config.json");
        console.log("Agent loaded successfully");

        // Create a document
        const document = await jacs.create_document(
            JSON.stringify({ hello: "world" }),  // document_string
            null,                               // custom_schema
            "example.json",                     // outputfilename
            false,                              // no_save
            null,                               // attachments
            false                               // embed
        );
        console.log("Created document:", document);

        // Verify the document
        const isValid = await jacs.verify_document(document);
        console.log("Document is valid:", isValid);

    } catch (error) {
        console.error("Error:", error);
    }
}

example(); 