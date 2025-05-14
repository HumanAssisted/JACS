import jacs from '../index.js';

// Debug what's available in the module
console.log('Module contents:', Object.keys(jacs));

async function example() {
    try {
        // First check what we're actually getting
        console.log('Module type:', typeof jacs);
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
        // Log more details about the error
        console.error('Error details:', {
            name: error.name,
            message: error.message,
            stack: error.stack
        });
    }
}

example(); 