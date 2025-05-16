import jacs from '../index.js';

// Debug what's available in the module
console.log('Module contents:', Object.keys(jacs));

async function example() {
    try {
        // First check what we're actually getting
        console.log('Module type:', typeof jacs);
        // Load the agent with the config
        await jacs.load("./jacs.client.config.json");
        console.log("Agent loaded successfully");

        const request = await jacs.signRequest(
            JSON.stringify({ hello: "world" }),  // document_string
            null,                               // custom_schema
            "example.json",                     // outputfilename
            true,                              // no_save
            null,                               // attachments
            false                               // embed
        );
        console.log("Created request:", request);
        const agentId = await jacs.verifyResponseWithAgentId(request);
        console.log("Agent ID and payload:", agentId);

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