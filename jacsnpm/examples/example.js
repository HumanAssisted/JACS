import jacs from '../index.js';
import assert from 'assert';

// Debug what's available in the module
console.log('Module contents:', Object.keys(jacs));

async function example() {
    try {
        // First check what we're actually getting
        console.log('Module type:', typeof jacs);
        // Load the agent with the config
        await jacs.load("./jacs.client.config.json");
        console.log("Agent loaded successfully");

        const docstring = { hello: "world" };

        const request = await jacs.signRequest(
            JSON.stringify(docstring),      // document_string
            null,                               // custom_schema
            "example.json",                     // outputfilename
            true,                              // no_save
            null,                               // attachments
            false                               // embed
        );
        console.log(typeof request);
        console.log("Created request:", request);
        console.log("Request type BEFORE verifyResponse:", typeof request);
        const response = await jacs.verifyResponse(request);
        console.log("Request type AFTER verifyResponse:", typeof request);
        
        console.log(typeof response);
        console.log("Verified response:", response);
        let payload = response.payload;

        const agent_and_payload = await jacs.verifyResponseWithAgentId(request);
        console.log(typeof agent_and_payload);
        console.log("Agent ID and payload:", agent_and_payload);
       

      
        console.log("Payload:", payload);   
        assert.deepStrictEqual(payload, docstring);

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