
/**
 * Creates middleware for JACS request/response signing and verification
 * @param {Object} options
 * @param {string} [options.configPath] - Path to JACS config file
 */
export function createJacsMiddleware(options = {}) {
    return async (ctx, next) => {
        const jacs = await import('./index.js');
        if (options.configPath) { 
            await jacs.load(options.configPath); 
        }

        // Verify incoming request if present
        if (ctx.request) {
            try {
                if (typeof ctx.request === 'string') {
                    // Assuming server receives JACS doc, client sends JACS doc
                    // Server verifies incoming request (which was signed by client's signRequest)
                    const verifiedRequest = await jacs.verifyResponse(ctx.request); // verifyResponse used to decrypt/verify a JACS document
                    ctx.request = verifiedRequest.payload;
                } else {
                    console.log("JACS Middleware: Request is not a string, assuming already parsed JSON");
                }
            } catch (error) { 
                throw new Error(`Invalid JACS request: ${error.message}`); 
            }
        }

        // Process the request through next middleware
        await next();

        // Sign outgoing response if present
        if (ctx.response) {
            try {
                // Server signs outgoing response
                ctx.response = await jacs.signRequest(ctx.response); // signRequest used to create a JACS document
            } catch (error) { 
                throw new Error(`Failed to sign response: ${error.message}`); 
            }
        }
    };
}