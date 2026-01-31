"use strict";
/**
 * JACS Setup Wizard
 *
 * Interactive setup for generating keys and creating agent identity.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.setupCommand = setupCommand;
const jacsnpm_1 = require("jacsnpm");
const uuid_1 = require("uuid");
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const crypto = __importStar(require("crypto"));
const index_1 = require("./index");
/**
 * Creates the setup command handler
 */
function setupCommand(api) {
    return async (ctx) => {
        const logger = api.logger;
        const homeDir = api.runtime.homeDir;
        try {
            // Get setup options from args or use defaults
            const options = parseSetupOptions(ctx.args);
            const jacsDir = path.join(homeDir, ".openclaw", "jacs");
            const keysDir = path.join(homeDir, ".openclaw", "jacs_keys");
            const configPath = path.join(jacsDir, "jacs.config.json");
            // Check if already initialized
            if (fs.existsSync(configPath)) {
                const existingConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
                return {
                    text: `JACS already initialized.\n\nAgent ID: ${existingConfig.jacs_agent_id_and_version?.split(":")[0]}\nConfig: ${configPath}\n\nUse 'openclaw jacs rotate' to rotate keys or delete ${jacsDir} to reinitialize.`,
                };
            }
            // Create directories with secure permissions
            fs.mkdirSync(jacsDir, { recursive: true, mode: 0o700 });
            fs.mkdirSync(keysDir, { recursive: true, mode: 0o700 });
            fs.mkdirSync(path.join(jacsDir, "agent"), { recursive: true });
            fs.mkdirSync(path.join(jacsDir, "documents"), { recursive: true });
            // Generate agent identity
            const agentId = (0, uuid_1.v4)();
            const agentVersion = (0, uuid_1.v4)();
            logger.info(`Generating ${options.keyAlgorithm} key pair...`);
            // Create JACS configuration using static function
            const jacsConfig = (0, jacsnpm_1.createConfig)("true", // jacs_use_security
            jacsDir, // jacs_data_directory
            keysDir, // jacs_key_directory
            "agent.private.pem.enc", // private key filename
            "agent.public.pem", // public key filename
            options.keyAlgorithm, // key algorithm
            options.keyPassword, // private key password
            `${agentId}:${agentVersion}`, // agent id:version
            "fs" // default storage
            );
            // Write config file
            fs.writeFileSync(configPath, jacsConfig, { mode: 0o600 });
            // Set password in environment for key generation
            process.env.JACS_PRIVATE_KEY_PASSWORD = options.keyPassword;
            // Create agent instance and load configuration (generates keys)
            const agent = new jacsnpm_1.JacsAgent();
            agent.load(configPath);
            // Create minimal agent document
            const agentDoc = {
                jacsId: agentId,
                jacsVersion: agentVersion,
                jacsAgentType: "ai",
                jacsName: options.agentName,
                jacsDescription: options.agentDescription,
                jacsAgentDomain: options.agentDomain,
                jacsServices: [],
                $schema: "https://hai.ai/schemas/agent/v1/agent.schema.json",
            };
            // Sign the agent document using instance method
            const signedAgent = agent.signRequest(agentDoc);
            // Save agent document
            const agentPath = path.join(jacsDir, "agent", `${agentId}:${agentVersion}.json`);
            fs.writeFileSync(agentPath, JSON.stringify(JSON.parse(signedAgent), null, 2));
            logger.info(`Agent created: ${agentId}`);
            // Load the public key for the runtime
            const pubKeyPath = path.join(keysDir, "agent.public.pem");
            const publicKey = fs.readFileSync(pubKeyPath, "utf-8");
            // Register the agent instance with the plugin runtime
            (0, index_1.setAgentInstance)(agent, agentId, publicKey);
            // Update OpenClaw plugin config
            api.updateConfig({
                agentId,
                keyAlgorithm: options.keyAlgorithm,
                agentName: options.agentName,
                agentDescription: options.agentDescription,
                agentDomain: options.agentDomain,
            });
            // Clean up password from environment
            delete process.env.JACS_PRIVATE_KEY_PASSWORD;
            return {
                text: `JACS initialized successfully!

Agent ID: ${agentId}
Algorithm: ${options.keyAlgorithm}
Config: ${configPath}
Keys: ${keysDir}

Your agent is ready to sign documents. Use:
  openclaw jacs sign <file>     - Sign a document
  openclaw jacs verify <file>   - Verify a signed document
  openclaw jacs status          - Show agent status
  openclaw jacs dns-record <domain> - Generate DNS TXT record

Note: Save your key password securely. It's required to sign documents.`,
                agentId,
                configPath,
            };
        }
        catch (err) {
            logger.error(`Setup failed: ${err.message}`);
            return {
                text: `JACS setup failed: ${err.message}`,
                error: err.message,
            };
        }
    };
}
/**
 * Parse setup options from command arguments
 */
function parseSetupOptions(args) {
    return {
        keyAlgorithm: args?.algorithm || args?.a || "pq2025",
        agentName: args?.name || args?.n || "OpenClaw JACS Agent",
        agentDescription: args?.description || args?.d || "OpenClaw agent with JACS cryptographic provenance",
        agentDomain: args?.domain,
        keyPassword: args?.password || args?.p || generateSecurePassword(),
    };
}
/**
 * Generate a cryptographically secure random password
 */
function generateSecurePassword() {
    return crypto.randomBytes(32).toString("base64");
}
//# sourceMappingURL=setup.js.map