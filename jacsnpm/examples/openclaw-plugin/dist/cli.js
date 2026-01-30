"use strict";
/**
 * JACS CLI Commands for OpenClaw
 *
 * Provides command-line interface for JACS operations.
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
exports.cliCommands = cliCommands;
const jacs = __importStar(require("jacsnpm"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/**
 * Creates CLI commands for the JACS plugin
 */
function cliCommands(api) {
    const homeDir = api.runtime.homeDir;
    const jacsDir = path.join(homeDir, ".openclaw", "jacs");
    const keysDir = path.join(homeDir, ".openclaw", "jacs_keys");
    return {
        init: {
            description: "Initialize JACS with key generation",
            args: ["[--algorithm <algo>]", "[--name <name>]", "[--password <password>]"],
            handler: async (args) => {
                return api.invoke("jacs-init", args);
            },
        },
        status: {
            description: "Show JACS status and agent info",
            handler: async () => {
                const configPath = path.join(jacsDir, "jacs.config.json");
                if (!fs.existsSync(configPath)) {
                    return {
                        text: "JACS not initialized.\n\nRun 'openclaw jacs init' to set up.",
                    };
                }
                const config = api.config;
                let jacsConfig = {};
                try {
                    jacsConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
                }
                catch { }
                const pubKeyPath = path.join(keysDir, "agent.public.pem");
                const publicKeyExists = fs.existsSync(pubKeyPath);
                const publicKeyHash = publicKeyExists
                    ? jacs.hashString(fs.readFileSync(pubKeyPath, "utf-8"))
                    : "N/A";
                return {
                    text: `JACS Status: Active

Agent ID: ${config.agentId || jacsConfig.jacs_agent_id_and_version?.split(":")[0] || "Unknown"}
Algorithm: ${config.keyAlgorithm || jacsConfig.jacs_agent_key_algorithm || "Unknown"}
Name: ${config.agentName || "Not set"}
Description: ${config.agentDescription || "Not set"}
Domain: ${config.agentDomain || "Not set"}

Keys:
  Public Key: ${publicKeyExists ? "Present" : "Missing"}
  Public Key Hash: ${publicKeyHash.substring(0, 32)}...
  Private Key: ${fs.existsSync(path.join(keysDir, "agent.private.pem.enc")) ? "Encrypted" : "Missing"}

Config Path: ${configPath}`,
                };
            },
        },
        sign: {
            description: "Sign a document with JACS",
            args: ["<file>"],
            handler: async (args) => {
                if (!api.runtime.jacs?.isInitialized()) {
                    return { text: "JACS not initialized. Run 'openclaw jacs init' first." };
                }
                const filePath = args.file || args._?.[0];
                if (!filePath) {
                    return { text: "Usage: openclaw jacs sign <file>", error: "Missing file argument" };
                }
                try {
                    const content = fs.readFileSync(filePath, "utf-8");
                    let document;
                    try {
                        document = JSON.parse(content);
                    }
                    catch {
                        // If not JSON, wrap as text document
                        document = { content, type: "text" };
                    }
                    const signed = jacs.signRequest(document);
                    const parsed = JSON.parse(signed);
                    return {
                        text: JSON.stringify(parsed, null, 2),
                        data: parsed,
                    };
                }
                catch (err) {
                    return {
                        text: `Failed to sign document: ${err.message}`,
                        error: err.message,
                    };
                }
            },
        },
        verify: {
            description: "Verify a JACS-signed document",
            args: ["<file>"],
            handler: async (args) => {
                if (!api.runtime.jacs?.isInitialized()) {
                    return { text: "JACS not initialized. Run 'openclaw jacs init' first." };
                }
                const filePath = args.file || args._?.[0];
                if (!filePath) {
                    return { text: "Usage: openclaw jacs verify <file>", error: "Missing file argument" };
                }
                try {
                    const content = fs.readFileSync(filePath, "utf-8");
                    const result = jacs.verifyResponse(content);
                    if (result.error) {
                        return {
                            text: `Verification failed: ${result.error}`,
                            data: result,
                            error: result.error,
                        };
                    }
                    return {
                        text: `Signature verified!

Signer: ${result.jacsId || "Unknown"}
Valid: Yes`,
                        data: result,
                    };
                }
                catch (err) {
                    return {
                        text: `Verification failed: ${err.message}`,
                        error: err.message,
                    };
                }
            },
        },
        hash: {
            description: "Hash a string using JACS",
            args: ["<string>"],
            handler: async (args) => {
                const input = args.string || args._?.join(" ");
                if (!input) {
                    return { text: "Usage: openclaw jacs hash <string>", error: "Missing input" };
                }
                const hash = jacs.hashString(input);
                return {
                    text: hash,
                    data: { input, hash },
                };
            },
        },
        "dns-record": {
            description: "Generate DNS TXT record for agent discovery",
            args: ["<domain>"],
            handler: async (args) => {
                if (!api.runtime.jacs?.isInitialized()) {
                    return { text: "JACS not initialized. Run 'openclaw jacs init' first." };
                }
                const domain = args.domain || args._?.[0];
                if (!domain) {
                    return { text: "Usage: openclaw jacs dns-record <domain>", error: "Missing domain" };
                }
                try {
                    const config = api.config;
                    const pubKeyPath = path.join(keysDir, "agent.public.pem");
                    if (!fs.existsSync(pubKeyPath)) {
                        return { text: "Public key not found.", error: "Missing public key" };
                    }
                    const publicKey = fs.readFileSync(pubKeyPath, "utf-8");
                    const publicKeyHash = jacs.hashString(publicKey);
                    const agentId = config.agentId || "unknown";
                    const txtRecord = `v=hai.ai; jacs_agent_id=${agentId}; alg=SHA-256; enc=base64; jac_public_key_hash=${publicKeyHash}`;
                    const recordOwner = `_v1.agent.jacs.${domain}.`;
                    return {
                        text: `DNS TXT Record for ${domain}

Record Owner: ${recordOwner}
Record Type: TXT
TTL: 3600
Content:
  ${txtRecord}

Add this record to your DNS provider to enable agent discovery via DNSSEC.`,
                        data: {
                            owner: recordOwner,
                            type: "TXT",
                            ttl: 3600,
                            content: txtRecord,
                        },
                    };
                }
                catch (err) {
                    return {
                        text: `Failed to generate DNS record: ${err.message}`,
                        error: err.message,
                    };
                }
            },
        },
    };
}
//# sourceMappingURL=cli.js.map