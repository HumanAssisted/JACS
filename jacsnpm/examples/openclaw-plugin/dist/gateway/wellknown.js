"use strict";
/**
 * JACS Gateway Methods
 *
 * Serves .well-known endpoints for JACS agent discovery.
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
exports.registerGatewayMethods = registerGatewayMethods;
const jacsnpm_1 = require("jacsnpm");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/**
 * Register gateway methods for well-known endpoints
 */
function registerGatewayMethods(api) {
    const homeDir = api.runtime.homeDir;
    const keysDir = path.join(homeDir, ".openclaw", "jacs_keys");
    // Serve /.well-known/jacs-pubkey.json
    api.registerGatewayMethod({
        method: "GET",
        path: "/.well-known/jacs-pubkey.json",
        handler: async (req, res) => {
            if (!api.runtime.jacs?.isInitialized()) {
                res.status(503).json({
                    error: "JACS not initialized",
                    message: "Run 'openclaw jacs init' to configure JACS",
                });
                return;
            }
            try {
                const config = api.config;
                const publicKeyPath = path.join(keysDir, "agent.public.pem");
                if (!fs.existsSync(publicKeyPath)) {
                    res.status(404).json({ error: "Public key not found" });
                    return;
                }
                const publicKey = fs.readFileSync(publicKeyPath, "utf-8");
                const publicKeyHash = (0, jacsnpm_1.hashString)(publicKey);
                res.setHeader("Content-Type", "application/json");
                res.setHeader("Cache-Control", "public, max-age=3600");
                res.json({
                    publicKey,
                    publicKeyHash,
                    algorithm: config.keyAlgorithm || "pq2025",
                    agentId: config.agentId,
                    timestamp: new Date().toISOString(),
                });
            }
            catch (err) {
                api.logger.error(`Failed to serve public key: ${err.message}`);
                res.status(500).json({ error: err.message });
            }
        },
    });
    // POST /jacs/verify - Public verification endpoint
    api.registerGatewayMethod({
        method: "POST",
        path: "/jacs/verify",
        handler: async (req, res) => {
            if (!api.runtime.jacs?.isInitialized()) {
                res.status(503).json({ error: "JACS not initialized" });
                return;
            }
            try {
                if (!req.body) {
                    res.status(400).json({ error: "Request body required" });
                    return;
                }
                const agent = api.runtime.jacs?.getAgent();
                if (!agent) {
                    res.status(503).json({ error: "JACS not initialized" });
                    return;
                }
                const result = agent.verifyResponse(JSON.stringify(req.body));
                res.json(result);
            }
            catch (err) {
                res.status(400).json({ error: err.message });
            }
        },
    });
    // POST /jacs/sign - Authenticated signing endpoint
    api.registerGatewayMethod({
        method: "POST",
        path: "/jacs/sign",
        requireAuth: true,
        handler: async (req, res) => {
            if (!api.runtime.jacs?.isInitialized()) {
                res.status(503).json({ error: "JACS not initialized" });
                return;
            }
            try {
                if (!req.body?.document) {
                    res.status(400).json({ error: "document field required in request body" });
                    return;
                }
                const agent = api.runtime.jacs?.getAgent();
                if (!agent) {
                    res.status(503).json({ error: "JACS not initialized" });
                    return;
                }
                const signed = agent.signRequest(req.body.document);
                res.json(JSON.parse(signed));
            }
            catch (err) {
                res.status(400).json({ error: err.message });
            }
        },
    });
    // GET /jacs/status - Health check endpoint
    api.registerGatewayMethod({
        method: "GET",
        path: "/jacs/status",
        handler: async (req, res) => {
            const config = api.config;
            const initialized = api.runtime.jacs?.isInitialized() || false;
            res.json({
                initialized,
                agentId: config.agentId || null,
                algorithm: config.keyAlgorithm || null,
                timestamp: new Date().toISOString(),
            });
        },
    });
}
//# sourceMappingURL=wellknown.js.map