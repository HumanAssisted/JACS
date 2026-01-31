/**
 * JACS OpenClaw Plugin
 *
 * Provides post-quantum cryptographic signatures for agent communications.
 *
 * Core Features:
 * - Key generation and secure storage
 * - Document signing and verification
 * - Public key endpoint for discovery
 */

import { JacsAgent, hashString, verifyString, createConfig } from "jacsnpm";
import { setupCommand } from "./setup";
import { cliCommands } from "./cli";
import { registerGatewayMethods } from "./gateway/wellknown";
import { registerTools } from "./tools";
import * as path from "path";
import * as fs from "fs";

export interface JACSPluginConfig {
  keyAlgorithm: string;
  autoSign: boolean;
  autoVerify: boolean;
  agentName?: string;
  agentDescription?: string;
  agentDomain?: string;
  agentId?: string;
}

export interface OpenClawPluginAPI {
  config: JACSPluginConfig;
  logger: {
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
    debug: (msg: string) => void;
  };
  runtime: {
    homeDir: string;
    fs: typeof fs;
    jacs?: JACSRuntime;
  };
  registerCli: (opts: any) => void;
  registerCommand: (opts: any) => void;
  registerTool: (opts: any) => void;
  registerGatewayMethod: (opts: any) => void;
  updateConfig: (update: Partial<JACSPluginConfig>) => void;
  invoke: (command: string, args: any) => Promise<any>;
}

export interface JACSRuntime {
  isInitialized: () => boolean;
  getAgent: () => JacsAgent | null;
  signDocument: (doc: any) => string;
  verifyDocument: (doc: string) => any;
  getAgentId: () => string | undefined;
  getPublicKey: () => string;
}

// Agent instance (replaces deprecated global singleton)
let agentInstance: JacsAgent | null = null;
let isInitialized = false;
let currentAgentId: string | undefined;
let publicKeyContent: string | undefined;

/**
 * Main plugin registration function called by OpenClaw
 */
export default function register(api: OpenClawPluginAPI): void {
  const config = api.config;
  const logger = api.logger;

  // Determine JACS directories
  const jacsDir = path.join(api.runtime.homeDir, ".openclaw", "jacs");
  const keysDir = path.join(api.runtime.homeDir, ".openclaw", "jacs_keys");
  const configPath = path.join(jacsDir, "jacs.config.json");

  // Try to initialize JACS if config exists
  if (fs.existsSync(configPath)) {
    try {
      // Use JacsAgent class instead of deprecated global load()
      agentInstance = new JacsAgent();
      agentInstance.load(configPath);
      currentAgentId = config.agentId;

      // Load public key
      const pubKeyPath = path.join(keysDir, "agent.public.pem");
      if (fs.existsSync(pubKeyPath)) {
        publicKeyContent = fs.readFileSync(pubKeyPath, "utf-8");
      }

      isInitialized = true;
      logger.info("JACS initialized successfully");
    } catch (err: any) {
      logger.warn(`JACS not initialized - run 'openclaw jacs init': ${err.message}`);
      agentInstance = null;
    }
  } else {
    logger.info("JACS not configured - run 'openclaw jacs init' to set up");
  }

  // Register CLI commands
  api.registerCli({
    name: "jacs",
    description: "JACS cryptographic provenance commands",
    subcommands: cliCommands(api),
  });

  // Register setup/init command
  api.registerCommand({
    name: "jacs-init",
    description: "Initialize JACS with key generation and agent creation",
    handler: setupCommand(api),
  });

  // Register agent tools for AI use
  registerTools(api);

  // Register gateway methods for well-known endpoints
  registerGatewayMethods(api);

  // Expose JACS runtime for other plugins
  api.runtime.jacs = {
    isInitialized: () => isInitialized,
    getAgent: () => agentInstance,
    signDocument: (doc: any) => {
      if (!agentInstance) throw new Error("JACS not initialized");
      return agentInstance.signRequest(doc);
    },
    verifyDocument: (doc: string) => {
      if (!agentInstance) throw new Error("JACS not initialized");
      return agentInstance.verifyResponse(doc);
    },
    getAgentId: () => currentAgentId,
    getPublicKey: () => publicKeyContent || "",
  };

  logger.debug("JACS plugin registered");
}

// Re-export for use by other modules
export { JacsAgent, hashString, verifyString, createConfig };

// Export internal state accessor for reinit after setup
export function setAgentInstance(agent: JacsAgent, agentId: string, publicKey: string): void {
  agentInstance = agent;
  currentAgentId = agentId;
  publicKeyContent = publicKey;
  isInitialized = true;
}

export { setupCommand } from "./setup";
export { cliCommands } from "./cli";
export { registerTools } from "./tools";
export { registerGatewayMethods } from "./gateway/wellknown";
