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

import * as jacs from "jacsnpm";
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
  signDocument: (doc: any) => string;
  verifyDocument: (doc: string) => any;
  getAgentId: () => string | undefined;
  getPublicKey: () => string;
}

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
      jacs.load(configPath);
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
    signDocument: (doc: any) => jacs.signRequest(doc),
    verifyDocument: (doc: string) => jacs.verifyResponse(doc),
    getAgentId: () => currentAgentId,
    getPublicKey: () => publicKeyContent || "",
  };

  logger.debug("JACS plugin registered");
}

// Export utilities for direct use
export { jacs };
export { setupCommand } from "./setup";
export { cliCommands } from "./cli";
export { registerTools } from "./tools";
export { registerGatewayMethods } from "./gateway/wellknown";
