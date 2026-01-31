/**
 * JACS Gateway Methods
 *
 * Serves .well-known endpoints for JACS agent discovery.
 */

import { hashString } from "jacsnpm";
import * as fs from "fs";
import * as path from "path";
import type { OpenClawPluginAPI } from "../index";

export interface GatewayRequest {
  method: string;
  path: string;
  body?: any;
  headers?: Record<string, string>;
  query?: Record<string, string>;
}

export interface GatewayResponse {
  status: (code: number) => GatewayResponse;
  json: (data: any) => void;
  send: (data: string) => void;
  setHeader: (name: string, value: string) => void;
}

/**
 * Register gateway methods for well-known endpoints
 */
export function registerGatewayMethods(api: OpenClawPluginAPI): void {
  const homeDir = api.runtime.homeDir;
  const keysDir = path.join(homeDir, ".openclaw", "jacs_keys");

  // Serve /.well-known/jacs-pubkey.json
  api.registerGatewayMethod({
    method: "GET",
    path: "/.well-known/jacs-pubkey.json",
    handler: async (req: GatewayRequest, res: GatewayResponse) => {
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
        const publicKeyHash = hashString(publicKey);

        res.setHeader("Content-Type", "application/json");
        res.setHeader("Cache-Control", "public, max-age=3600");
        res.json({
          publicKey,
          publicKeyHash,
          algorithm: config.keyAlgorithm || "pq2025",
          agentId: config.agentId,
          timestamp: new Date().toISOString(),
        });
      } catch (err: any) {
        api.logger.error(`Failed to serve public key: ${err.message}`);
        res.status(500).json({ error: err.message });
      }
    },
  });

  // POST /jacs/verify - Public verification endpoint
  api.registerGatewayMethod({
    method: "POST",
    path: "/jacs/verify",
    handler: async (req: GatewayRequest, res: GatewayResponse) => {
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
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    },
  });

  // POST /jacs/sign - Authenticated signing endpoint
  api.registerGatewayMethod({
    method: "POST",
    path: "/jacs/sign",
    requireAuth: true,
    handler: async (req: GatewayRequest, res: GatewayResponse) => {
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
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    },
  });

  // GET /jacs/status - Health check endpoint
  api.registerGatewayMethod({
    method: "GET",
    path: "/jacs/status",
    handler: async (req: GatewayRequest, res: GatewayResponse) => {
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
