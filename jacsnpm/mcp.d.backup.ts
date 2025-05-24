import { McpServer } from "@modelcontextprotocol/sdk/server/mcp";
import { Client } from "@modelcontextprotocol/sdk/client/index";

export interface JacsOptions {
    configPath?: string;
}

export interface JacsServerOptions extends JacsOptions {
    name: string;
    version: string;
}

export interface JacsClientOptions extends JacsServerOptions {
    url: string;
}

export function createJacsTransport(transport: any, options?: JacsOptions): any;

export class JacsMcpServer extends McpServer {
    constructor(options: JacsServerOptions);
}

export class JacsMcpClient extends Client {
    constructor(options: JacsClientOptions);
}