/**
 * JACS Setup Wizard
 *
 * Interactive setup for generating keys and creating agent identity.
 */
import type { OpenClawPluginAPI } from "./index";
export interface SetupOptions {
    keyAlgorithm: string;
    agentName: string;
    agentDescription: string;
    agentDomain?: string;
    keyPassword: string;
}
export interface SetupResult {
    text: string;
    agentId?: string;
    configPath?: string;
    error?: string;
}
/**
 * Creates the setup command handler
 */
export declare function setupCommand(api: OpenClawPluginAPI): (ctx: any) => Promise<SetupResult>;
//# sourceMappingURL=setup.d.ts.map