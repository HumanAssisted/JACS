/**
 * JACS CLI Commands for OpenClaw
 *
 * Provides command-line interface for JACS operations.
 */
import type { OpenClawPluginAPI } from "./index";
export interface CLIResult {
    text: string;
    data?: any;
    error?: string;
}
export interface CLICommand {
    description: string;
    args?: string[];
    handler: (args: any) => Promise<CLIResult>;
}
export interface CLICommands {
    [key: string]: CLICommand;
}
/**
 * Creates CLI commands for the JACS plugin
 */
export declare function cliCommands(api: OpenClawPluginAPI): CLICommands;
//# sourceMappingURL=cli.d.ts.map