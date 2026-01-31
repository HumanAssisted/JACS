/**
 * JACS Gateway Methods
 *
 * Serves .well-known endpoints for JACS agent discovery.
 */
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
export declare function registerGatewayMethods(api: OpenClawPluginAPI): void;
//# sourceMappingURL=wellknown.d.ts.map