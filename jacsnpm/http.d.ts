// Define JacsOptions if not already defined elsewhere
interface JacsOptions {
  configPath: string;
}

// For Koa
export function JACSKoaMiddleware(options: JacsOptions): (ctx: any, next: () => Promise<void>) => Promise<void>;

// For Express
export function JACSExpressMiddleware(options: JacsOptions): (req: any, res: any, next: () => Promise<void>) => Promise<void>;

// You can keep the old one if it's still used or remove it
// export function createJacsMiddleware(options?: JacsOptions): (ctx: any, next: () => Promise<void>) => Promise<void>;
