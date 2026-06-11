import type { RequestHandler, Request } from "express";

declare module "express-serve-static-core" {
  interface Request {
    csrfToken(): string;
  }
}

export interface CsrfCookieOptions {
  key?: string;
  path?: string;
  httpOnly?: boolean;
  sameSite?: "strict" | "lax" | "none" | boolean;
  secure?: boolean;
  maxAge?: number | null;
}

export interface CsrfOptions {
  secret: string;
  cookie?: CsrfCookieOptions;
  ignoreMethods?: string[];
  value?: (req: Request) => string | undefined;
  csrfParam?: string;
  perSessionTokens?: boolean;
}

declare function csrfProtection(options: CsrfOptions): RequestHandler;

export default csrfProtection;
