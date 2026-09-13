import { timingSafeEqual } from "node:crypto";
import { ApiProblem } from "./errors.js";

export type ApiScope =
  | "receipts:write"
  | "defenses:write"
  | "safety:write"
  | "cre:write"
  | "replays:write"
  | "validators:read"
  | "validators:write";

export interface ApiPrincipal {
  subject: string;
  tenantId: string;
  scopes: readonly ApiScope[];
}

export interface ApiAuthenticator {
  authenticate(authorization: string | null): ApiPrincipal;
}

export interface StaticApiKey {
  token: string;
  principal: ApiPrincipal;
}

function equalToken(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export class StaticApiKeyAuthenticator implements ApiAuthenticator {
  constructor(private readonly keys: readonly StaticApiKey[]) {
    if (keys.some((key) => key.token.length < 16)) throw new Error("API keys must contain at least 16 characters");
  }

  authenticate(authorization: string | null): ApiPrincipal {
    if (!authorization?.startsWith("Bearer ")) {
      throw new ApiProblem(401, "authentication-required", "Authentication required", "A Bearer API key is required.");
    }
    const token = authorization.slice("Bearer ".length);
    const match = this.keys.find((key) => equalToken(token, key.token));
    if (!match) throw new ApiProblem(401, "invalid-credentials", "Invalid credentials", "The supplied API key is invalid.");
    return structuredClone(match.principal);
  }
}

export function requireScope(principal: ApiPrincipal, scope: ApiScope): void {
  if (!principal.scopes.includes(scope)) {
    throw new ApiProblem(403, "insufficient-scope", "Insufficient scope", `The ${scope} scope is required.`);
  }
}
