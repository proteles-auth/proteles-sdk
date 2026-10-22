//! Pure URL builders for the BFF's `/api/auth/*` endpoints. Free of Svelte and
//! the DOM so they are trivially unit-testable.

import type { SignInOptions, SignOutOptions, SignUpOptions } from "./types.js";

export const DEFAULT_BASE_PATH = "/api/auth";

function stripTrailingSlash(path: string): string {
  return path.replace(/\/+$/, "");
}

/** Resolves the BFF mount path: an explicit value, else
 *  `VITE_PROTELES_BASE_PATH` (Vite/Nuxt public-env convention), else
 *  `/api/auth`. */
export function resolveBasePath(explicit?: string): string {
  if (explicit) return stripTrailingSlash(explicit);
  const fromEnv =
    typeof process !== "undefined" ? process.env?.["VITE_PROTELES_BASE_PATH"] : undefined;
  return stripTrailingSlash(fromEnv || DEFAULT_BASE_PATH);
}

export function meUrl(basePath: string): string {
  return `${basePath}/me`;
}

/** `{basePath}/{action}`, with the parameters that are set as its query. One
 *  builder, so that the routes cannot come to encode `returnTo` differently. */
function actionUrl(basePath: string, action: string, params: Record<string, string | undefined>): string {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (value) query.set(name, value);
  }
  const qs = query.toString();
  return `${basePath}/${action}${qs ? `?${qs}` : ""}`;
}

export function loginUrl(basePath: string, options?: SignInOptions): string {
  return actionUrl(basePath, "login", { returnTo: options?.returnTo, connection: options?.connection });
}

export function signupUrl(basePath: string, options?: SignUpOptions): string {
  return actionUrl(basePath, "signup", { returnTo: options?.returnTo });
}

export function logoutUrl(basePath: string, options?: SignOutOptions): string {
  return actionUrl(basePath, "logout", { returnTo: options?.returnTo });
}
