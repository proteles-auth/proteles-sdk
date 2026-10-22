//! Minimal cookie parsing + serialization. We manage `Set-Cookie` by hand
//! (rather than relying on a framework's cookie jar) so the same code runs as
//! a Next route handler, as Edge middleware, or against a plain `Request`.

export interface CookieOptions {
  maxAge?: number; // seconds; 0 clears
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "lax" | "strict" | "none";
}

/** Parses a `Cookie` request header into a name→value map. */
export function parseCookies(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (!name) continue;
    // A value that is not valid percent-encoding is kept as it arrived rather
    // than thrown on. The header carries every cookie on the domain, not only
    // ours, and `decodeURIComponent("%")` threw from inside an async handler
    // nothing caught — one request of a few bytes took a Node process down.
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

/** Builds a `Set-Cookie` header value. */
export function serializeCookie(name: string, value: string, opts: CookieOptions = {}): string {
  const segments = [`${name}=${encodeURIComponent(value)}`];
  segments.push(`Path=${opts.path ?? "/"}`);
  if (opts.httpOnly ?? true) segments.push("HttpOnly");
  if (opts.secure ?? true) segments.push("Secure");
  segments.push(`SameSite=${capitalize(opts.sameSite ?? "lax")}`);
  if (opts.maxAge !== undefined) {
    segments.push(`Max-Age=${Math.floor(opts.maxAge)}`);
    // Include a matching Expires so clearing (Max-Age=0) is honored by older
    // clients too.
    if (opts.maxAge <= 0) segments.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT");
  }
  return segments.join("; ");
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
