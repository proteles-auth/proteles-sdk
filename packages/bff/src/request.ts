//! Normalizing framework request objects to a Web `Request`.
//!
//! Next.js and SvelteKit hand handlers a Web `Request` (or something wrapping
//! one), but the Nitro/h3 family — Nuxt and SolidStart — hands over an h3 event
//! backed by a Node `IncomingMessage`. This adapter accepts any of those shapes
//! so the framework packages can share one implementation.

/** The Node request fields we read when converting an h3 event. */
export interface NodeRequestLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
}

/** Anything this module can normalize: a Web `Request`, an h3 event
 *  (`.node.req` or `.web.request`), or anything else exposing `.request`. */
export type RequestSource =
  | Request
  | { request: Request; context?: Record<string, unknown> }
  | { web: { request: Request }; context?: Record<string, unknown> }
  | { node: { req: NodeRequestLike }; context?: Record<string, unknown> };

function isRequest(value: unknown): value is Request {
  return typeof Request !== "undefined" && value instanceof Request;
}

/**
 * Normalizes any supported source to a Web `Request`.
 *
 * Note: the auth endpoints are driven entirely by the URL, method, and cookie
 * header — none of them reads a request body — so converting from a Node
 * request without streaming its body is correct here, and leaves a body the
 * framework may still need downstream intact.
 */
export function toWebRequest(source: RequestSource): Request {
  if (isRequest(source)) return source;

  const candidate = source as {
    request?: Request;
    web?: { request?: Request };
    node?: { req: NodeRequestLike };
  };
  if (candidate.request && isRequest(candidate.request)) return candidate.request;
  if (candidate.web?.request && isRequest(candidate.web.request)) return candidate.web.request;

  const req = candidate.node?.req;
  if (!req) {
    throw new Error("@proteles/bff: could not derive a Request from the given event");
  }

  // **Nothing here throws on what a client sent.** This runs on every request,
  // before any auth route, inside async handlers — and Express 4 and plain
  // `node:http` servers drop a rejected promise, which Node then turns into a
  // process exit. A malformed Host, a TRACE, or a header name the Fetch API
  // refuses each took the whole app down with one request. What cannot be
  // represented is replaced with something inert instead.
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    try {
      headers.set(key, Array.isArray(value) ? value.join("; ") : value);
    } catch {
      // An HTTP/2 pseudo-header (`:authority`) or a value the Fetch API
      // refuses: not one the auth routes read.
    }
  }

  const forwardedProto = headers.get("x-forwarded-proto");
  const proto = forwardedProto?.split(",")[0]?.trim() || "http";
  const host = headers.get("x-forwarded-host") || headers.get("host") || "localhost";
  let url: URL;
  try {
    url = new URL(req.url || "/", `${proto}://${host}`);
  } catch {
    // An unparseable Host or target. The auth routes build every URL they
    // send anywhere from configuration, so this origin is never echoed; the
    // request is simply not one of theirs.
    url = new URL("http://localhost/");
  }

  // The Fetch API refuses these three outright. The auth routes do not branch
  // on the method, so serving one as a GET grants nothing a GET would not.
  const requested = (req.method || "GET").toUpperCase();
  const method = FORBIDDEN_METHODS.has(requested) ? "GET" : req.method || "GET";

  return new Request(url.toString(), { method, headers });
}

/** Methods `new Request` throws on (Fetch standard, "forbidden method"). */
const FORBIDDEN_METHODS = new Set(["CONNECT", "TRACE", "TRACK"]);

/** Reads `event.context` when the source exposes one (h3 events do). */
export function contextOf(source: RequestSource): Record<string, unknown> | undefined {
  return (source as { context?: Record<string, unknown> }).context;
}

/** The Node response fields we write when sending a Web `Response`. */
export interface NodeResponseLike {
  statusCode: number;
  setHeader: (name: string, value: string | string[]) => void;
  end: (chunk?: string) => void;
}

/**
 * Writes a Web `Response` to a Node `ServerResponse`, so a plain `node:http`
 * server (or Express, or anything else Node-native) can serve the auth routes:
 *
 * ```js
 * const response = await app.handle(toWebRequest({ node: { req } }));
 * await sendNodeResponse(res, response);
 * ```
 *
 * `Set-Cookie` needs care: a `Response` can carry several, and they must be sent
 * as separate header lines rather than one comma-joined value, or browsers will
 * accept only the first. `Headers.getSetCookie()` gives the list where available
 * (Node 18.14+), with a split fallback for older runtimes.
 */
export async function sendNodeResponse(res: NodeResponseLike, response: Response): Promise<void> {
  res.statusCode = response.status;

  const setCookies = readSetCookies(response.headers);
  if (setCookies.length > 0) res.setHeader("set-cookie", setCookies);

  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") return; // handled above
    res.setHeader(key, value);
  });

  const body = await response.text();
  res.end(body.length > 0 ? body : undefined);
}

/** Every `Set-Cookie` value on a `Headers`, as separate entries. */
export function readSetCookies(headers: Headers): string[] {
  const withGetter = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof withGetter.getSetCookie === "function") return withGetter.getSetCookie();
  const merged = headers.get("set-cookie");
  // Split only at a comma that starts a new `name=` pair, so the comma inside an
  // `Expires=Thu, 01 Jan …` attribute is not treated as a boundary.
  return merged ? merged.split(/,\s*(?=[A-Za-z0-9_-]+=)/) : [];
}
