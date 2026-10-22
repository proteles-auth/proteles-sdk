//! Tests for the framework-request adapter shared by @proteles/vue and
//! @proteles/solid (Nuxt and SolidStart both hand handlers h3 events).

import { test } from "node:test";
import assert from "node:assert/strict";

import { contextOf, readSetCookies, sendNodeResponse, toWebRequest } from "../src/request.ts";

/** An h3-style event backed by a Node-like request. */
function h3Event(url: string, init?: { method?: string; cookie?: string; headers?: Record<string, string> }) {
  const parsed = new URL(url);
  return {
    node: {
      req: {
        method: init?.method ?? "GET",
        url: `${parsed.pathname}${parsed.search}`,
        headers: {
          host: parsed.host,
          ...(init?.cookie ? { cookie: init.cookie } : {}),
          ...(init?.headers ?? {}),
        } as Record<string, string | string[] | undefined>,
      },
    },
    context: {} as Record<string, unknown>,
  };
}

test("accepts a Web Request unchanged", () => {
  const req = new Request("https://app.example.com/api/auth/me");
  assert.equal(toWebRequest(req), req);
});

test("unwraps { request } and { web: { request } }", () => {
  const req = new Request("https://app.example.com/x");
  assert.equal(toWebRequest({ request: req }), req);
  assert.equal(toWebRequest({ web: { request: req } }), req);
});

test("reconstructs URL, method, and headers from a Node request", () => {
  const out = toWebRequest(
    h3Event("https://app.example.com/api/auth/login?returnTo=/dash", { method: "POST", cookie: "a=1" }),
  );
  assert.equal(out.method, "POST");
  assert.equal(out.url, "http://app.example.com/api/auth/login?returnTo=/dash");
  assert.equal(out.headers.get("cookie"), "a=1");
});

test("honors x-forwarded-proto and x-forwarded-host (behind a proxy)", () => {
  const out = toWebRequest(
    h3Event("http://internal:3000/api/auth/me", {
      headers: { "x-forwarded-proto": "https, http", "x-forwarded-host": "app.example.com" },
    }),
  );
  assert.equal(new URL(out.url).origin, "https://app.example.com", "uses the first forwarded proto and host");
});

test("joins repeated headers rather than dropping them", () => {
  const event = h3Event("https://app.example.com/x");
  event.node.req.headers["cookie"] = ["a=1", "b=2"];
  assert.equal(toWebRequest(event).headers.get("cookie"), "a=1; b=2");
});

test("falls back to localhost when no host header is present", () => {
  const event = h3Event("https://app.example.com/x");
  delete event.node.req.headers["host"];
  assert.equal(new URL(toWebRequest(event).url).host, "localhost");
});

test("fails loudly on an unsupported shape", () => {
  assert.throws(() => toWebRequest({} as never), /could not derive a Request/);
});

test("contextOf exposes an h3 event's context bag, and undefined otherwise", () => {
  const event = h3Event("https://app.example.com/x");
  event.context["k"] = "v";
  assert.deepEqual(contextOf(event), { k: "v" });
  assert.equal(contextOf(new Request("https://app.example.com/x")), undefined);
});

// --- sending a Response to a Node ServerResponse -------------------------

/** A minimal ServerResponse double. */
function nodeRes() {
  const headers: Record<string, string | string[]> = {};
  let body: string | undefined;
  let ended = false;
  return {
    statusCode: 0,
    setHeader(name: string, value: string | string[]) {
      headers[name.toLowerCase()] = value;
    },
    end(chunk?: string) {
      body = chunk;
      ended = true;
    },
    get headers() {
      return headers;
    },
    get body() {
      return body;
    },
    get ended() {
      return ended;
    },
  };
}

test("sendNodeResponse copies status, headers, and body", async () => {
  const res = nodeRes();
  await sendNodeResponse(
    res,
    new Response(JSON.stringify({ ok: true }), {
      status: 201,
      headers: { "content-type": "application/json" },
    }),
  );
  assert.equal(res.statusCode, 201);
  assert.equal(res.headers["content-type"], "application/json");
  assert.equal(res.body, '{"ok":true}');
  assert.ok(res.ended);
});

test("sendNodeResponse sends multiple Set-Cookie values as separate lines", async () => {
  // One comma-joined value would make browsers accept only the first cookie —
  // and the auth callback sets two (session + clearing the flow cookie).
  const headers = new Headers();
  headers.append("set-cookie", "proteles_session=abc; Path=/; HttpOnly");
  headers.append("set-cookie", "proteles_flow=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
  const res = nodeRes();
  await sendNodeResponse(res, new Response(null, { status: 303, headers }));

  const cookies = res.headers["set-cookie"];
  assert.ok(Array.isArray(cookies), "set-cookie must be an array of values");
  assert.equal(cookies.length, 2, `expected 2 cookies, got ${JSON.stringify(cookies)}`);
  assert.ok(cookies.some((c) => c.startsWith("proteles_session=abc")));
  assert.ok(
    cookies.some((c) => c.startsWith("proteles_flow=") && /Expires=Thu, 01 Jan 1970/.test(c)),
    "the Expires comma must not split a cookie",
  );
});

test("sendNodeResponse handles an empty body without sending 'undefined'", async () => {
  const res = nodeRes();
  await sendNodeResponse(res, new Response(null, { status: 303, headers: { location: "/" } }));
  assert.equal(res.statusCode, 303);
  assert.equal(res.headers["location"], "/");
  assert.equal(res.body, undefined, "no body written for an empty response");
});

test("readSetCookies returns each cookie, and an empty list when there are none", () => {
  const headers = new Headers();
  assert.deepEqual(readSetCookies(headers), []);
  headers.append("set-cookie", "a=1");
  headers.append("set-cookie", "b=2; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
  assert.deepEqual(readSetCookies(headers).length, 2);
});

test("toWebRequest never throws on what a client sent", () => {
  // Each of these threw inside an async handler that Express 4 and plain
  // node:http leave unhandled, and Node exits on an unhandled rejection.
  const make = (req: { method?: string; url?: string; headers: Record<string, string | string[] | undefined> }) =>
    toWebRequest({ node: { req } });

  const trace = make({ method: "TRACE", url: "/", headers: { host: "app.example.com" } });
  assert.equal(trace.method, "GET", "a method the Fetch API forbids is served as a GET");
  assert.doesNotThrow(() => make({ method: "CONNECT", url: "app.example.com:443", headers: { host: "app.example.com" } }));
  assert.doesNotThrow(() => make({ method: "GET", url: "/", headers: { host: "a b" } }));
  assert.doesNotThrow(() => make({ method: "GET", url: "//", headers: { host: "app.example.com" } }));
  assert.doesNotThrow(() => make({ method: "GET", url: "/", headers: { host: "app.example.com", ":authority": "x" } }));

  // The control: an ordinary request is carried through as it came.
  const ok = make({ method: "POST", url: "/api/auth/logout?x=1", headers: { host: "app.example.com" } });
  assert.equal(ok.method, "POST");
  assert.equal(ok.url, "http://app.example.com/api/auth/logout?x=1");
});
