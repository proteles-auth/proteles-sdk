import { test } from "node:test";
import assert from "node:assert/strict";

import {
  HX_REDIRECT_HEADER,
  htmxLocation,
  htmxRedirect,
  isBoosted,
  isHtmxRequest,
  toHtmxResponse,
  withHtmxTrigger,
} from "../src/htmx.ts";

const htmxRequest = (extra: Record<string, string> = {}) =>
  new Request("https://app.example.com/x", { headers: { "hx-request": "true", ...extra } });

test("isHtmxRequest detects the HX-Request header on a Web Request", () => {
  assert.equal(isHtmxRequest(htmxRequest()), true);
  assert.equal(isHtmxRequest(new Request("https://app.example.com/x")), false, "a normal request is not htmx");
});

test("isHtmxRequest reads Headers, { headers }, and a Node-style event", () => {
  assert.equal(isHtmxRequest(new Headers({ "hx-request": "true" })), true);
  assert.equal(isHtmxRequest({ headers: new Headers({ "hx-request": "true" }) }), true);
  assert.equal(isHtmxRequest({ headers: { "hx-request": "true" } }), true, "plain Node header bag");
  assert.equal(isHtmxRequest({ node: { req: { headers: { "hx-request": "true" } } } }), true, "h3-style event");
  assert.equal(isHtmxRequest({ node: { req: { headers: {} } } }), false);
});

test("isHtmxRequest tolerates array header values and is case-insensitive on the name", () => {
  assert.equal(isHtmxRequest({ headers: { "hx-request": ["true", "true"] } }), true);
});

test("a boosted navigation is still an htmx request", () => {
  // hx-boost sends HX-Request too, and needs the same redirect handling: it's an
  // XHR that would otherwise swap a login page into the body.
  const boosted = htmxRequest({ "hx-boosted": "true" });
  assert.equal(isHtmxRequest(boosted), true);
  assert.equal(isBoosted(boosted), true);
  assert.equal(isBoosted(htmxRequest()), false);
});

test("htmxRedirect returns 200 with HX-Redirect — not a 3xx", () => {
  const res = htmxRedirect("/dashboard");
  // 200 is the point: htmx only reads HX-Redirect on a successful response, and
  // XHR would silently follow a 3xx before htmx ever saw the header.
  assert.equal(res.status, 200);
  assert.equal(res.headers.get(HX_REDIRECT_HEADER), "/dashboard");
  assert.equal(res.headers.get("location"), null, "no Location, so nothing follows it");
});

test("htmxLocation sets HX-Location for a client-side navigation", () => {
  const res = htmxLocation("/settings");
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("hx-location"), "/settings");
});

test("withHtmxTrigger adds a plain event name, or a JSON payload with detail", () => {
  const plain = withHtmxTrigger(new Response("ok"), "proteles:signed-in");
  assert.equal(plain.headers.get("hx-trigger"), "proteles:signed-in");

  const detailed = withHtmxTrigger(new Response("ok"), "proteles:signed-in", { sub: "u1" });
  assert.deepEqual(JSON.parse(detailed.headers.get("hx-trigger")!), { "proteles:signed-in": { sub: "u1" } });
});

test("withHtmxTrigger preserves the original status and body", async () => {
  const res = withHtmxTrigger(new Response("<p>hi</p>", { status: 201 }), "evt");
  assert.equal(res.status, 201);
  assert.equal(await res.text(), "<p>hi</p>");
});

// --- the conversion that makes the shared BFF safe for htmx ---------------

test("toHtmxResponse rewrites a redirect to HX-Redirect for htmx callers", () => {
  const redirect = new Response(null, { status: 302, headers: { location: "/api/auth/login" } });
  const converted = toHtmxResponse(redirect, htmxRequest());

  assert.equal(converted.status, 200, "no longer a redirect XHR would follow");
  assert.equal(converted.headers.get(HX_REDIRECT_HEADER), "/api/auth/login");
  assert.equal(converted.headers.get("location"), null, "Location removed");
});

test("toHtmxResponse leaves a redirect alone for a normal browser request", () => {
  const redirect = new Response(null, { status: 303, headers: { location: "/" } });
  const untouched = toHtmxResponse(redirect, new Request("https://app.example.com/x"));

  assert.equal(untouched.status, 303, "a full page load still gets a real redirect");
  assert.equal(untouched.headers.get("location"), "/");
});

test("toHtmxResponse preserves Set-Cookie — the login and callback responses need it", () => {
  // The login response carries both a redirect and the encrypted flow cookie; the
  // callback carries the session cookie plus a flow-clear. Dropping either would
  // break the flow silently.
  const headers = new Headers({ location: "https://auth.example.com/oauth/authorize" });
  headers.append("set-cookie", "proteles_flow=abc; Path=/; HttpOnly");
  headers.append("set-cookie", "other=1; Path=/");
  const converted = toHtmxResponse(new Response(null, { status: 302, headers }), htmxRequest());

  const withGetter = converted.headers as Headers & { getSetCookie?: () => string[] };
  const cookies =
    typeof withGetter.getSetCookie === "function"
      ? withGetter.getSetCookie()
      : (converted.headers.get("set-cookie") ?? "").split(/,\s*(?=[A-Za-z0-9_-]+=)/);
  assert.equal(cookies.length, 2, `both cookies survive, got ${JSON.stringify(cookies)}`);
  assert.ok(cookies.some((c) => c.startsWith("proteles_flow=abc")));
  assert.equal(converted.headers.get(HX_REDIRECT_HEADER), "https://auth.example.com/oauth/authorize");
});

test("toHtmxResponse passes non-redirects straight through", async () => {
  const json = new Response('{"authenticated":false}', { status: 200, headers: { "content-type": "application/json" } });
  const out = toHtmxResponse(json, htmxRequest());
  assert.equal(out.status, 200);
  assert.equal(await out.text(), '{"authenticated":false}', "body intact");

  const notFound = toHtmxResponse(new Response("nope", { status: 404 }), htmxRequest());
  assert.equal(notFound.status, 404);
});

test("toHtmxResponse ignores a 3xx that carries no Location", () => {
  const weird = new Response(null, { status: 304 });
  assert.equal(toHtmxResponse(weird, htmxRequest()).status, 304);
});
