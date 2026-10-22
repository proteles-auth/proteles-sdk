import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ALPINE_REQUEST_HEADER,
  ALPINE_TARGET_HEADER,
  alpineTargets,
  escapeHtml,
  isAlpineRequest,
  signInFragment,
} from "../src/alpine-ajax.ts";

const alpineRequest = (extra: Record<string, string> = {}) =>
  new Request("https://app.example.com/x", {
    headers: { [ALPINE_REQUEST_HEADER]: "true", ...extra },
  });

test("isAlpineRequest detects the X-Alpine-Request header on a Web Request", () => {
  assert.equal(isAlpineRequest(alpineRequest()), true);
  assert.equal(
    isAlpineRequest(new Request("https://app.example.com/x")),
    false,
    "a normal navigation is not an Alpine AJAX request",
  );
});

test("isAlpineRequest reads Headers, { headers }, and a Node-style event", () => {
  // The four shapes the BFF's adapters hand us. A helper that only understood
  // Web Requests would silently answer `false` on every Node framework, and
  // `false` here means "treat it as a navigation" — so the failure is a login
  // page merged into a fragment, which is the bug this package exists to avoid.
  assert.equal(isAlpineRequest(new Headers({ [ALPINE_REQUEST_HEADER]: "true" })), true);
  assert.equal(isAlpineRequest({ headers: new Headers({ [ALPINE_REQUEST_HEADER]: "true" }) }), true);
  assert.equal(isAlpineRequest({ headers: { [ALPINE_REQUEST_HEADER]: "true" } }), true, "Node header bag");
  assert.equal(
    isAlpineRequest({ node: { req: { headers: { [ALPINE_REQUEST_HEADER]: "true" } } } }),
    true,
    "h3-style event",
  );
  assert.equal(isAlpineRequest({ node: { req: { headers: {} } } }), false);
});

test("isAlpineRequest tolerates an array header value", () => {
  // Node's raw header bag gives an array when a header repeats.
  assert.equal(isAlpineRequest({ headers: { [ALPINE_REQUEST_HEADER]: ["true"] } }), true);
});

test("only the literal 'true' counts as an Alpine request", () => {
  // The header is attacker-supplied and the branch it selects changes the whole
  // response shape. "present" is not the test; the documented value is.
  for (const value of ["false", "TRUE", "1", "", "yes"]) {
    assert.equal(
      isAlpineRequest({ headers: { [ALPINE_REQUEST_HEADER]: value } }),
      false,
      `${JSON.stringify(value)} must not count`,
    );
  }
});

test("alpineTargets splits the space-separated id list", () => {
  assert.deepEqual(alpineTargets(alpineRequest({ [ALPINE_TARGET_HEADER]: "profile" })), ["profile"]);
  assert.deepEqual(
    alpineTargets(alpineRequest({ [ALPINE_TARGET_HEADER]: "profile  sidebar\tcount" })),
    ["profile", "sidebar", "count"],
    "any run of whitespace separates, and empties are dropped",
  );
  assert.deepEqual(alpineTargets(alpineRequest()), [], "no header means no targets");
});

test("signInFragment addresses every id the caller asked for", () => {
  // Alpine merges by id. A body that does not contain the requested id fires
  // `ajax:missing` and swaps nothing — which, to the person clicking, is
  // indistinguishable from the click doing nothing at all.
  const html = signInFragment(["profile", "sidebar"], { loginUrl: "/api/auth/login" });
  assert.match(html, /<div id="profile">/);
  assert.match(html, /<div id="sidebar">/);
  assert.match(html, /href="\/api\/auth\/login"/);
});

test("signInFragment's link carries no x-target", () => {
  // The one markup rule this package has, applied to the markup it generates
  // itself: leaving for the authorization server is a real navigation, and an
  // x-target here would fetch the sign-in page and merge it into the fragment —
  // reintroducing the exact bug, from inside the fix.
  const html = signInFragment(["profile"], { loginUrl: "/api/auth/login" });
  assert.ok(!html.includes("x-target"), html);
});

test("signInFragment falls back to a bare fragment for _top or no target", () => {
  // `_top` is Alpine's name for replacing the whole document, so wrapping the
  // body in a div with id "_top" would address an element that does not exist.
  const top = signInFragment(["_top"], { loginUrl: "/l" });
  assert.ok(!top.includes("id=\"_top\""), top);
  assert.match(top, /Sign in/);
  assert.match(signInFragment([], { loginUrl: "/l" }), /Sign in/);
});

test("a hostile X-Alpine-Target cannot inject markup", () => {
  // The header is attacker-controlled and is interpolated into HTML. Ids that
  // could not be Alpine targets anyway are dropped rather than escaped, which
  // removes the question instead of answering it.
  const html = signInFragment(
    ['x"><script>alert(1)</script><div id="y', "ok-id", "1-starts-with-a-digit", "a b"],
    { loginUrl: "/l" },
  );
  assert.ok(!html.includes("<script>"), html);
  assert.match(html, /<div id="ok-id">/);
  assert.ok(!html.includes("1-starts-with-a-digit"), "an id cannot start with a digit");
});

test("a hostile loginUrl cannot break out of the href", () => {
  const html = signInFragment(["profile"], { loginUrl: '/l" onmouseover="alert(1)' });
  assert.ok(!html.includes('onmouseover="alert(1)"'), html);
  assert.match(html, /&quot;/);
});

test("the copy is overridable, and escaped", () => {
  const html = signInFragment(["profile"], {
    loginUrl: "/l",
    message: "Session over <b>",
    linkText: "Log in & continue",
  });
  assert.match(html, /Session over &lt;b&gt;/);
  assert.match(html, /Log in &amp; continue/);
});

test("escapeHtml covers the five characters that matter", () => {
  assert.equal(escapeHtml(`&<>"'`), "&amp;&lt;&gt;&quot;&#39;");
});
