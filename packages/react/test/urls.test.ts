import { test } from "node:test";
import assert from "node:assert/strict";

import { DEFAULT_BASE_PATH, loginUrl, logoutUrl, meUrl, resolveBasePath, signupUrl } from "../src/urls.ts";

test("resolveBasePath defaults, honors an explicit path, and strips trailing slashes", () => {
  assert.equal(resolveBasePath(), DEFAULT_BASE_PATH);
  assert.equal(resolveBasePath("/auth"), "/auth");
  assert.equal(resolveBasePath("/auth/"), "/auth");
});

test("resolveBasePath reads NEXT_PUBLIC_PROTELES_BASE_PATH", () => {
  const prev = process.env["NEXT_PUBLIC_PROTELES_BASE_PATH"];
  process.env["NEXT_PUBLIC_PROTELES_BASE_PATH"] = "/custom/auth/";
  try {
    assert.equal(resolveBasePath(), "/custom/auth");
  } finally {
    if (prev === undefined) delete process.env["NEXT_PUBLIC_PROTELES_BASE_PATH"];
    else process.env["NEXT_PUBLIC_PROTELES_BASE_PATH"] = prev;
  }
});

test("meUrl", () => {
  assert.equal(meUrl("/api/auth"), "/api/auth/me");
});

test("loginUrl encodes returnTo and connection", () => {
  assert.equal(loginUrl("/api/auth"), "/api/auth/login");
  assert.equal(loginUrl("/api/auth", { returnTo: "/dashboard" }), "/api/auth/login?returnTo=%2Fdashboard");
  assert.equal(
    loginUrl("/api/auth", { returnTo: "/a", connection: "google" }),
    "/api/auth/login?returnTo=%2Fa&connection=google",
  );
});

test("signupUrl encodes returnTo, on the sign-up route, and nothing else", () => {
  assert.equal(signupUrl("/api/auth"), "/api/auth/signup");
  assert.equal(signupUrl("/api/auth", { returnTo: "/welcome?plan=pro" }), "/api/auth/signup?returnTo=%2Fwelcome%3Fplan%3Dpro");
  // A caller in plain JS can hand it signIn's options; the connection stays behind.
  const signInOptions = { returnTo: "/a", connection: "google" };
  assert.equal(signupUrl("/api/auth", signInOptions), "/api/auth/signup?returnTo=%2Fa");
});

test("logoutUrl encodes returnTo", () => {
  assert.equal(logoutUrl("/api/auth"), "/api/auth/logout");
  assert.equal(logoutUrl("/api/auth", { returnTo: "/bye" }), "/api/auth/logout?returnTo=%2Fbye");
});
