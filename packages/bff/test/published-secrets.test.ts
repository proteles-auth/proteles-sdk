import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import { PUBLISHED_SECRETS, publishedAs } from "../src/published-secrets.ts";
import { resolveConfig } from "../src/config.ts";

const base = {
  issuer: "https://idp.example",
  clientId: "app",
  appUrl: "https://app.example",
};

test("a session secret published in this repository is refused", () => {
  assert.throws(
    // Entry one: valid base64 for exactly 32 bytes, so no other check here
    // would have stopped it.
    () => resolveConfig({ ...base, sessionSecret: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" }),
    /published in the Proteles repository/,
  );
});

test("a published value is named even when it is not valid base64", () => {
  // The ordering claim: these three do not decode to 32 bytes, so a check
  // placed after the decode would report the wrong problem.
  for (const secret of [
    "local-development-only-not-a-secret-32b+",
    "CHANGE_ME_32_RANDOM_BYTES_BASE64",
    "CHANGE_ME_TO_AT_LEAST_32_RANDOM_BYTES_SEE_ABOVE",
  ]) {
    assert.throws(
      () => resolveConfig({ ...base, sessionSecret: secret }),
      /published in the Proteles repository/,
      `${secret} was not refused for being published`,
    );
  }
});

test("a trailing newline does not smuggle a published key through", () => {
  // `openssl rand -base64 32 > file` and `echo` both leave one.
  assert.throws(
    () => resolveConfig({ ...base, sessionSecret: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\n" }),
    /published in the Proteles repository/,
  );
});

test("a freshly generated key is accepted", () => {
  // The register refuses what was published, not what looks weak.
  const fresh = randomBytes(32).toString("base64");
  assert.doesNotThrow(() => resolveConfig({ ...base, sessionSecret: fresh }));
});

test("the same bytes in another spelling are not refused, deliberately", () => {
  // Documenting the boundary rather than asserting a wish: the comparison is on
  // the trimmed string, so URL-safe or unpadded spellings of the same bytes get
  // through. Normalising would be the first step toward an entropy oracle. If
  // this ever becomes intolerable, the fix is a new register entry, not a
  // decoder.
  const urlSafe = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY".replace(/\+/g, "-").replace(/\//g, "_");
  assert.equal(publishedAs(urlSafe), undefined);
});

test("every registered value is reachable through the lookup", () => {
  assert.equal(PUBLISHED_SECRETS.length, 12, "has the Rust register changed?");
  for (const p of PUBLISHED_SECRETS) {
    assert.equal(publishedAs(p.value), p.publishedAs, `${p.value} is registered but not found`);
    assert.ok(p.publishedAs.length > 0, "a refusal must be able to say where the value came from");
  }
});
