import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { JwksCache, verifyIdToken } from "../src/idtoken.ts";
import type { FetchLike } from "../src/types.ts";

// ---------------------------------------------------------------------------
// The shared ID-token vectors (M2, `docs/mobile-SDKs.md` §5.2), the same file
// the Swift and Kotlin SDKs and `reference-verify.mjs` are held to. Each
// verifier must reach `verdict` for every vector, with `expect.now` as the
// clock and `jwks` as the only key set.
//
// Read from `mobile/vectors/`, not copied, so the four cannot drift apart.
// Before this ran, ten of the 36 reached the wrong verdict here.
//
// vectors.json is itself a copy of the server repository's canonical file
// (mobile/vectors/SOURCE.md), and SHA256SUMS records which one: a file edited
// here by hand, or refreshed without its sum, fails below.
// ---------------------------------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FILE = path.resolve(HERE, "../../../mobile/vectors/vectors.json");

type Vector = {
  name: string;
  token: string;
  jwks: unknown;
  expect: { issuer: string; audience: string; nonce: string | null; accessToken: string | null; now: number };
  verdict: "accept" | "reject";
  why: string;
};

const { vectors } = JSON.parse(readFileSync(FILE, "utf8")) as { vectors: Vector[] };

test("the vectors file is the canonical copy SHA256SUMS records", () => {
  const sums = readFileSync(path.join(path.dirname(FILE), "SHA256SUMS"), "utf8");
  const recorded = /^([0-9a-f]{64}) [ *]vectors\.json$/m.exec(sums)?.[1];
  assert.ok(recorded, "SHA256SUMS has no line for vectors.json");
  const actual = createHash("sha256").update(readFileSync(FILE)).digest("hex");
  assert.equal(actual, recorded, "vectors.json does not match SHA256SUMS: refresh both from the server repository (mobile/vectors/SOURCE.md)");
});

test("the vectors file is the one the native SDKs read, and it is not empty", () => {
  // A path that resolved to nothing would make every assertion below vacuous.
  assert.ok(vectors.length >= 36, `read ${vectors.length} vectors from ${FILE}`);
  assert.ok(vectors.some((v) => v.verdict === "accept") && vectors.some((v) => v.verdict === "reject"));
});

for (const v of vectors) {
  test(`vector ${v.name}: ${v.verdict}`, async () => {
    const fetch: FetchLike = async () =>
      new Response(JSON.stringify(v.jwks), { status: 200, headers: { "content-type": "application/json" } });
    let got: "accept" | "reject" = "accept";
    let why = "";
    try {
      await verifyIdToken(v.token, {
        issuer: v.expect.issuer,
        audience: v.expect.audience,
        nonce: v.expect.nonce,
        accessToken: v.expect.accessToken,
        jwks: new JwksCache("https://vectors.test/jwks", fetch),
        now: () => v.expect.now * 1000,
      });
    } catch (err) {
      got = "reject";
      why = (err as Error).message;
    }
    assert.equal(got, v.verdict, `${v.name}: ${v.why}${why ? ` (refused: ${why})` : ""}`);
  });
}
