#!/usr/bin/env node
//! The settled ID-token rules as code, and the proof that vectors.json agrees
//! with them.
//!
//! A vector file is only as good as its verdicts: a vector marked "reject" that
//! a correct verifier would reject for some *other* reason tests nothing, and
//! one marked "accept" that a careful verifier refuses would fail every native
//! SDK for being right. So this is a verifier written directly from the rules in
//! docs/mobile-SDKs.md §5 and §5.2, in the order they give, and every vector is
//! run through it. It is the reference the Swift and Kotlin implementations are
//! held to — through the vectors, not by being read.
//!
//! Run with no arguments: every vector must reach its verdict, and every
//! refusal must be for the reason its name gives (checked by `reason`).

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SKEW = 60;

class Refused extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

function b64uDecode(segment, what) {
  // Divergence 6: base64url with no padding, and nothing outside its alphabet.
  if (!/^[A-Za-z0-9_-]*$/.test(segment)) throw new Refused(`${what}-not-base64url`);
  const bytes = Buffer.from(segment, "base64url");
  // And the one spelling of those bytes: a final character whose unused bits
  // are not zero decodes to the same bytes in a lenient decoder and different
  // ones in a strict one, so two verifiers could disagree about what was signed.
  if (bytes.toString("base64url") !== segment) throw new Refused(`${what}-not-base64url`);
  return bytes;
}

/**
 * JSON, strictly: `JSON.parse`, after a scan that refuses a member named twice
 * in one object. `JSON.parse` keeps the last; a parser that keeps the first
 * reads a different token from the same bytes (RFC 7515 §4, RFC 8259 §4).
 */
function parseStrict(text, what) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Refused(`${what}-not-json`);
  }
  let i = 0;
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const str = () => {
    const start = i++;
    while (text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    i++;
    return JSON.parse(text.slice(start, i));
  };
  const val = () => {
    ws();
    if (text[i] === "{") {
      i++;
      const seen = new Set();
      ws();
      if (text[i] === "}") return i++;
      for (;;) {
        ws();
        const key = str();
        if (seen.has(key)) throw new Refused("duplicate-member");
        seen.add(key);
        ws();
        i++; // :
        val();
        ws();
        if (text[i++] === "}") return;
      }
    } else if (text[i] === "[") {
      i++;
      ws();
      if (text[i] === "]") return i++;
      for (;;) {
        val();
        ws();
        if (text[i++] === "]") return;
      }
    } else if (text[i] === '"') {
      str();
    } else {
      while (i < text.length && !",]} \t\n\r".includes(text[i])) i++;
    }
  };
  val();
  return value;
}

/** The modulus length in bits, and whether the exponent is one RSA can use. */
function rsaKeyIsSound(jwk) {
  if (typeof jwk.n !== "string" || typeof jwk.e !== "string") return false;
  const n = Buffer.from(jwk.n, "base64url");
  let first = 0;
  while (first < n.length && n[first] === 0) first++;
  const bits = n.length - first === 0 ? 0 : (n.length - first - 1) * 8 + (32 - Math.clz32(n[first]));
  const e = BigInt("0x" + (Buffer.from(jwk.e, "base64url").toString("hex") || "0"));
  // An exponent of one makes the "signature" the padded digest itself, which
  // anyone can write; an even one is not an RSA key.
  return bits >= 2048 && e >= 3n && e % 2n === 1n;
}

/** Verifies `token`; returns its claims or throws Refused. */
export function verifyIdToken(token, { jwks, issuer, audience, nonce, accessToken, now }) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Refused("not-three-segments");
  const [h, p, s] = parts;
  const header = parseStrict(b64uDecode(h, "header").toString("utf8"), "header");

  // 1. The algorithm first, before any key is looked up or any claim read.
  if (header.alg !== "RS256") throw new Refused("algorithm");
  // A header extension the sender marked critical is one this verifier must
  // understand to accept the token (RFC 7515 §4.1.11), and it understands none.
  if ("crit" in header) throw new Refused("crit");
  // 2. The key, by kid, from keys fit for signature verification.
  if (typeof header.kid !== "string" || header.kid === "") throw new Refused("kid-missing");
  const usable = (jwks.keys || []).filter(
    (k) =>
      k.kty === "RSA" &&
      (k.use === undefined || k.use === "sig") &&
      (k.alg === undefined || k.alg === "RS256") &&
      rsaKeyIsSound(k),
  );
  const jwk = usable.find((k) => k.kid === header.kid);
  if (!jwk) throw new Refused("no-usable-key");
  // 3. The signature, over the bytes exactly as they arrived.
  const signature = b64uDecode(s, "signature");
  b64uDecode(p, "payload");
  const key = createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
  if (!verify("RSA-SHA256", Buffer.from(`${h}.${p}`), key, signature)) throw new Refused("signature");
  // 4. Only now, the claims.
  const claims = parseStrict(b64uDecode(p, "payload").toString("utf8"), "payload");
  if (claims.iss !== issuer) throw new Refused("issuer");
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (aud.length !== 1 || aud[0] !== audience) throw new Refused("audience");
  if (typeof claims.sub !== "string" || claims.sub === "") throw new Refused("sub");
  if (typeof claims.exp !== "number") throw new Refused("exp-missing");
  if (now > claims.exp + SKEW) throw new Refused("expired");
  if (typeof claims.iat === "number" && claims.iat > now + SKEW) throw new Refused("issued-in-the-future");
  // 5. The nonce: null is the explicit skip; anything else must be present and equal.
  if (nonce !== null) {
    if (nonce === "" || claims.nonce !== nonce) throw new Refused("nonce");
  }
  // 6. at_hash, whenever the caller holds the access token (M3).
  if (accessToken !== null) {
    const digest = createHash("sha256").update(accessToken, "ascii").digest();
    const expected = digest.subarray(0, digest.length / 2).toString("base64url");
    if (claims.at_hash !== expected) throw new Refused("at-hash");
  }
  return claims;
}

// The reason each refusing vector must be refused for. A refusal for any other
// reason means the vector does not test what its name says.
const EXPECTED_REASON = {
  "alg-none": "algorithm",
  "alg-hs256-keyed-with-the-public-key": "algorithm",
  "alg-rs512": "algorithm",
  "kid-missing": "kid-missing",
  "kid-unknown": "no-usable-key",
  "the-only-matching-key-is-for-encryption": "no-usable-key",
  "the-only-matching-key-says-another-algorithm": "no-usable-key",
  "payload-altered-after-signing": "signature",
  "two-segments": "not-three-segments",
  "padded-base64url": "header-not-base64url",
  "issuer-with-a-trailing-slash": "issuer",
  "another-issuer": "issuer",
  "another-audience": "audience",
  "audience-shared-with-another-client": "audience",
  "expired-past-the-skew": "expired",
  "issued-in-the-future-past-the-skew": "issued-in-the-future",
  "exp-missing": "exp-missing",
  "sub-missing": "sub",
  "nonce-mismatch": "nonce",
  "nonce-missing-when-expected": "nonce",
  "an-empty-expected-nonce-is-not-a-skip": "nonce",
  "at-hash-mismatch": "at-hash",
  "at-hash-missing-when-an-access-token-is-held": "at-hash",
  "signature-in-a-non-canonical-spelling": "signature-not-base64url",
  "a-critical-header-extension": "crit",
  "a-claim-named-twice": "duplicate-member",
  "a-header-that-is-not-json": "header-not-json",
  "a-key-below-2048-bits": "no-usable-key",
  "a-key-whose-exponent-is-one": "no-usable-key",
};

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUN_DIRECTLY = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (RUN_DIRECTLY) {
  const { vectors } = JSON.parse(readFileSync(path.join(HERE, "vectors.json"), "utf8"));
  let failures = 0;
  for (const v of vectors) {
    let got;
    let reason;
    try {
      verifyIdToken(v.token, { jwks: v.jwks, ...v.expect });
      got = "accept";
    } catch (e) {
      if (!(e instanceof Refused)) throw e;
      got = "reject";
      reason = e.reason;
    }
    const want = EXPECTED_REASON[v.name];
    const ok = got === v.verdict && (got === "accept" || reason === want);
    if (!ok) failures += 1;
    console.log(`  ${ok ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m"} ${v.name}: ${got}${reason ? ` (${reason})` : ""}${ok ? "" : ` — expected ${v.verdict}${want ? ` (${want})` : ""}`}`);
  }
  const unnamed = vectors.filter((v) => v.verdict === "reject" && !(v.name in EXPECTED_REASON));
  for (const v of unnamed) {
    failures += 1;
    console.log(`  \x1b[31m✗\x1b[0m ${v.name}: a refusing vector with no expected reason here`);
  }
  console.log(failures ? `\n${failures} vector(s) disagree with the reference` : `\nall ${vectors.length} vectors agree with the reference, each refusal for its own reason`);
  process.exit(failures ? 1 : 0);
}
