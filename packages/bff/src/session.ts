//! Authenticated encryption of the session/flow cookies. AES-256-GCM via Web
//! Crypto — a port of Go's `sessionManager` (`encrypt`/`decrypt`). The wire
//! format is base64url(iv ‖ ciphertext ‖ tag): a random 12-byte IV prepended
//! to the GCM output (Web Crypto appends the 16-byte tag to the ciphertext).
//! Any tampering or a wrong key fails `decrypt`, and the value is never trusted.

import { base64UrlDecode, base64UrlEncode, randomBytes, subtle } from "./crypto.js";

const IV_BYTES = 12;

export class SessionCrypto {
  private keyPromise: Promise<CryptoKey> | undefined;
  private readonly rawKey: Uint8Array;

  constructor(sessionSecretB64: string) {
    this.rawKey = base64UrlDecode(sessionSecretB64);
    if (this.rawKey.length !== 32) {
      throw new Error("session secret must decode to exactly 32 bytes");
    }
  }

  private key(): Promise<CryptoKey> {
    if (!this.keyPromise) {
      this.keyPromise = subtle().then((s) =>
        s.importKey("raw", toArrayBuffer(this.rawKey), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]),
      );
    }
    return this.keyPromise;
  }

  /** Encrypts a JSON-serializable value to a compact base64url token. */
  async encrypt(value: unknown): Promise<string> {
    const s = await subtle();
    const key = await this.key();
    const iv = await randomBytes(IV_BYTES);
    const plaintext = new TextEncoder().encode(JSON.stringify(value));
    const ciphertext = new Uint8Array(
      await s.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext)),
    );
    const out = new Uint8Array(iv.length + ciphertext.length);
    out.set(iv, 0);
    out.set(ciphertext, iv.length);
    return base64UrlEncode(out);
  }

  /** Decrypts a token produced by `encrypt`. Throws on tamper/wrong key. */
  async decrypt<T>(token: string): Promise<T> {
    const raw = base64UrlDecode(token);
    if (raw.length <= IV_BYTES) {
      throw new Error("ciphertext too short");
    }
    const iv = raw.slice(0, IV_BYTES);
    const ciphertext = raw.slice(IV_BYTES);
    const s = await subtle();
    const key = await this.key();
    const plaintext = new Uint8Array(
      await s.decrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(ciphertext)),
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  }
}

/** Copies a view into a standalone ArrayBuffer for the Web Crypto APIs (avoids
 *  TS 5.7's `Uint8Array<ArrayBufferLike>` vs. `ArrayBuffer` view-generic issue
 *  and any `SharedArrayBuffer` ambiguity). */
function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}
