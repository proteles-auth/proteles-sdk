# @proteles/js

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

Framework-agnostic OAuth2/OIDC client core for the Proteles identity platform.

This is the substrate the framework SDKs build on. Most apps should use a
higher-level package instead:

- **[`@proteles/next`](https://www.npmjs.com/package/@proteles/next)** — a Backend-for-Frontend for Next.js. Tokens
  live in encrypted, httpOnly cookies on your own server and never reach the
  browser. **Recommended.**
- **[`@proteles/react`](https://www.npmjs.com/package/@proteles/react)** — drop-in components (`<SignInButton>`,
  `<UserButton>`, `useUser()`) that talk to the BFF.

Reach for `@proteles/js` directly only when integrating a runtime that doesn't
yet have a dedicated SDK.

It is a TypeScript port of Proteles' reference Go client: the same
mandatory PKCE, `state`/`nonce` binding, refresh-with-rotation, revoke, and
userinfo fetch — validated against the same authorization server.

## Install

```bash
npm install @proteles/js
```

Requires a runtime with `fetch` and Web Crypto (Node 18.12+, modern browsers,
edge runtimes). Node 18 is supported via a `node:crypto` fallback.

## Usage

The client holds **no session state**. You generate an authorization request,
persist the returned `state` / `codeVerifier` / `nonce` somewhere only your
server can read (an encrypted cookie — exactly what `@proteles/next` does), then
complete the exchange on the callback.

```ts
import { OAuthClient } from "@proteles/js";

const client = new OAuthClient({
  issuer: "https://auth.example.com", // your tenant's issuer
  clientId: process.env.OAUTH_CLIENT_ID!,
  clientSecret: process.env.OAUTH_CLIENT_SECRET, // omit for a public (PKCE-only) client
  redirectUri: "https://app.example.com/api/auth/callback",
  scopes: ["openid", "profile", "email", "offline_access"],
});

// 1. Start login — redirect the browser to `url`, persist the rest server-side.
const { url, state, codeVerifier, nonce } = await client.createAuthorizationUrl();

// 2. On the callback: verify `state` matches, then exchange the code.
const tokens = await client.exchangeCode({ code, codeVerifier });

// 3. Read the user.
const user = await client.fetchUserInfo(tokens.accessToken);

// 4. Later: refresh (rotation-aware) and revoke on logout.
const refreshed = await client.refresh(tokens.refreshToken!);
const revoked = await client.revoke(tokens.refreshToken!); // never throws
if (!revoked.ok) console.warn("refresh token not revoked:", revoked.error.message);
```

### Errors: "no" versus "not now"

Every failure is an `OAuthError`. `code` is the OAuth `error` (`invalid_grant`,
`invalid_client`, …) when the server sent one and `status` the HTTP status when
there was an answer. Two more fields say whether trying again could help:

- `retryable` — true when no answer arrived (`unreachable`), and for `408`,
  `429` and every `5xx`. The token endpoint answers `503
  temporarily_unavailable` when its password pool is full, which says nothing
  about the grant; the rate limiter answers `429`. False for every other `4xx`:
  `invalid_grant` means sign in again, and no retry of that token can succeed:
  the server has already spent, revoked or expired it.
- `retryAfter` — the server's `Retry-After` in seconds, read as a number or an
  HTTP-date and capped at an hour, when it sent a usable one.

`revoke()` never throws: a sign-out has to be able to finish locally. It
resolves `{ ok: true }` for any `2xx` — RFC 7009 answers `200` for a token it
does not know, too — and `{ ok: false, error }` otherwise, so a failed
revocation can be retried or reported rather than lost.

### Confidential vs. public clients

- With a `clientSecret`, the token endpoint is called with HTTP Basic
  (`client_secret_basic`).
- Without one, the client is public: it sends `client_id` in the request body
  and relies on PKCE. The server must allow `token_endpoint_auth_method: none`
  for that client.

### Endpoints

Endpoints are derived from `issuer` using the server's conventional paths
(`/oauth/authorize`, `/oauth/token`, `/oauth/userinfo`, `/oauth/revoke`). Pass
`endpoints` to override any of them.

### Back-channel logout

When a session at your Proteles workspace ends — the person signs out,
signs out everywhere, resets a password, is deactivated or deleted — an app
that registered a `backchannel_logout_uri` is sent a signed logout token
(OpenID Connect Back-Channel Logout 1.0). Register it with the app's other
settings: `backchannelLogoutUri` in `@proteles/management`'s `createApp` or
`updateApp`, or `backchannel_logout_uri` at dynamic registration. It must be
`https`.

The token arrives as a form-encoded `POST` with one field, `logout_token`.
Verify it, end the session it names, and answer:

```ts
import { JwksCache, verifyLogoutToken, OAuthError } from "@proteles/js";

const issuer = "https://acme.auth.example.com"; // the iss in your ID tokens
const jwks = new JwksCache(`${issuer}/.well-known/jwks.json`); // one per process

async function backchannelLogout(form: URLSearchParams): Promise<number> {
  try {
    const claims = await verifyLogoutToken(form.get("logout_token") ?? "", {
      issuer,
      audience: "your-client-id",
      jwks,
    });
    // `sid` is the session's id as the ID tokens you were issued for it
    // carried — keep `sid` with your session at sign-in to find it again.
    await endSessions({ sid: claims.sid, sub: claims.sub });
    return 200;
  } catch (e) {
    // 503 when the key set could not be read just now: the server tries again
    // later. 400 for a token that is wrong, which is never retried.
    return e instanceof OAuthError && e.retryable ? 503 : 400;
  }
}
```

Ending a session that already ended is fine, and the same token can arrive
twice (a retry repeats its `jti`), so make `endSessions` idempotent rather
than refusing a `jti` you have seen.

## Security notes

- `state`, `codeVerifier`, and `nonce` are secrets for the duration of a login;
  never expose them to the browser. Validate `state` on the callback with the
  provided `timingSafeEqual`.
- `OAuthError.message` is diagnostic only — never surface it to end users.
- Every network call has a 10s default timeout (`timeoutMs`) so a slow AS can't
  hang your request.

## Develop

```bash
npm install      # from the repository root
npm run build    # tsc -> dist
npm test         # tsx + node:test
```
