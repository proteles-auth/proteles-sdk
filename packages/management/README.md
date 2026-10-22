# @proteles/management

> **You need a Proteles account.** This package is a client for the Proteles
> Management API: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then create an API key in your
> workspace.

A typed client for the Proteles **Management API** (`/api/v1/*`) — the control
plane. Every operation the API publishes, 102 at this release:
provision tenants, apps and keys; configure connections, branding, mail,
webhooks and SAML; read the audit trail and export it; and respond to an
incident.

It is what Proteles' own CI provisions with. It is **not** what the Proteles
console is built on — that talks to the same API directly. This file said
otherwise for a while, which is worth stating plainly rather than quietly
correcting: a reader deciding whether to depend on this package was told it had
a second consumer inside the product, and it does not.

The wire shapes are generated from the published OpenAPI document
([`spec/openapi.json`](https://github.com/proteles-auth/proteles-sdk/blob/main/spec/openapi.json),
pinned to a server commit), which Proteles' server tests hold to a real server
response at every schema this client maps; CI here fails if the generated
types drift from it. The camelCase types you see are hand-written on top, and
every operation the API declares is reachable from here.

## Install

```bash
npm install @proteles/management
```

## Usage

```ts
import { ManagementClient } from "@proteles/management";

// Platform token: full, cross-tenant access (provisioning).
const platform = new ManagementClient({
  baseUrl: "https://auth.proteles.com",
  token: process.env.PROTELES_PLATFORM_TOKEN!,
});

const tenant = await platform.createTenant({ slug: "acme", displayName: "Acme Inc" });
const key = await platform.createApiKey(tenant.id, { name: "ci", scopes: ["audit:read"] }); // key.apiKey shown once

// Tenant key: scoped to its own tenant (day-to-day config).
const acme = new ManagementClient({ baseUrl: "https://auth.proteles.com", token: key.apiKey });

const app = await acme.createApp({
  clientName: "Acme Web",
  tokenEndpointAuthMethod: "client_secret_basic",
  grantTypes: ["authorization_code", "refresh_token"],
  redirectUris: ["https://acme.example/api/auth/callback"],
  // Where signing out returns to: @proteles/bff ends the session at Proteles
  // too, and comes back here only if this is registered.
  postLogoutRedirectUris: ["https://acme.example/"],
  scopes: ["openid", "profile", "email", "offline_access"],
});
// app.clientId / app.clientSecret (secret returned once)

// The provider sends the browser back to the Proteles server, not to your app,
// so this is the server's callback on one of the tenant's own hosts —
// `<slug>.<base host>` or a verified custom domain — and the same value is
// registered with the provider. Anything else is refused with a 400.
await acme.upsertConnection({
  provider: "google",
  clientId: "…apps.googleusercontent.com",
  clientSecret: "…",
  redirectUri: "https://acme.<base host>/login/google/callback",
});

await acme.updateTenantBranding(tenant.id, { appName: "Acme", primaryColor: "#ff0066" });
const events = await acme.listAudit({ limit: 50 });
```

## Two credentials

- **Platform bootstrap token** — full, cross-tenant access. Use it to
  `createTenant` and `createApiKey`; endpoints that operate on a specific tenant
  take a `tenantId`.
- **Tenant API key** (`mk_…`) — scoped to its own tenant. `tenantId` is derived
  from the key; passing a *different* tenant's id is rejected with a
  `ManagementError` (`status: 403`).

## Methods

| Method | Endpoint |
| --- | --- |
| `createTenant(input)` | `POST /api/v1/tenants` (platform) |
| `inviteTenantOwner(id, input)` | `POST /api/v1/tenants/{id}/owner-invitations` (platform) |
| `withdrawTenantOwnerInvitation(id, input)` | `DELETE /api/v1/tenants/{id}/owner-invitations` (platform) |
| `getTenant(id)` | `GET /api/v1/tenants/{id}` |
| `updateTenantBranding(id, branding)` | `PATCH /api/v1/tenants/{id}` |
| `createApiKey(id, input)` | `POST /api/v1/tenants/{id}/keys` (platform) |
| `listApiKeys(id)` | `GET /api/v1/tenants/{id}/keys` (platform) |
| `revokeApiKey(id, keyId)` | `DELETE /api/v1/tenants/{id}/keys/{keyId}` (platform) |
| `listDomains(id)` | `GET /api/v1/tenants/{id}/domains` (`domains:write`) |
| `claimDomain(id, domain)` | `POST /api/v1/tenants/{id}/domains` (`domains:write`) |
| `verifyDomain(id, domain)` | `POST /api/v1/tenants/{id}/domains/{domain}/verify` (`domains:write`) |
| `releaseDomain(id, domain)` | `DELETE /api/v1/tenants/{id}/domains/{domain}` (`domains:write`) |
| `createApp(input)` | `POST /api/v1/apps` |
| `listApps(scope?)` | `GET /api/v1/apps` |
| `upsertConnection(input)` | `POST /api/v1/connections` |
| `listConnections(scope?)` | `GET /api/v1/connections` |
| `listAudit(options?)` | `GET /api/v1/audit` |
| `getUsage(options?)` | `GET /api/v1/usage` (`usage:read`) |

Everything is camelCase; the client maps to/from the API's snake_case wire
format. Secrets (`apiKey`, `clientSecret`) are returned exactly once by the
server and never retrievable again.

**Inviting people into an app.** Give the app a sign-in start address,
`initiateLoginUri` on `createApp` or `updateApp` — with a Proteles SDK, the
app's `/api/auth/login` — and pass its `clientId` to `inviteUser`. Whoever
accepts the invitation is sent there with `iss`, and a new account arrives
signed in. `inviteUser` refuses an app with no `initiateLoginUri`.

### Reading usage

```ts
const usage = await mgmt.getUsage({ tenantId, months: 12 });
usage.activeUsers;  // 42
usage.period;       // "2026-08-01" — an ISO date, the first of the month
usage.definition;   // "distinct users who signed in or refreshed a token, per calendar month, UTC"
usage.series;       // [{ period: "2025-09-01", activeUsers: 0 }, … ] oldest first
```

The definition comes back with the number rather than living here, and that is
deliberate: "active users" has several defensible meanings — rolling thirty
days, sign-ins only, per application — and each gives a different figure. An
invoice dispute is a bad place to discover which one was meant.

Quiet months are present in the series as zeroes rather than omitted, so a chart
needs no gap-filling, and `activeUsers` is always the last point of `series`,
read from the same query — two queries could disagree across a month boundary.

There is no method that writes a usage figure, and no endpoint behind one. These
numbers are produced by people signing in; something that could adjust them
would be something that could adjust an invoice.

## Errors

Any non-2xx response throws a `ManagementError` carrying the API's `code`
(e.g. `"conflict"`, `"forbidden"`, `"not_found"`) and HTTP `status`. When the
server could not read the request body, `detail` says why — the field it did
not know and the ones it expected, or the value that did not fit:

```ts
try {
  await client.createApp({ tenantId, clientName: "Billing" });
} catch (e) {
  if (e instanceof ManagementError && e.detail) console.error(e.message, "—", e.detail);
}
```

`message` and `detail` are for people; branch on `code` and `status`.

## Develop

```bash
npm install      # from the repository root
npm run build    # tsc -> dist
npm test         # tsx + node:test (wire mapping + error handling, mock fetch)
```

The full control-plane lifecycle is also exercised against a **live** server by
[`scripts/verify-management.mjs`](https://github.com/proteles-auth/proteles-sdk/blob/main/scripts/verify-management.mjs), which
Proteles' integration tests run.
