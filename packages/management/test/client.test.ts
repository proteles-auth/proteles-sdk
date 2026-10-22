import { test } from "node:test";
import assert from "node:assert/strict";

import { ManagementClient } from "../src/client.ts";
import type { CreateApiKeyInput } from "../src/types.ts";
import { ManagementError } from "../src/errors.ts";
import type { FetchLike } from "../src/types.ts";

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function mockFetch(respond: (rec: Recorded) => Response): { fetch: FetchLike; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const fetch: FetchLike = async (url, init) => {
    const raw = typeof init?.body === "string" ? init.body : "";
    calls.push({
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers: (init?.headers as Record<string, string>) ?? {},
      body: raw ? JSON.parse(raw) : undefined,
    });
    return respond(calls[calls.length - 1]!);
  };
  return { fetch, calls };
}

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

const make = (respond: (rec: Recorded) => Response) => {
  const { fetch, calls } = mockFetch(respond);
  return { client: new ManagementClient({ baseUrl: "https://api.proteles.com/", token: "plat-token", fetch }), calls };
};

test("an id of '.', '..' or nothing is refused before any request is made", async () => {
  // `encodeURIComponent` leaves dots alone, and the URL parser resolves a
  // path segment of `.` or `..` away. So `replayDelivery(".")` posted to
  // /api/v1/webhook/deliveries/replay, which replays deliveries in bulk, and
  // `getTenant("..")` read /api/v1/ — another endpoint, with the caller's
  // token, for a call that named one thing. An empty id has the same effect.
  const { client, calls } = make(() => json({ requeued: 1 }));
  const cases: [string, () => Promise<unknown>][] = [
    ['replayDelivery(".")', () => client.replayDelivery(".")],
    ['replayDelivery("..")', () => client.replayDelivery("..")],
    ['getTenant("..")', () => client.getTenant("..")],
    ['deleteApp(".")', () => client.deleteApp(".")],
    ['getWebhook("")', () => client.getWebhook("")],
  ];
  for (const [label, call] of cases) {
    await assert.rejects(call, (err: unknown) => {
      assert.ok(err instanceof ManagementError, `${label}: expected ManagementError, got ${String(err)}`);
      assert.match(err.message, /id/, `${label}: the message says what was wrong`);
      return true;
    });
  }
  assert.deepEqual(calls.map((c) => c.url), [], "and nothing was sent");

  // Dots that are not a whole segment are an ordinary id, encoded as before.
  await client.replayDelivery("...");
  await client.replayDelivery("a.b");
  assert.deepEqual(
    calls.map((c) => new URL(c.url).pathname),
    ["/api/v1/webhook/deliveries/.../replay", "/api/v1/webhook/deliveries/a.b/replay"],
  );
});

test("an answer whose body stalls ends at the timeout", { timeout: 5000 }, async () => {
  // The timer used to be cleared on the headers, and the body
  // was read after it with no deadline. The double errors its body on abort,
  // as a real fetch does.
  const fetch: FetchLike = async (_url, init) =>
    new Response(
      new ReadableStream({
        start(controller) {
          init?.signal?.addEventListener("abort", () => controller.error(new DOMException("aborted", "AbortError")));
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  const client = new ManagementClient({ baseUrl: "https://api.proteles.com/", token: "plat-token", fetch, timeoutMs: 50 });
  await assert.rejects(() => client.getTenant("t1"), ManagementError);
  await assert.rejects(() => client.exportAudit(), ManagementError);
});

test("every request carries the bearer token", async () => {
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.createTenant({ slug: "acme" });
  assert.equal(calls[0]!.headers["authorization"], "Bearer plat-token");
});

test("createTenant sends ownerEmail as owner_email, and omits the key when unset", async () => {
  // The server has read `owner_email` on this path since it shipped; the SDK had
  // no way to send it, so a caller either dropped to a raw request or left the
  // tenant ownerless.
  {
    const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }, 201));
    await client.createTenant({ slug: "acme", ownerEmail: "owner@acme.test" });
    assert.deepEqual(calls[0]!.body, { slug: "acme", owner_email: "owner@acme.test" });
  }
  {
    const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }, 201));
    await client.createTenant({ slug: "acme" });
    assert.ok(
      !("owner_email" in (calls[0]!.body as Record<string, unknown>)),
      "an unset owner sends no key at all",
    );
  }
});

test("createTenant returns a summary — the policy fields are not in it", async () => {
  // This test used to read `tenant.mfaPolicy` and assert it was `undefined`,
  // with a comment explaining that an optional field reading undefined says "no
  // policy" rather than "not stated". It described the defect and then pinned
  // it. Now the return type is `TenantSummary` and those two lines do not
  // compile — which is the assertion, and a stronger one than `assert.equal`:
  // it holds for every caller, not just this one.
  //
  // The suite was never typechecked when that was written. `tsconfig.json`
  // included only `src`, so nothing ever compared these fixtures or these reads
  // against the types they exercise. `tsconfig.test.json` now does.
  const { client } = make(() => json({ id: "t1", slug: "acme", status: "active" }, 201));
  const tenant = await client.createTenant({ slug: "acme" });
  assert.deepEqual(Object.keys(tenant), ["id", "slug", "status"]);
  assert.equal(tenant.slug, "acme");
  // @ts-expect-error a summary has no policy to read, and that is the point
  assert.equal(tenant.mfaPolicy, undefined);
});

test("createTenant maps displayName -> display_name and parses the response", async () => {
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }, 201));
  const tenant = await client.createTenant({ slug: "acme", displayName: "Acme Inc" });
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/tenants");
  assert.equal(calls[0]!.method, "POST");
  assert.deepEqual(calls[0]!.body, { slug: "acme", display_name: "Acme Inc" });
  assert.deepEqual(tenant, { id: "t1", slug: "acme", status: "active" });
});

test("getTenant parses branding from snake_case", async () => {
  const { client } = make(() =>
    json({ id: "t1", slug: "acme", status: "active", branding: { app_name: "Acme", primary_color: "#f06", logo_uri: null } }),
  );
  const tenant = await client.getTenant("t1");
  assert.deepEqual(tenant.branding, { appName: "Acme", primaryColor: "#f06" }); // null logo_uri omitted
});

test("updateTenantBranding sends branding as snake_case and omits undefined keys", async () => {
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active", branding: { app_name: "Acme" } }));
  await client.updateTenantBranding("t1", { appName: "Acme" });
  assert.equal(calls[0]!.method, "PATCH");
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/tenants/t1");
  assert.deepEqual(calls[0]!.body, { branding: { app_name: "Acme" } });
});

test("createApiKey posts to the tenant keys path and returns the raw key and its id", async () => {
  const { client, calls } = make(() =>
    json({ id: "k1", api_key: "mk_abc", name: "ci", scopes: ["apps:write"] }, 201),
  );
  const key = await client.createApiKey("t1", { name: "ci", scopes: ["apps:write"] });
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/tenants/t1/keys");
  assert.deepEqual(key, { id: "k1", apiKey: "mk_abc", name: "ci", scopes: ["apps:write"] });
});

test("createApp maps the whole camelCase input to snake_case and returns the secret once", async () => {
  const { client, calls } = make(() => json({ client_id: "cid", client_name: "Web", client_secret: "shh" }, 201));
  const app = await client.createApp({
    tenantId: "t1",
    clientName: "Web",
    tokenEndpointAuthMethod: "client_secret_basic",
    redirectUris: ["https://app/cb"],
    grantTypes: ["authorization_code"],
    scopes: ["openid"],
    firstParty: true,
  });
  assert.deepEqual(calls[0]!.body, {
    tenant_id: "t1",
    client_name: "Web",
    token_endpoint_auth_method: "client_secret_basic",
    redirect_uris: ["https://app/cb"],
    grant_types: ["authorization_code"],
    scopes: ["openid"],
    first_party: true,
  });
  assert.deepEqual(app, { clientId: "cid", clientName: "Web", clientSecret: "shh" });
});

test("createApp can register a private_key_jwt client", async () => {
  // The reason this test exists. `tokenEndpointAuthMethod` was a hand-written
  // three-value union and `jwtAuthPublicKeyPem` was not in the type at all, so
  // the only client that does not authenticate with a shared secret was the one
  // client this SDK could not create. The server requires the PEM for this
  // method (400 without it) and refuses it with every other method (400 with
  // it), so the pair travels together or not at all.
  const { client, calls } = make(() => json({ client_id: "cid", client_name: "Svc" }, 201));
  const app = await client.createApp({
    tenantId: "t1",
    clientName: "Svc",
    tokenEndpointAuthMethod: "private_key_jwt",
    jwtAuthPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n",
    grantTypes: ["client_credentials"],
  });
  const body = calls[0]!.body as Record<string, unknown>;
  assert.equal(body["token_endpoint_auth_method"], "private_key_jwt");
  assert.equal(
    body["jwt_auth_public_key_pem"],
    "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n",
  );
  // Confidential, but issued no secret — that is the point of the method, and
  // a caller that expected one would store `undefined` as a credential.
  assert.equal(app.clientSecret, undefined);
});

test("createApp sends post_logout_redirect_uris and service_account_id, and omits them when unset", async () => {
  {
    const { client, calls } = make(() => json({ client_id: "cid", client_name: "Web" }, 201));
    await client.createApp({
      tenantId: "t1",
      redirectUris: ["https://app/cb"],
      postLogoutRedirectUris: ["https://app/bye"],
      serviceAccountId: "6f1a0c2e-0000-4000-8000-000000000001",
    });
    assert.deepEqual(calls[0]!.body, {
      tenant_id: "t1",
      redirect_uris: ["https://app/cb"],
      post_logout_redirect_uris: ["https://app/bye"],
      service_account_id: "6f1a0c2e-0000-4000-8000-000000000001",
    });
  }
  {
    const { client, calls } = make(() => json({ client_id: "cid", client_name: "Web" }, 201));
    await client.createApp({ tenantId: "t1", redirectUris: ["https://app/cb"] });
    const body = calls[0]!.body as Record<string, unknown>;
    for (const k of ["post_logout_redirect_uris", "jwt_auth_public_key_pem", "service_account_id"]) {
      assert.ok(!(k in body), `${k} is absent, not null — the server reads null as a type error`);
    }
  }
});

const ANDROID_FP = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
const wireIdentity = { android: { package_name: "com.example.app", sha256_cert_fingerprints: [ANDROID_FP] }, ios: { app_id: "ABCDE12345.com.example.app" } };
const identity = { android: { packageName: "com.example.app", sha256CertFingerprints: [ANDROID_FP] }, ios: { appId: "ABCDE12345.com.example.app" } };

test("createApp sends an app identity in the wire's spelling and maps the stored one back", async () => {
  const { client, calls } = make(() => json({ client_id: "cid", client_name: "Mobile", app_identity: wireIdentity }, 201));
  const app = await client.createApp({ tenantId: "t1", tokenEndpointAuthMethod: "none", redirectUris: ["https://app.example/cb"], appIdentity: identity });
  assert.deepEqual((calls[0]!.body as Record<string, unknown>)["app_identity"], wireIdentity);
  assert.deepEqual(app.appIdentity, identity);
});

test("createApp sends one platform alone, without a key for the other", async () => {
  // The server's AppIdentity denies unknown fields and reads null as a type
  // error, so the absent platform must be absent on the wire, not null.
  for (const [only, wire] of [
    [{ ios: identity.ios }, { ios: wireIdentity.ios }],
    [{ android: identity.android }, { android: wireIdentity.android }],
  ] as const) {
    const { client, calls } = make(() => json({ client_id: "cid", client_name: "Mobile" }, 201));
    await client.createApp({ tenantId: "t1", redirectUris: ["https://app.example/cb"], appIdentity: only });
    assert.deepEqual((calls[0]!.body as Record<string, unknown>)["app_identity"], wire);
  }
});

test("updateApp sets an identity, clears it with null, and leaves it alone when omitted", async () => {
  const updated = (app_identity: unknown) =>
    json({ client_id: "cid", client_name: "Mobile", client_type: "public", grant_types: [], redirect_uris: [], post_logout_redirect_uris: [], scopes: [], first_party: false, is_active: true, app_identity });
  {
    const { client, calls } = make(() => updated(wireIdentity));
    const app = await client.updateApp("cid", { tenantId: "t1", appIdentity: identity });
    assert.deepEqual((calls[0]!.body as Record<string, unknown>)["app_identity"], wireIdentity);
    assert.deepEqual(app.appIdentity, identity);
  }
  {
    const { client, calls } = make(() => updated(null));
    const app = await client.updateApp("cid", { tenantId: "t1", appIdentity: null });
    const body = calls[0]!.body as Record<string, unknown>;
    assert.ok("app_identity" in body && body["app_identity"] === null, "null is sent: it is how a client stops being an app");
    assert.equal(app.appIdentity, null);
  }
  {
    const { client, calls } = make(() => updated(null));
    await client.updateApp("cid", { tenantId: "t1", clientName: "Renamed" });
    assert.ok(!("app_identity" in (calls[0]!.body as Record<string, unknown>)), "omitted is left out, so the stored identity stays");
  }
});

test("createApp sends a back-channel logout URI and maps what was stored, and omits it when unset", async () => {
  {
    const { client, calls } = make(() =>
      json({ client_id: "cid", client_name: "Web", backchannel_logout_uri: "https://app/bcl", backchannel_logout_session_required: true }, 201),
    );
    const app = await client.createApp({
      tenantId: "t1",
      redirectUris: ["https://app/cb"],
      backchannelLogoutUri: "https://app/bcl",
      backchannelLogoutSessionRequired: true,
    });
    const body = calls[0]!.body as Record<string, unknown>;
    assert.equal(body["backchannel_logout_uri"], "https://app/bcl");
    assert.equal(body["backchannel_logout_session_required"], true);
    assert.equal(app.backchannelLogoutUri, "https://app/bcl");
    assert.equal(app.backchannelLogoutSessionRequired, true);
  }
  {
    const { client, calls } = make(() => json({ client_id: "cid", client_name: "Web" }, 201));
    const app = await client.createApp({ tenantId: "t1", redirectUris: ["https://app/cb"] });
    const body = calls[0]!.body as Record<string, unknown>;
    for (const k of ["backchannel_logout_uri", "backchannel_logout_session_required"]) {
      assert.ok(!(k in body), `${k} is absent, not null`);
    }
    assert.ok(!("backchannelLogoutUri" in app), "and the result does not claim one");
  }
});

test("updateApp sets a back-channel logout URI, stops it with null, and leaves it alone when omitted", async () => {
  const updated = (uri: string | null, required: boolean) =>
    json({ client_id: "cid", client_name: "Web", client_type: "confidential", grant_types: [], redirect_uris: [], post_logout_redirect_uris: [], scopes: [], first_party: false, is_active: true, app_identity: null, backchannel_logout_uri: uri, backchannel_logout_session_required: required });
  {
    const { client, calls } = make(() => updated("https://app/bcl", false));
    const app = await client.updateApp("cid", { tenantId: "t1", backchannelLogoutUri: "https://app/bcl" });
    assert.equal((calls[0]!.body as Record<string, unknown>)["backchannel_logout_uri"], "https://app/bcl");
    assert.equal(app.backchannelLogoutUri, "https://app/bcl");
    assert.equal(app.backchannelLogoutSessionRequired, false);
  }
  {
    const { client, calls } = make(() => updated(null, false));
    const app = await client.updateApp("cid", { tenantId: "t1", backchannelLogoutUri: null });
    const body = calls[0]!.body as Record<string, unknown>;
    assert.ok("backchannel_logout_uri" in body && body["backchannel_logout_uri"] === null, "null is sent: it is how an app stops being told");
    assert.equal(app.backchannelLogoutUri, null);
  }
  {
    const { client, calls } = make(() => updated("https://app/bcl", false));
    await client.updateApp("cid", { tenantId: "t1", clientName: "Renamed" });
    assert.ok(!("backchannel_logout_uri" in (calls[0]!.body as Record<string, unknown>)), "omitted is left out");
  }
});

test("listApps maps the back-channel logout URI, and null from a server that does not list it", async () => {
  const row = { client_id: "cid", client_name: "Web", client_type: "confidential", grant_types: [], redirect_uris: [], first_party: false, created_at: "2026-01-01T00:00:00Z", is_active: true, self_registered: false, app_identity: null };
  {
    const { client } = make(() => json({ apps: [{ ...row, backchannel_logout_uri: "https://app/bcl", backchannel_logout_session_required: true }], self_registered: { used: 0, limit: 10, source: "default" } }));
    const [app] = await client.listApps({ tenantId: "t1" });
    assert.equal(app!.backchannelLogoutUri, "https://app/bcl");
    assert.equal(app!.backchannelLogoutSessionRequired, true);
  }
  {
    const { client } = make(() => json({ apps: [row], self_registered: { used: 0, limit: 10, source: "default" } }));
    const [app] = await client.listApps({ tenantId: "t1" });
    assert.equal(app!.backchannelLogoutUri, null);
    assert.equal(app!.backchannelLogoutSessionRequired, false);
  }
});

test("an app's sign-in start address is sent, mapped, cleared with null, and null from a server that does not list it", async () => {
  const start = "https://app/api/auth/login";
  {
    const { client, calls } = make(() => json({ client_id: "cid", client_name: "Web", initiate_login_uri: start }, 201));
    const app = await client.createApp({ tenantId: "t1", redirectUris: ["https://app/cb"], initiateLoginUri: start });
    assert.equal((calls[0]!.body as Record<string, unknown>)["initiate_login_uri"], start);
    assert.equal(app.initiateLoginUri, start);
  }
  {
    const { client, calls } = make(() => json({ client_id: "cid", client_name: "Web" }, 201));
    const app = await client.createApp({ tenantId: "t1", redirectUris: ["https://app/cb"] });
    assert.ok(!("initiate_login_uri" in (calls[0]!.body as Record<string, unknown>)), "absent, not null");
    assert.ok(!("initiateLoginUri" in app), "and the result does not claim one");
  }
  const updated = (uri: string | null) =>
    json({ client_id: "cid", client_name: "Web", client_type: "confidential", grant_types: [], redirect_uris: [], post_logout_redirect_uris: [], scopes: [], first_party: false, is_active: true, app_identity: null, backchannel_logout_uri: null, backchannel_logout_session_required: false, initiate_login_uri: uri });
  {
    const { client, calls } = make(() => updated(null));
    const app = await client.updateApp("cid", { tenantId: "t1", initiateLoginUri: null });
    const body = calls[0]!.body as Record<string, unknown>;
    assert.ok("initiate_login_uri" in body && body["initiate_login_uri"] === null, "null is sent: it is how the address is cleared");
    assert.equal(app.initiateLoginUri, null);
  }
  {
    const { client, calls } = make(() => updated(start));
    const app = await client.updateApp("cid", { tenantId: "t1", clientName: "Renamed" });
    assert.ok(!("initiate_login_uri" in (calls[0]!.body as Record<string, unknown>)), "omitted is left out");
    assert.equal(app.initiateLoginUri, start);
  }
  const row = { client_id: "cid", client_name: "Web", client_type: "confidential", grant_types: [], redirect_uris: [], first_party: false, created_at: "2026-01-01T00:00:00Z", is_active: true, self_registered: false, app_identity: null };
  {
    const { client } = make(() => json({ apps: [{ ...row, initiate_login_uri: start }], self_registered: { used: 0, limit: 10, source: "default" } }));
    const [app] = await client.listApps({ tenantId: "t1" });
    assert.equal(app!.initiateLoginUri, start);
  }
  {
    const { client } = make(() => json({ apps: [row], self_registered: { used: 0, limit: 10, source: "default" } }));
    const [app] = await client.listApps({ tenantId: "t1" });
    assert.equal(app!.initiateLoginUri, null);
  }
});

test("inviteUser names the app to return the invitee to, and maps it back; omitted, it is left out", async () => {
  {
    const { client, calls } = make(() => json({ email: "ada@x.test", expires_at: "2026-10-21T00:00:00Z", delivered: true, client_id: "cid" }, 202));
    const invitation = await client.inviteUser({ tenantId: "t1", email: "ada@x.test", clientId: "cid" });
    assert.equal((calls[0]!.body as Record<string, unknown>)["client_id"], "cid");
    assert.equal(invitation.clientId, "cid");
  }
  {
    const { client, calls } = make(() => json({ email: "ada@x.test", expires_at: "2026-10-21T00:00:00Z", delivered: true }, 202));
    const invitation = await client.inviteUser({ tenantId: "t1", email: "ada@x.test" });
    assert.ok(!("client_id" in (calls[0]!.body as Record<string, unknown>)));
    assert.ok(!("clientId" in invitation));
  }
});

test("listApps maps each app's identity, and null where it has none", async () => {
  const row = (app_identity: unknown) => ({ client_id: "cid", client_name: "Web", client_type: "public", grant_types: [], redirect_uris: [], first_party: false, created_at: "2026-01-01T00:00:00Z", is_active: true, self_registered: false, app_identity });
  const { client } = make(() => json({ apps: [row(wireIdentity), row(null)] }));
  const apps = await client.listApps({ tenantId: "t1" });
  assert.deepEqual(apps[0]!.appIdentity, identity);
  assert.equal(apps[1]!.appIdentity, null);
});

test("listApps sends tenant_id as a query param and maps each app", async () => {
  const { client, calls } = make(() =>
    json({ apps: [{ client_id: "cid", client_name: "Web", client_type: "confidential", grant_types: ["authorization_code"], redirect_uris: ["u"], first_party: false, created_at: "2026-01-01T00:00:00Z", is_active: false, self_registered: true }] }),
  );
  const apps = await client.listApps({ tenantId: "t1" });
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/apps?tenant_id=t1");
  assert.equal(apps[0]!.clientId, "cid");
  assert.equal(apps[0]!.clientType, "confidential");
  assert.deepEqual(apps[0]!.grantTypes, ["authorization_code"]);
});

test("upsertConnection maps clientSecret -> client_secret and never returns it", async () => {
  const { client, calls } = make(() => json({ provider: "google", client_id: "gid", redirect_uri: "u", enabled: true }));
  const conn = await client.upsertConnection({ tenantId: "t1", provider: "google", clientId: "gid", clientSecret: "secret", redirectUri: "u" });
  assert.equal(calls[0]!.body && (calls[0]!.body as Record<string, unknown>)["client_secret"], "secret");
  // No `in_use` in this reply, as from a server before plans limited social
  // logins: read as the switch, which is what that server did.
  assert.deepEqual(conn, { provider: "google", clientId: "gid", redirectUri: "u", enabled: true, inUse: true });
  assert.ok(!("clientSecret" in conn) && !("client_secret" in conn));
});

test("a connection the plan switches off says so", async () => {
  const { client } = make(() =>
    json({ connections: [{ provider: "github", client_id: "gh", redirect_uri: "u", enabled: true, in_use: false }] }),
  );
  const [conn] = await client.listConnections({ tenantId: "t1" });
  assert.equal(conn!.enabled, true);
  assert.equal(conn!.inUse, false);
});

test("listConnections and listAudit map results; audit passes limit", async () => {
  const connClient = make(() => json({ connections: [{ provider: "google", client_id: "g", redirect_uri: "u", enabled: true }] }));
  assert.equal((await connClient.client.listConnections({ tenantId: "t1" }))[0]!.provider, "google");

  const auditClient = make(() =>
    json({ events: [{ event_type: "app.created", severity: "info", client_id: "c", actor_user_id: null, ip: null, detail: "x", detail_json: "{\"k\":\"v\"}", leaf_version: 2, created_at: "2026-01-01T00:00:00Z" }] }),
  );
  const events = await auditClient.client.listAudit({ tenantId: "t1", limit: 25 });
  assert.equal(auditClient.calls[0]!.url, "https://api.proteles.com/api/v1/audit?tenant_id=t1&limit=25");
  assert.equal(events[0]!.eventType, "app.created");
  assert.equal(events[0]!.actorUserId, null);
});

test("getUsage maps the wire shape and carries the definition with the number", async () => {
  const { client, calls } = make(() =>
    json({
      tenant_id: "t1",
      soft_cap: 40,
      over_soft_cap: true,
      metric: "monthly_active_users",
      definition: "distinct users who signed in or refreshed a token, per calendar month, UTC",
      period: "2026-08-01",
      active_users: 42,
      series: [
        { period: "2026-07-01", active_users: 31 },
        { period: "2026-08-01", active_users: 42 },
      ],
    }),
  );

  const usage = await client.getUsage({ tenantId: "t1", months: 6 });
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/usage?tenant_id=t1&months=6");
  assert.equal(usage.activeUsers, 42);
  assert.equal(usage.period, "2026-08-01", "an ISO date, matching what the server sends");
  assert.equal(usage.series[1]!.activeUsers, 42);

  // The definition travels with the number rather than living in documentation.
  // "Active users" has several defensible meanings and they give different
  // figures; an invoice dispute is a bad place to find out which was meant.
  assert.match(usage.definition, /calendar month/);
  assert.equal(usage.metric, "monthly_active_users");
});

test("getUsage omits absent options rather than sending them empty", async () => {
  // `tenant_id` is how a platform token names a tenant and how a tenant key is
  // checked against its own; sending `tenant_id=undefined` would be a request
  // for a tenant named "undefined" rather than a request without one.
  const { client, calls } = make(() =>
    json({ metric: "monthly_active_users", definition: "d", period: "2026-08-01", active_users: 0, series: [] }),
  );
  await client.getUsage();
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/usage");
});

test("getUsage says when the count starts again, and an older server's silence stays silence", async () => {
  const { client } = make(() =>
    json({
      metric: "monthly_active_users",
      definition: "d",
      period: "2026-12-01",
      resets_at: "2027-01-01T00:00:00Z",
      active_users: 3,
      series: [],
    }),
  );
  const usage = await client.getUsage();
  assert.equal(usage.resetsAt, "2027-01-01T00:00:00Z");

  // A server from before `resets_at` says nothing, and the SDK must not fill
  // the gap: the guess a caller would make is the renewal date, which is wrong.
  const { client: older } = make(() =>
    json({ metric: "monthly_active_users", definition: "d", period: "2026-08-01", active_users: 3, series: [] }),
  );
  assert.equal("resetsAt" in (await older.getUsage()), false);
});

test("getUsage survives a server that sends no series", async () => {
  // Defensive rather than speculative: every other mapper here treats its array
  // as optional, because a `.map` on undefined is a TypeError thrown inside the
  // SDK and attributed to the caller.
  const { client } = make(() =>
    json({ metric: "monthly_active_users", definition: "d", period: "2026-08-01", active_users: 3 }),
  );
  const usage = await client.getUsage({ tenantId: "t1" });
  assert.deepEqual(usage.series, []);
  assert.equal(usage.activeUsers, 3);
});

test("getBilling maps the plan, its source and the subscription, and passes an ended one through", async () => {
  const { client, calls } = make(() =>
    json({
      tenant_id: "t1",
      plan: "business",
      source: "subscription",
      override_plan: null,
      billing_enabled: true,
      subscription: {
        plan: "business",
        status: "past_due",
        in_force: true,
        interval: "year",
        current_period_end: "2027-01-31T00:00:00Z",
        cancel_at_period_end: false,
        extra_seats: 3,
      },
    }),
  );
  const billing = await client.getBilling({ tenantId: "t1" });
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/billing?tenant_id=t1");
  assert.equal(billing.plan, "business");
  assert.equal(billing.source, "subscription");
  assert.equal(billing.billingEnabled, true);
  assert.equal(billing.subscription?.inForce, true, "past_due keeps the plan");
  assert.equal(billing.subscription?.extraSeats, 3);
  assert.equal(billing.subscription?.currentPeriodEnd, "2027-01-31T00:00:00Z");

  const none = make(() =>
    json({ tenant_id: "t1", plan: "free", source: "none", override_plan: null, billing_enabled: false, subscription: null }),
  );
  const free = await none.client.getBilling();
  assert.equal(none.calls[0]!.url, "https://api.proteles.com/api/v1/billing");
  assert.equal(free.subscription, null);
});

test("a structured API error becomes ManagementError with code + status", async () => {
  const { client } = make(() => json({ error: "conflict", message: "a tenant with that slug already exists" }, 409));
  await assert.rejects(
    () => client.createTenant({ slug: "dup" }),
    (e: unknown) => {
      assert.ok(e instanceof ManagementError);
      assert.equal(e.code, "conflict");
      assert.equal(e.status, 409);
      assert.match(e.message, /already exists/);
      return true;
    },
  );
});

test("a body the server could not read carries what it could not read", async () => {
  const { client } = make(() =>
    json(
      {
        error: "invalid_request",
        message: "invalid JSON body",
        detail: "unknown field `name`, expected one of `client_name`, `redirect_uris` at line 1 column 7",
      },
      400,
    ),
  );
  await assert.rejects(() => client.listApps({ tenantId: "t1" }), (e: unknown) => {
    assert.ok(e instanceof ManagementError);
    assert.equal(e.message, "invalid JSON body");
    assert.match(e.detail ?? "", /unknown field `name`/);
    return true;
  });
});

test("an error with no detail leaves it undefined", async () => {
  const { client } = make(() => json({ error: "not_found", message: "no such app" }, 404));
  await assert.rejects(() => client.listApps({ tenantId: "t1" }), (e: unknown) => {
    assert.ok(e instanceof ManagementError);
    assert.equal(e.detail, undefined);
    return true;
  });
});

test("a non-JSON error body still throws a ManagementError with the status", async () => {
  const { client } = make(() => new Response("gateway blew up", { status: 502 }));
  await assert.rejects(() => client.listApps({ tenantId: "t1" }), (e: unknown) => {
    assert.ok(e instanceof ManagementError);
    assert.equal(e.status, 502);
    return true;
  });
});

test("the constructor validates required config", () => {
  const fetch = mockFetch(() => json({})).fetch;
  assert.throws(() => new ManagementClient({ baseUrl: "", token: "t", fetch }), ManagementError);
  assert.throws(() => new ManagementClient({ baseUrl: "https://x", token: "", fetch }), ManagementError);
});

// The server reads an absent or empty `scopes` as *unrestricted* — its own
// source calls that "the maximally privileged mint" — and this method's
// documented example used to omit it. So the advertised way to mint a key
// minted one with full authority over the tenant.
test("createApiKey sends the scopes it was given, and they reach the wire", async () => {
  const { client, calls } = make(() =>
    json({ api_key: "mk_x", name: "ci", scopes: ["audit:read"] }),
  );
  await client.createApiKey("t1", { name: "ci", scopes: ["audit:read"] });
  assert.deepEqual(calls[0]!.body, { name: "ci", scopes: ["audit:read"] });
});

// The server mints no key without scopes. The client sends what it is
// given rather than keeping a second copy of the rule, and the server's 400
// reaches the caller as an error — never as a key.
test("an empty scope list is refused, and the refusal reaches the caller", async () => {
  const { client, calls } = make(() =>
    json({ error: "invalid_request", message: "name at least one scope: a key with no scopes would have every permission, and none is minted; known scopes: audit:read" }, 400),
  );
  await assert.rejects(
    () => client.createApiKey("t1", { name: "root", scopes: [] }),
    (e: unknown) => {
      assert.ok(e instanceof ManagementError);
      assert.equal(e.status, 400);
      assert.match(e.message, /at least one scope/);
      return true;
    },
  );
  assert.deepEqual(calls[0]!.body, { name: "root", scopes: [] });

  // And omitting it is a compile error, not a request.
  // @ts-expect-error scopes is required precisely so this cannot be written
  const omitted: CreateApiKeyInput = { name: "ci" };
  void omitted;
});

// A key minted through the SDK could not be revoked through it: `createApiKey`
// returns no `id`, and there was no way to list keys to find one. The mint was
// reachable and the un-mint was not.
test("a key can be found and revoked through the client", async () => {
  const { client, calls } = make((rec) => {
    if (rec.method === "DELETE") return json({ revoked: true, id: "k1" });
    return json({
      keys: [{ id: "k1", name: "ci", scopes: ["audit:read"], created_at: "2026-01-01T00:00:00Z", revoked: false }],
    });
  });
  const keys = await client.listApiKeys("t1");
  assert.equal(keys.length, 1);
  assert.deepEqual(keys[0], {
    id: "k1", name: "ci", scopes: ["audit:read"], createdAt: "2026-01-01T00:00:00Z", revoked: false,
  });

  await client.revokeApiKey("t1", keys[0]!.id);
  assert.equal(calls[1]!.method, "DELETE");
  assert.equal(calls[1]!.url, "https://api.proteles.com/api/v1/tenants/t1/keys/k1");
});

// Custom domains were entirely unreachable from the typed client — the newest
// and most security-sensitive surface in the API had no client at all.
test("a domain can be claimed, verified and released", async () => {
  const { client, calls } = make((rec) => {
    if (rec.method === "DELETE") return new Response(null, { status: 204 });
    if (rec.url.endsWith("/verify")) return json({ domain: "id.acme.test", verified: true });
    return json({
      domain: "id.acme.test", verified: false, verified_at: null, created_at: "2026-01-01T00:00:00Z",
      challenge: { type: "TXT", name: "_proteles-challenge.id.acme.test", value: "tok" },
    });
  });

  const claimed = await client.claimDomain("t1", "id.acme.test");
  assert.equal(claimed.verified, false);
  assert.equal(claimed.verifiedAt, null, "an unverified claim has no proof date");
  assert.equal(claimed.challenge?.name, "_proteles-challenge.id.acme.test");

  const proof = await client.verifyDomain("t1", "id.acme.test");
  assert.equal(proof.verified, true);
  assert.equal(calls[1]!.url, "https://api.proteles.com/api/v1/tenants/t1/domains/id.acme.test/verify");

  await client.releaseDomain("t1", "id.acme.test");
  assert.equal(calls[2]!.method, "DELETE");
});

// A hostname is user-supplied and goes into a path segment.
test("a hostile domain cannot escape its path segment", async () => {
  const { client, calls } = make(() => json({ domain: "x", verified: true }));
  await client.verifyDomain("t1", "../../tenants/other/keys");
  assert.ok(
    !calls[0]!.url.includes("/tenants/other/"),
    `the path was not escaped: ${calls[0]!.url}`,
  );
});

// --- tenant policy fields ---------------------------------------------------
//
// The server has returned these four since the MFA grace period shipped; this
// client dropped them on the floor. A console reading policy through the
// typed client got `undefined` for every tenant and had no way to tell that
// apart from "optional".

test("getTenant carries the MFA policy fields the server returns", async () => {
  const { client } = make(() =>
    json({
      id: "t1",
      slug: "acme",
      status: "active",
      branding: {},
      mfa_policy: "required",
      mfa_grace_days: 14,
      mfa_required_since: "2026-08-01T00:00:00+00:00",
      mfa_grace_until: "2026-08-15T00:00:00+00:00",
    }),
  );
  const tenant = await client.getTenant("t1");
  assert.equal(tenant.mfaPolicy, "required");
  assert.equal(tenant.mfaGraceDays, 14);
  assert.equal(tenant.mfaRequiredSince, "2026-08-01T00:00:00+00:00");
  assert.equal(tenant.mfaGraceUntil, "2026-08-15T00:00:00+00:00");
});

test("getTenant carries the tenant's issuer, and a null one as null", async () => {
  // The issuer an app configures for this tenant. Without the field a caller
  // has no way to know it, and falls back to printing one base URL for every
  // tenant; a mapper that dropped the field would put callers back there.
  const { client } = make(() =>
    json({ id: "t1", slug: "acme", status: "active", issuer: "https://acme.auth.example", mfa_policy: "optional", mfa_grace_days: 0 }),
  );
  assert.equal((await client.getTenant("t1")).issuer, "https://acme.auth.example");

  const { client: bare } = make(() =>
    json({ id: "t1", slug: "acme", status: "active", issuer: null, mfa_policy: "optional", mfa_grace_days: 0 }),
  );
  const tenant = await bare.getTenant("t1");
  assert.equal(tenant.issuer, null);
  assert.ok("issuer" in tenant, "present and null, not absent");
});

test("a zero grace window survives the mapper", async () => {
  // `mfa_grace_days: 0` is a requirement with no window — enrol now or you are
  // locked out. A truthiness test in the mapper would drop precisely this,
  // leaving the strictest setting indistinguishable from an unset one.
  const { client } = make(() =>
    json({ id: "t1", slug: "acme", status: "active", mfa_policy: "required", mfa_grace_days: 0 }),
  );
  const tenant = await client.getTenant("t1");
  assert.equal(tenant.mfaGraceDays, 0);
});

test("a null deadline is carried as null rather than dropped", async () => {
  // "No requirement is running" is an answer. Omitting the key would make the
  // caller guess between that and "this client is too old to know".
  const { client } = make(() =>
    json({
      id: "t1",
      slug: "acme",
      status: "active",
      mfa_policy: "optional",
      mfa_grace_days: 7,
      mfa_required_since: null,
      mfa_grace_until: null,
    }),
  );
  const tenant = await client.getTenant("t1");
  assert.equal(tenant.mfaRequiredSince, null);
  assert.equal(tenant.mfaGraceUntil, null);
  assert.ok("mfaGraceUntil" in tenant, "present and null, not absent");
});

test("listTenants returns summaries without inventing a policy", async () => {
  // GET /api/v1/tenants is a summary: three fields, no policy. Defaulting one
  // in would have this client assert `optional` about a tenant that requires a
  // second factor — the unknown-is-omitted rule, on the field where guessing
  // wrong understates the tenant's security posture.
  const { client } = make(() => json({ tenants: [{ id: "t1", slug: "acme", status: "active" }] }));
  const [tenant] = await client.listTenants();
  assert.equal(tenant!.slug, "acme");
  assert.ok(!("mfaPolicy" in tenant!), "absent, not defaulted");
});

// --- updateTenant -----------------------------------------------------------

test("updateTenant sends only the fields present in the patch", async () => {
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", { mfaPolicy: "required", mfaGraceDays: 30 });
  assert.equal(calls[0]!.method, "PATCH");
  assert.deepEqual(calls[0]!.body, { mfa_policy: "required", mfa_grace_days: 30 });
});

test("updateTenant sends an explicit null to clear the self-registration cap", async () => {
  // The three-state field. `null` means "drop the override, fall back to the
  // deployment default" and is a different request from leaving it alone; a
  // client that could only omit could never make it.
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", { maxSelfRegisteredClients: null });
  assert.deepEqual(calls[0]!.body, { max_self_registered_clients: null });
  assert.ok(
    "max_self_registered_clients" in (calls[0]!.body as Record<string, unknown>),
    "the key must survive serialization — an undefined here would be dropped by JSON.stringify and read as 'leave it alone'",
  );
});

test("updateTenant omits the cap entirely when the patch does not mention it", async () => {
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", { mfaPolicy: "optional" });
  assert.deepEqual(calls[0]!.body, { mfa_policy: "optional" });
});

test("updateTenant sends a cap of zero rather than treating it as unset", async () => {
  // 0 is a real ceiling: this tenant may self-register nothing. Falsy checks
  // are the standing hazard on this field and the reason it is pinned here.
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", { maxSelfRegisteredClients: 0 });
  assert.deepEqual(calls[0]!.body, { max_self_registered_clients: 0 });
});

test("updateTenant sends the four tenant security settings it used to be unable to send", async () => {
  // Each of these was readable through `getTenant` and unsettable through this
  // client. Mid-incident that is the worst possible split: the typed client
  // would tell an operator the email factor was on and offer no way to turn it
  // off.
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", {
    maxMembers: 25,
    mfaSelfRecoveryHours: 24,
    mfaEmailFactorEnabled: false,
    passkeyAttestation: "required",
  });
  assert.deepEqual(calls[0]!.body, {
    max_members: 25,
    mfa_self_recovery_hours: 24,
    mfa_email_factor_enabled: false,
    passkey_attestation: "required",
  });
});

test("updateTenant tells apart clearing a nullable tenant limit from leaving it alone", async () => {
  // `max_members` and `mfa_self_recovery_hours` are `double_option` on the
  // server: absent means "leave it", explicit null means "remove the limit" and
  // "turn self-service recovery off". A client that pruned nulls could not ask
  // for either.
  {
    const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
    await client.updateTenant("t1", { maxMembers: null, mfaSelfRecoveryHours: null });
    assert.deepEqual(calls[0]!.body, { max_members: null, mfa_self_recovery_hours: null });
  }
  {
    const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
    await client.updateTenant("t1", { mfaPolicy: "optional" });
    const body = calls[0]!.body as Record<string, unknown>;
    for (const k of ["max_members", "mfa_self_recovery_hours", "mfa_email_factor_enabled", "passkey_attestation"]) {
      assert.ok(!(k in body), `${k} is untouched when the patch does not mention it`);
    }
  }
});

test("updateTenant sends accountRecoveryCodesEnabled, false included, and nothing when it is absent", async () => {
  // The recovery-codes switch. `false` is how codes are switched off, so the falsy-value
  // trap matters as much here as for the email factor.
  for (const enabled of [true, false]) {
    const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
    await client.updateTenant("t1", { accountRecoveryCodesEnabled: enabled });
    assert.deepEqual(calls[0]!.body, { account_recovery_codes_enabled: enabled });
  }
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", { mfaPolicy: "optional" });
  assert.ok(!("account_recovery_codes_enabled" in (calls[0]!.body as Record<string, unknown>)));
});

test("updateTenant sends both sign-up switches, false included, and neither when absent", async () => {
  // The two sign-up switches. `false` is how sign-up is closed again, so the
  // falsy-value trap matters here as it does for the factors.
  for (const enabled of [true, false]) {
    const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
    await client.updateTenant("t1", { passwordSignupEnabled: enabled, socialSignupEnabled: !enabled });
    assert.deepEqual(calls[0]!.body, { password_signup_enabled: enabled, social_signup_enabled: !enabled });
  }
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", { mfaPolicy: "optional" });
  const body = calls[0]!.body as Record<string, unknown>;
  assert.ok(!("password_signup_enabled" in body) && !("social_signup_enabled" in body));
});

test("updateTenant sends mfaEmailFactorEnabled false rather than dropping it", async () => {
  // The falsy-value trap, and the one that matters most here: `false` is the
  // whole point of the field — it is how the factor gets turned off.
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", { mfaEmailFactorEnabled: false });
  assert.deepEqual(calls[0]!.body, { mfa_email_factor_enabled: false });
});

test("updateTenant sends a member cap of 1 rather than treating it as unset", async () => {
  // 1 is the server's floor, not 0 — "a tenant with no members cannot be
  // administered" — so the smallest legal value is also a truthy one. Kept as a
  // test anyway because the neighbouring cap's floor *is* 0.
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenant("t1", { maxMembers: 1 });
  assert.deepEqual(calls[0]!.body, { max_members: 1 });
});

test("updateTenantBranding still sends exactly what it used to", async () => {
  // It delegates to updateTenant now. The wire shape is the contract.
  const { client, calls } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  await client.updateTenantBranding("t1", { appName: "Acme" });
  assert.deepEqual(calls[0]!.body, { branding: { app_name: "Acme" } });
});

// --- fields the server sends that this client used to drop ------------------
//
// Fourteen of them, across four types, ten marked required by the published
// spec. They were not missed for want of testing: every fixture in this file is
// an untyped object literal, so `tsc` never compared one against `WireApp`, and
// a suite of self-consistent fixtures stays green no matter how much of the
// response the client ignores. These assert the fields exist and survive the
// snake_case → camelCase crossing, which is the only part a fixture can prove.

test("an inactive app is reported as inactive", async () => {
  const { client } = make(() =>
    json({
      apps: [
        {
          client_id: "cid",
          client_name: "Web",
          created_at: "2026-01-01T00:00:00Z",
          is_active: false,
          self_registered: true,
        },
      ],
    }),
  );
  const [app] = await client.listApps();
  // The reason this one is required rather than optional: inactive clients are
  // listed, so a caller that cannot see the flag shows a disabled application
  // as a live one.
  assert.equal(app!.isActive, false);
  assert.equal(app!.selfRegistered, true);
  assert.equal(app!.createdAt, "2026-01-01T00:00:00Z");
});

test("a tenant's plan binding says which of the two reasons a plan does not bind", async () => {
  // The default tenant reads `plans_enforced: false` whether or not the
  // deployment enforces plans; `plan_binding` is what tells the two apart.
  const body = (plan_binding?: string) => ({ id: "t1", slug: "default", status: "active", plans_enforced: false, ...(plan_binding ? { plan_binding } : {}) });
  let { client } = make(() => json(body("platform_tenant")));
  assert.equal((await client.getTenant("t1")).planBinding, "platform_tenant");
  ({ client } = make(() => json(body("not_enforced"))));
  assert.equal((await client.getTenant("t1")).planBinding, "not_enforced");
  // A server before the field: absent, not invented.
  ({ client } = make(() => json(body())));
  const t = await client.getTenant("t1");
  assert.equal(t.planBinding, undefined);
  assert.equal("planBinding" in t, false);
});

test("a tenant's attestation and member policy survive the mapping", async () => {
  const { client } = make(() =>
    json({
      id: "t1",
      slug: "acme",
      status: "active",
      mfa_policy: "required",
      passkey_attestation: "required",
      attestation_ca_count: 0,
      mfa_email_factor_enabled: true,
      account_recovery_codes_enabled: false,
      password_signup_enabled: true,
      social_signup_enabled: false,
      mfa_self_recovery_hours: null,
      max_members: null,
      member_count: 3,
    }),
  );
  const t = await client.getTenant("t1");
  assert.equal(t.passkeyAttestation, "required");
  // Zero, not absent. `"required"` with no CAs behind it is a tenant that can
  // enrol no passkeys at all, and a falsy check here would hide exactly that.
  assert.equal(t.attestationCaCount, 0);
  assert.equal(t.mfaEmailFactorEnabled, true);
  // `false`, not `undefined`: off is an answer.
  assert.equal(t.accountRecoveryCodesEnabled, false);
  assert.equal(t.passwordSignupEnabled, true);
  assert.equal(t.socialSignupEnabled, false);
  // `null` is an answer — "self-recovery is off", "no member cap" — and must not
  // arrive as `undefined`, which means "this response did not say".
  assert.equal(t.mfaSelfRecoveryHours, null);
  assert.equal(t.maxMembers, null);
  assert.equal(t.memberCount, 3);
});

test("a tenant's owner count survives the mapping: zero as zero, null as null, absent as absent", async () => {
  // Zero is the answer that sends an operator to invite an owner, so a falsy
  // check that turned it into "not reported" would hide exactly that tenant.
  for (const [sent, want] of [[0, 0], [null, null], [2, 2]] as const) {
    const { client } = make(() => json({ id: "t1", slug: "acme", status: "active", owner_count: sent }));
    const t = await client.getTenant("t1");
    assert.equal(t.ownerCount, want, `owner_count ${String(sent)}`);
  }
  const { client } = make(() => json({ id: "t1", slug: "acme", status: "active" }));
  assert.equal("ownerCount" in (await client.getTenant("t1")), false, "an older server's silence stays silence");
});

test("inviteTenantOwner posts the address to the tenant's owner-invitations path and maps the answer", async () => {
  const { client, calls } = make(() =>
    json(
      { email: "nina@acme.test", role: "owner", expires_at: "2026-10-21T00:00:00Z", delivered: false, replaced: ["nina@exmaple.test"] },
      202,
    ),
  );
  const sent = await client.inviteTenantOwner("t/1", { email: "nina@acme.test" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.method, "POST");
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/tenants/t%2F1/owner-invitations", "the id stays in its segment");
  assert.deepEqual(calls[0]!.body, { email: "nina@acme.test" }, "the address and nothing else");
  // `delivered: false` is carried, not turned into an error or a true; and
  // the mistyped invitation it withdrew is named.
  assert.deepEqual(sent, {
    email: "nina@acme.test",
    role: "owner",
    expiresAt: "2026-10-21T00:00:00Z",
    delivered: false,
    replaced: ["nina@exmaple.test"],
  });
});

test("withdrawTenantOwnerInvitation deletes on the same path with the address and maps the answer", async () => {
  const { client, calls } = make(() => json({ email: "nina@exmaple.test", withdrawn: false }));
  const out = await client.withdrawTenantOwnerInvitation("t/1", { email: "nina@exmaple.test" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.method, "DELETE");
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/tenants/t%2F1/owner-invitations", "the id stays in its segment");
  assert.deepEqual(calls[0]!.body, { email: "nina@exmaple.test" }, "the address and nothing else");
  // `withdrawn: false` is an answer, not an error or a true.
  assert.deepEqual(out, { email: "nina@exmaple.test", withdrawn: false });
});

test("inviteTenantOwner surfaces a workspace that cannot send mail as the server's error", async () => {
  const { client } = make(() => json({ error: "mail_not_configured", message: "this workspace cannot send mail" }, 409));
  await assert.rejects(client.inviteTenantOwner("t1", { email: "nina@acme.test" }), (err: unknown) => {
    assert.ok(err instanceof ManagementError);
    assert.equal(err.status, 409);
    assert.equal(err.code, "mail_not_configured");
    return true;
  });
});

test("a listing is a summary — the settings are not there to read", async () => {
  // This test used to assert `t.passkeyAttestation === undefined` and call that
  // the point. It was the defect: the field existed on the type, was always
  // undefined, and an optional field reading `undefined` says "this tenant has
  // no attestation policy" — about a tenant that may well require one.
  //
  // `listTenants` now returns `TenantSummary`, so the field is not on the type
  // at all and reading it does not compile. What survives at runtime is that the
  // three fields the listing does carry come through, and nothing is invented.
  const { client } = make(() => json({ tenants: [{ id: "t1", slug: "acme", status: "active" }] }));
  const [t] = await client.listTenants();
  assert.deepEqual(t, { id: "t1", slug: "acme", status: "active" });
  assert.deepEqual(Object.keys(t!), ["id", "slug", "status"]);
});


test("getPlan maps what is applied, including the unrestricted set where plans are not enforced", async () => {
  const { client, calls } = make(() =>
    json({
      tenant_id: "t1",
      plan: "free",
      source: "none",
      enforced: false,
      plan_binding: "not_enforced",
      entitlements: {
        included_active_users: null,
        active_user_overage_billed: false,
        included_seats: null,
        extra_seats_billed: false,
        log_retention_days: null,
        allowed_session_ttl_seconds: null,
        sms: true,
        enhanced_support: false,
      },
    }),
  );
  const p = await client.getPlan({ tenantId: "t1" });
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/plan?tenant_id=t1");
  assert.equal(p.source, "none");
  assert.equal(p.enforced, false);
  // Why: the deployment's switch is off, not the platform's own tenant.
  assert.equal(p.planBinding, "not_enforced");
  assert.equal(p.entitlements.logRetentionDays, null);
  assert.equal(p.entitlements.includedSeats, null);
  assert.equal(p.entitlements.sms, true);
});

test("usage reports the soft cap and whether it is passed", async () => {
  const { client } = make(() =>
    json({
      tenant_id: "t1",
      metric: "monthly_active_users",
      definition: "d",
      period: "2026-08-01",
      active_users: 42,
      soft_cap: 40,
      effective_soft_cap: 40,
      over_soft_cap: true,
      series: [],
    }),
  );
  const u = await client.getUsage();
  assert.equal(u.tenantId, "t1");
  assert.equal(u.softCap, 40);
  assert.equal(u.effectiveSoftCap, 40);
  assert.equal(u.overSoftCap, true);
});

test("an audit event carries the bytes the seal is computed over", async () => {
  const raw = '{"k":"v"}';
  const { client } = make(() =>
    json({
      events: [
        {
          event_type: "app.created",
          severity: "info",
          client_id: null,
          actor_user_id: null,
          ip: null,
          detail: "k=v",
          detail_json: raw,
          leaf_version: 2,
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
    }),
  );
  const [e] = await client.listAudit();
  // Byte-identical, not re-serialised: the seal is computed over these exact
  // bytes, so a client that parsed and re-encoded them would hand callers a
  // string that no longer verifies.
  assert.equal(e!.detailJson, raw);
  assert.equal(e!.leafVersion, 2);
  // A v2 row has no causer at all, and the mapper must say `null` rather than
  // leaving the property undefined — the two are different answers, and only
  // one of them survives `JSON.stringify`.
  assert.equal(e!.causedByUserId, null);
});

test("the administrator who acted and the user acted upon are kept apart", async () => {
  // Both ends on one row, and different people. The two fields are adjacent
  // strings of the same shape in every layer between the database and here, so
  // a transposition anywhere along that path type-checks — and would report
  // the administrator as the person whose access was revoked.
  const { client } = make(() =>
    json({
      events: [
        {
          event_type: "tenant_member.revoked",
          severity: "warning",
          client_id: null,
          actor_user_id: "aaaaaaaa-0000-4000-8000-000000000001",
          caused_by_user_id: "bbbbbbbb-0000-4000-8000-000000000002",
          ip: null,
          detail: "removed 'nina' (admin)",
          detail_json: null,
          leaf_version: 3,
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
    }),
  );
  const [e] = await client.listAudit();
  assert.equal(e!.actorUserId, "aaaaaaaa-0000-4000-8000-000000000001");
  assert.equal(e!.causedByUserId, "bbbbbbbb-0000-4000-8000-000000000002");
});

test("every audit filter the API takes reaches the wire under its own name", async () => {
  // The gap this closes: `ListAuditOptions` took `limit` and nothing else while
  // the API took seven filters, so the search and the causer filter were
  // both unreachable from this client.
  //
  // Asserted per parameter rather than against one assembled URL, so a failure
  // names the filter that is wrong instead of printing two long strings and
  // leaving the reader to diff them.
  const { client, calls } = make(() => json({ events: [], next_cursor: null }));
  await client.listAudit({
    tenantId: "t1",
    limit: 25,
    eventType: ["login.failure", "mfa.failure"],
    severity: "warning",
    actorUserId: "aaaaaaaa-0000-4000-8000-000000000001",
    causedByUserId: "bbbbbbbb-0000-4000-8000-000000000002",
    clientId: "app",
    since: "2026-08-01T00:00:00Z",
    until: "2026-09-01T00:00:00Z",
    cursor: "opaque-cursor",
  });

  const q = new URL(calls[0]!.url).searchParams;
  for (const [key, want] of [
    ["tenant_id", "t1"],
    ["limit", "25"],
    ["event_type", "login.failure,mfa.failure"],
    ["severity", "warning"],
    ["actor_user_id", "aaaaaaaa-0000-4000-8000-000000000001"],
    ["caused_by_user_id", "bbbbbbbb-0000-4000-8000-000000000002"],
    ["client_id", "app"],
    ["since", "2026-08-01T00:00:00Z"],
    ["until", "2026-09-01T00:00:00Z"],
    ["cursor", "opaque-cursor"],
  ] as const) {
    assert.equal(q.get(key), want, `${key} did not reach the wire`);
  }
});

test("the two user filters are not transposed on the way out", async () => {
  // They are adjacent options of the same type with names one word apart, and a
  // client that swapped them would answer "what did this administrator do" with
  // "what was done to them" — plausible, wrong, and invisible without this.
  const { client, calls } = make(() => json({ events: [], next_cursor: null }));
  await client.listAudit({ actorUserId: "subject-id", causedByUserId: "admin-id" });
  const q = new URL(calls[0]!.url).searchParams;
  assert.equal(q.get("actor_user_id"), "subject-id");
  assert.equal(q.get("caused_by_user_id"), "admin-id");
});

test("an empty filter list sends no parameter at all", async () => {
  // The server reads an empty `event_type=` as no constraint, so both spellings
  // return the same rows and this is not a correctness fix. It is still worth
  // pinning: a request should carry what the caller asked for and no more, and
  // "the client sends parameters nobody asked for" is how a client and a server
  // come to disagree about what was requested.
  const { client, calls } = make(() => json({ events: [], next_cursor: null }));
  await client.listAudit({ eventType: [], severity: ["  ", ""] });
  const q = new URL(calls[0]!.url).searchParams;
  assert.equal(q.has("event_type"), false, "an empty array must not become `event_type=`");
  assert.equal(q.has("severity"), false, "and neither must a list of blanks");
});

test("a comma-separated string is accepted as well as an array", async () => {
  // Both spellings exist in the wild — the array because it is what a caller
  // building a filter has, the string because it is what the API documents.
  const { client, calls } = make(() => json({ events: [], next_cursor: null }));
  await client.listAudit({ eventType: "login.failure, mfa.failure " });
  assert.equal(
    new URL(calls[0]!.url).searchParams.get("event_type"),
    "login.failure,mfa.failure",
    "the parts are trimmed, so a space after a comma is not part of the type",
  );
});

test("listAuditPage carries the cursor, and null means the end", async () => {
  // Without this a client cannot read past the first page, which for a tenant
  // with any history is most of their own trail — and the workaround, asking
  // for a huge limit, is the thing keyset paging exists to avoid.
  {
    const { client } = make(() => json({ events: [], next_cursor: "next-page" }));
    const page = await client.listAuditPage();
    assert.equal(page.nextCursor, "next-page");
  }
  {
    const { client } = make(() => json({ events: [], next_cursor: null }));
    assert.equal((await client.listAuditPage()).nextCursor, null);
  }
  {
    // A server that omitted the key entirely still reads as "the end" rather
    // than as `undefined`, so a caller has one value to test rather than two.
    const { client } = make(() => json({ events: [] }));
    assert.equal((await client.listAuditPage()).nextCursor, null);
  }
});

test("listAudit still returns the events alone", async () => {
  // The compatibility half. `listAuditPage` is additive precisely so this
  // signature does not move under callers written against it.
  const { client } = make(() =>
    json({
      events: [
        {
          event_type: "login.success",
          severity: "info",
          client_id: null,
          actor_user_id: null,
          caused_by_user_id: null,
          ip: null,
          detail: null,
          detail_json: null,
          leaf_version: 3,
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
      next_cursor: "more",
    }),
  );
  const events = await client.listAudit();
  assert.ok(Array.isArray(events), "listAudit returns an array, not a page");
  assert.equal(events.length, 1);
  assert.equal(events[0]!.eventType, "login.success");
});

// --- the operations the client could not reach ------------------------------
//
// Fifty-one of sixty-eight, and the shape was consistent: create almost
// everything, change or act on almost nothing. These tests cover the traps
// rather than every method — the wire shapes are generated and the paths are
// held by `sdk-operation-coverage.mjs`, so what is left worth asserting is the
// handful of places where a plausible implementation would be wrong.

test("the incident path reaches the right endpoints", async () => {
  const seen: string[] = [];
  const { client } = make((rec) => {
    seen.push(`${rec.method} ${new URL(rec.url).pathname}`);
    return json({
      user_id: "u1", username: "alice", totp_removed: true, passkeys_removed: 2, note: "n",
      sessions_revoked_at: "2026-09-09T00:00:00Z", reason: "r", performed_by: "platform-token",
      is_active: false, changed: true,
    });
  });
  await client.resetUserMfa("u1", { reason: "lost phone" });
  await client.revokeUserSessions("u1", { reason: "compromise" });
  await client.deactivateUser("u1", { reason: "compromise" });
  await client.reactivateUser("u1", { reason: "cleared" });
  assert.deepEqual(seen, [
    "POST /api/v1/users/u1/mfa/reset",
    "POST /api/v1/users/u1/sessions/revoke",
    "POST /api/v1/users/u1/deactivate",
    "POST /api/v1/users/u1/reactivate",
  ]);
});

test("deactivateUser surfaces a failed session revoke rather than hiding it", async () => {
  // `sessionsRevokedAt: null` on this path does not mean "no sessions" — it
  // means the account was switched off and the revocation did not complete, so
  // the user may still hold a live one. A client that dropped the field, or
  // defaulted it, would turn a follow-up action into silence.
  const { client } = make(() =>
    json({ user_id: "u1", username: "alice", is_active: false, changed: true, sessions_revoked_at: null, performed_by: "platform-token" }),
  );
  const r = await client.deactivateUser("u1", { reason: "compromise" });
  assert.equal(r.sessionsRevokedAt, null);
  assert.equal(r.changed, true);
});

test("bulkUpdateUsers keeps the three counts apart", async () => {
  // A retry shows up entirely in `alreadyInThatState`, a typo entirely in
  // `notFound`. Collapsing them into "how many succeeded" loses both.
  const { client, calls } = make(() =>
    json({ changed: 2, already_in_that_state: 1, not_found: ["u9"], sessions_revoked_at: null }),
  );
  const r = await client.bulkUpdateUsers({ userIds: ["u1", "u2", "u3", "u9"], action: "deactivate", reason: "audit" });
  assert.deepEqual(r, { changed: 2, alreadyInThatState: 1, notFound: ["u9"], sessionsRevokedAt: null });
  assert.deepEqual(calls[0]!.body, {
    user_ids: ["u1", "u2", "u3", "u9"],
    action: "deactivate",
    reason: "audit",
  });
});

test("findUser maps the second-factor status a caller decides on", async () => {
  const { client, calls } = make(() =>
    json({
      id: "u1",
      username: "alice",
      email: null,
      is_active: true,
      mfa: { totp: true, passkeys: 0, recovery_codes_remaining: 0, email: false, sms: true },
    }),
  );
  const u = await client.findUser("alice", { tenantId: "t1" });
  assert.equal(new URL(calls[0]!.url).searchParams.get("username"), "alice");
  assert.equal(new URL(calls[0]!.url).searchParams.get("tenant_id"), "t1");
  // Zero recovery codes with a factor enrolled is the state worth noticing, and
  // `0` is falsy — a truthiness mapping would report it as absent.
  // `sms` is the factor an operator most needs to see before a reset: a lost
  // phone is the commonest reason to call, and the lookup used not to say.
  assert.deepEqual(u.mfa, { totp: true, passkeys: 0, recoveryCodesRemaining: 0, email: false, sms: true });
});

test("the SMS factor's switch reads and writes one shape, and on carries the tenant", async () => {
  const body = {
    tenant_id: "t1",
    sms_factor_enabled: true,
    plan: "team",
    plan_includes_sms: true,
    offered: true,
    deliverable: false,
    daily_limit: 2000,
    sent_today: 0,
    sent_this_month: 12,
    accepted_this_month: 11,
  };
  const { client, calls } = make(() => json(body));
  const read = await client.getSmsFactor({ tenantId: "t1" });
  const written = await client.setSmsFactor({ tenantId: "t1", enabled: true });
  assert.deepEqual(read, written);
  assert.equal(read.acceptedThisMonth, 11);
  assert.equal(read.deliverable, false, "false is a value, not an absence");
  assert.equal(calls[0]!.method, "GET");
  assert.equal(new URL(calls[0]!.url).searchParams.get("tenant_id"), "t1");
  assert.equal(calls[1]!.method, "PUT");
  assert.deepEqual(calls[1]!.body, { tenant_id: "t1", enabled: true });
});

test("rotateSigningKey and rotateApiKey are one path segment apart", async () => {
  const seen: string[] = [];
  const { client } = make((rec) => {
    seen.push(new URL(rec.url).pathname);
    return json({
      signing_key: { kid: "k1", alg: "RS256" },
      id: "k2", api_key: "mk_new", replaces: "k1", previous_key_expires_at: "2026-09-10T00:00:00Z",
    });
  });
  await client.rotateSigningKey("t1");
  await client.rotateApiKey("t1", "k1");
  assert.deepEqual(seen, ["/api/v1/tenants/t1/keys/rotate", "/api/v1/tenants/t1/keys/k1/rotate"]);
});

test("deleteTenant sends the slug back and reports what the audit trail keeps", async () => {
  const { client, calls } = make(() =>
    json({
      id: "t1", slug: "acme", deleted: true, users: 4, clients: 2, api_keys: 1,
      audit_rows: "retained", audit_rows_may_contain_identifiers: true,
    }),
  );
  const r = await client.deleteTenant("t1", { confirmSlug: "acme" });
  assert.deepEqual(calls[0]!.body, { confirm_slug: "acme" });
  // The field an erasure request has to be answered with.
  assert.equal(r.auditRowsMayContainIdentifiers, true);
});

test("replaceWebhook sends url and events every time, because PUT replaces", async () => {
  const { client, calls } = make(() =>
    json({ id: "w1", name: "n", url: "https://x/h", events: ["mfa.admin_reset"], enabled: true, max_deliveries_per_minute: 60, disable_after_dead_letters: 10 }),
  );
  await client.replaceWebhook("w1", { url: "https://x/h", events: ["mfa.admin_reset"] });
  const body = calls[0]!.body as Record<string, unknown>;
  assert.equal(body["url"], "https://x/h");
  assert.deepEqual(body["events"], ["mfa.admin_reset"]);
  // Omitting the secret keeps the stored one; sending an empty one would not.
  assert.ok(!("secret" in body), "an omitted secret is absent, not empty");
});

test("listDeadLetters sends a boolean query parameter", async () => {
  // The `query` type was `string | number | undefined`, so this did not compile
  // until it was widened. A client that stringified it elsewhere would have
  // sent "false" for a parameter whose absence means false.
  const { client, calls } = make(() =>
    json({ outstanding: 0, outstanding_by_endpoint: {}, retention_days: 30, dead_letters: [] }),
  );
  await client.listDeadLetters({ includeAcknowledged: true, limit: 5 });
  const q = new URL(calls[0]!.url).searchParams;
  assert.equal(q.get("include_acknowledged"), "true");
  assert.equal(q.get("limit"), "5");
});

test("replayDeliveries reports that more remain rather than that it failed", async () => {
  const { client } = make(() => json({ requeued: 100, more_may_remain: true }));
  const r = await client.replayDeliveries({ status: "exhausted" });
  assert.deepEqual(r, { requeued: 100, moreMayRemain: true });
});

test("setSoftCap sends an explicit null to remove the cap", async () => {
  const { client, calls } = make(() => json({ tenant_id: "t1", soft_cap: null }));
  const r = await client.setSoftCap({ tenantId: "t1", softCap: null });
  assert.deepEqual(calls[0]!.body, { tenant_id: "t1", soft_cap: null });
  assert.equal(r.softCap, null);
});

test("bindAppServiceAccount clears the binding when no id is given", async () => {
  // `undefined` would be pruned from the body and the server would read the
  // call as "change nothing", which is the opposite of what clearing means.
  const { client, calls } = make(() => json({ client_id: "c1", service_account_id: null }));
  const r = await client.bindAppServiceAccount("c1");
  assert.deepEqual(calls[0]!.body, { service_account_id: null });
  assert.equal(r.serviceAccountId, null);
});

test("setSessionLifetime tells apart clearing the override from leaving it", async () => {
  const { client, calls } = make(() =>
    json({ tenant_id: "t1", session_ttl_seconds: null, effective_session_ttl_seconds: 3600 }),
  );
  await client.setSessionLifetime({ tenantId: "t1", sessionTtlSeconds: null });
  assert.deepEqual(calls[0]!.body, { tenant_id: "t1", session_ttl_seconds: null });
});

test("exportAudit returns the raw NDJSON and carries every audit filter", async () => {
  // It cannot go through `request<T>`, which parses JSON — so it has its own
  // fetch, and the filters had to be shared rather than reimplemented. A client
  // that supported a filter on the listing and not the export would hand back a
  // wider trail than was asked for, silently.
  const body = '{"event_type":"login.failure"}\n{"event_type":"login.failure"}\n';
  const { client, calls } = make(() => new Response(body, { status: 200 }));
  const text = await client.exportAudit({
    tenantId: "t1",
    eventType: ["login.failure"],
    severity: "warning",
    since: "2026-09-01T00:00:00Z",
  });
  assert.equal(text, body);
  const q = new URL(calls[0]!.url).searchParams;
  assert.equal(q.get("tenant_id"), "t1");
  assert.equal(q.get("event_type"), "login.failure");
  assert.equal(q.get("severity"), "warning");
  assert.equal(q.get("since"), "2026-09-01T00:00:00Z");
});

test("exportAudit raises a ManagementError rather than returning an error body", async () => {
  const { client } = make(() => json({ error: "forbidden", message: "nope" }, 403));
  await assert.rejects(() => client.exportAudit(), (e: unknown) => {
    assert.ok(e instanceof ManagementError);
    assert.equal(e.status, 403);
    assert.equal(e.code, "forbidden");
    return true;
  });
});

test("sendTestMail reports a refused message as a fact, not a failure", async () => {
  // The server answers 200 with `sent: false` and an error, because a relay
  // that refuses the message is an answer about the configuration. A client
  // that threw on it would make a diagnostic endpoint undiagnosable.
  const { client } = make(() => json({ sent: false, to: "x@y.test", error: "relay refused" }));
  const r = await client.sendTestMail({ to: "x@y.test" });
  assert.deepEqual(r, { sent: false, to: "x@y.test", via: undefined, error: "relay refused" });
});

test("listResources keeps tenant-wide scopes apart from an audience's", async () => {
  const { client } = make(() =>
    json({
      resources: [{ id: "r1", identifier: "https://api.acme", display_name: "API", scopes: [{ id: "s1", resource_server_id: "r1", name: "read", description: "Read" }] }],
      tenant_scopes: [{ id: "s2", resource_server_id: null, name: "profile", description: "Profile" }],
    }),
  );
  const r = await client.listResources();
  assert.equal(r.resources[0]!.scopes![0]!.resourceServerId, "r1");
  assert.equal(r.tenantScopes[0]!.resourceServerId, null);
});

test("exportTenant carries the omissions as part of the answer", async () => {
  const { client } = make(() =>
    json({
      tenant: { id: "t1" },
      tables: { users: [{ id: "u1" }] },
      truncated: ["audit_log"],
      excluded: [{ table: "oauth_authorization_codes", disposition: "ephemeral", reason: "credential material" }],
    }),
  );
  const e = await client.exportTenant("t1");
  assert.deepEqual(e.truncated, ["audit_log"]);
  assert.equal(e.excluded[0]!.disposition, "ephemeral");
});

const SAML_WIRE = {
  id: "c1",
  name: "Acme Okta",
  idp_entity_id: "https://idp.acme.test",
  idp_sso_url: "https://idp.acme.test/sso",
  certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
  certificate_next_pem: null,
  sp_entity_id: "https://auth.acme.test",
  acs_url: "https://auth.acme.test/saml/c1/acs",
  attr_username: null,
  attr_email: "email",
  max_assertion_lifetime_seconds: 600,
  allow_unsolicited: false,
  relay_state_hosts: ["app.acme.test"],
  enabled: true,
  created_at: "2026-09-13T00:00:00Z",
  updated_at: "2026-09-13T00:00:00Z",
};

test("listSamlConnections unwraps the envelope and maps every field", async () => {
  const { client, calls } = make(() => json({ connections: [SAML_WIRE] }));
  const got = await client.listSamlConnections({ tenantId: "t1" });
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/saml/connections?tenant_id=t1");
  assert.equal(got.length, 1);
  // Every wire field reaches a public one. A mapper that drops a field is the
  // failure this asserts: the value simply goes missing, and nothing else says so.
  assert.deepEqual(got[0], {
    id: "c1",
    name: "Acme Okta",
    idpEntityId: "https://idp.acme.test",
    idpSsoUrl: "https://idp.acme.test/sso",
    certificatePem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
    certificateNextPem: null,
    spEntityId: "https://auth.acme.test",
    acsUrl: "https://auth.acme.test/saml/c1/acs",
    attrUsername: null,
    attrEmail: "email",
    maxAssertionLifetimeSeconds: 600,
    allowUnsolicited: false,
    relayStateHosts: ["app.acme.test"],
    enabled: true,
    createdAt: "2026-09-13T00:00:00Z",
    updatedAt: "2026-09-13T00:00:00Z",
  });
});

test("createSamlConnection snake-cases every field it sends", async () => {
  const { client, calls } = make(() => json(SAML_WIRE, 201));
  await client.createSamlConnection({
    tenantId: "t1",
    name: "Acme Okta",
    idpEntityId: "https://idp.acme.test",
    idpSsoUrl: "https://idp.acme.test/sso",
    certificatePem: "pem",
    spEntityId: "https://auth.acme.test",
    acsUrl: "https://auth.acme.test/saml/c1/acs",
    attrEmail: "email",
    relayStateHosts: ["app.acme.test"],
    enabled: true,
  });
  assert.equal(calls[0]!.method, "POST");
  assert.deepEqual(calls[0]!.body, {
    tenant_id: "t1",
    name: "Acme Okta",
    idp_entity_id: "https://idp.acme.test",
    idp_sso_url: "https://idp.acme.test/sso",
    certificate_pem: "pem",
    sp_entity_id: "https://auth.acme.test",
    acs_url: "https://auth.acme.test/saml/c1/acs",
    attr_email: "email",
    relay_state_hosts: ["app.acme.test"],
    enabled: true,
  });
  // The optional policy fields are absent rather than null: the server's
  // defaults are the refusing answer, and sending an explicit null would ask it
  // to store one.
  const body = calls[0]!.body as Record<string, unknown>;
  for (const absent of ["certificate_next_pem", "attr_username", "max_assertion_lifetime_seconds", "allow_unsolicited"]) {
    assert.ok(!(absent in body), `${absent} must not be sent when unset`);
  }
});

test("replaceSamlConnection is a PUT to the connection, and delete carries the tenant", async () => {
  {
    const { client, calls } = make(() => json(SAML_WIRE));
    await client.replaceSamlConnection("c1", {
      name: "Acme Okta",
      idpEntityId: "https://idp.acme.test",
      idpSsoUrl: "https://idp.acme.test/sso",
      certificatePem: "pem",
      spEntityId: "https://auth.acme.test",
      acsUrl: "https://auth.acme.test/saml/c1/acs",
    });
    assert.equal(calls[0]!.method, "PUT");
    assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/saml/connections/c1");
  }
  {
    const { client, calls } = make(() => new Response(null, { status: 204 }));
    await client.deleteSamlConnection("c1", { tenantId: "t1" });
    assert.equal(calls[0]!.method, "DELETE");
    assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/saml/connections/c1?tenant_id=t1");
  }
});

test("a connection id with a slash cannot escape its path", async () => {
  const { client, calls } = make(() => json(SAML_WIRE));
  await client.getSamlConnection("../../tenants");
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/saml/connections/..%2F..%2Ftenants");
});

test("the per-tenant SAML switch is read and written on the tenant, not the connection", async () => {
  {
    const { client, calls } = make(() => json({ enabled: false }));
    const got = await client.getTenantSaml("t1");
    assert.equal(calls[0]!.method, "GET");
    assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/tenants/t1/saml");
    assert.deepEqual(got, { enabled: false });
  }
  {
    const { client, calls } = make(() => json({ enabled: true }));
    const got = await client.setTenantSaml("t1", true);
    assert.equal(calls[0]!.method, "PUT");
    assert.deepEqual(calls[0]!.body, { enabled: true });
    assert.deepEqual(got, { enabled: true });
  }
  // Turning it off sends the field rather than omitting it: `request` prunes
  // undefined, and an omitted `enabled` would be a body the server refuses
  // rather than a switch set to false.
  {
    const { client, calls } = make(() => json({ enabled: false }));
    await client.setTenantSaml("t1", false);
    assert.deepEqual(calls[0]!.body, { enabled: false });
  }
});

test("the identity-provider switch is its own path, not the phase 1 one", async () => {
  {
    const { client, calls } = make(() => json({ enabled: false, sso_url: null }));
    const got = await client.getTenantSamlIdp("t1");
    assert.equal(calls[0]!.method, "GET");
    assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/tenants/t1/saml-idp");
    assert.deepEqual(got, { enabled: false, ssoUrl: null }, "nothing is pinned until the first enable");
  }
  {
    // The address the server pinned comes back camelCased, and it is the
    // tenant's own origin rather than the issuer — which is the whole point,
    // and the only thing here that would catch the mapper dropping the field.
    const pinned = "https://acme.auth.example.com/saml/idp/0b1e.../sso";
    const { client, calls } = make(() => json({ enabled: true, sso_url: pinned }));
    const got = await client.setTenantSamlIdp("t1", true);
    assert.equal(calls[0]!.method, "PUT");
    assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/tenants/t1/saml-idp");
    assert.deepEqual(calls[0]!.body, { enabled: true });
    assert.deepEqual(got, { enabled: true, ssoUrl: pinned });
  }
  {
    const { client, calls } = make(() => json({ enabled: false, sso_url: null }));
    await client.setTenantSamlIdp("t1", false);
    assert.deepEqual(calls[0]!.body, { enabled: false }, "false is sent, not pruned");
  }
});

test("a SAML application's single-logout status reaches the caller as the server derived it", async () => {
  // Whether a registration can take part in single logout is shown, not
  // left to be inferred from a partial logout later.
  const wire = (slo: string | null, cert: string | null, status: string) => ({
    id: "sp1",
    name: "Payroll",
    sp_entity_id: "https://payroll.example.test",
    acs_urls: ["https://payroll.example.test/acs"],
    default_acs_url: "https://payroll.example.test/acs",
    request_signing_certificate_pem: cert,
    name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    enrol_on_first_sign_in: true,
    slo_url: slo,
    single_logout: status,
    open_to_every_tenant_user: false,
    enabled: true,
    created_at: "2026-10-08T00:00:00Z",
    updated_at: "2026-10-08T00:00:00Z",
  });
  const { client } = make(() =>
    json({
      service_providers: [
        wire(null, null, "no_logout_endpoint_or_certificate"),
        wire(null, "pem", "no_logout_endpoint"),
        wire("https://payroll.example.test/slo", null, "no_certificate"),
        wire("https://payroll.example.test/slo", "pem", "takes_part"),
      ],
    }),
  );
  const got = await client.listSamlServiceProviders({ tenantId: "t1" });
  assert.deepEqual(
    got.map((sp) => [sp.sloUrl, sp.singleLogout]),
    [
      [null, "no_logout_endpoint_or_certificate"],
      [null, "no_logout_endpoint"],
      ["https://payroll.example.test/slo", "no_certificate"],
      ["https://payroll.example.test/slo", "takes_part"],
    ],
  );
});

test("checkApp reads the findings for one app, in the tenant asked for", async () => {
  const { client, calls } = make(() =>
    json({
      client_id: "web",
      client_name: "Web",
      ready: false,
      findings: [
        { check: "active", level: "ok", message: "The app is switched on." },
        { check: "redirect_uris", level: "problem", message: "http://app.example/cb is plain http." },
      ],
    }),
  );
  const result = await client.checkApp("web", { tenantId: "t-1" });
  assert.equal(calls[0]!.method, "GET");
  assert.equal(calls[0]!.url, "https://api.proteles.com/api/v1/apps/web/check?tenant_id=t-1");
  assert.deepEqual(result, {
    clientId: "web",
    clientName: "Web",
    ready: false,
    findings: [
      { check: "active", level: "ok", message: "The app is switched on." },
      { check: "redirect_uris", level: "problem", message: "http://app.example/cb is plain http." },
    ],
  });
});
