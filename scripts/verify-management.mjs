// Live integration check for @proteles/management: drives the built client
// through a real control-plane lifecycle against a running server — provision a
// tenant, mint a key, create an app, configure a connection, read it back, and
// read the audit trail. Proves the client's wire mapping matches the server.
//
// Env: MGMT_BASE_URL (default http://127.0.0.1:8080), MGMT_TOKEN (platform
//      bootstrap token), MGMT_TENANT_BASE_HOST (optional; see step 5). Exit
//      code is non-zero on any failed assertion.

import assert from "node:assert/strict";
import { ManagementClient } from "../packages/management/dist/index.js";

const BASE_URL = process.env.MGMT_BASE_URL || "http://127.0.0.1:8080";
const TOKEN = process.env.MGMT_TOKEN;
if (!TOKEN) {
  console.error("missing required env MGMT_TOKEN");
  process.exit(2);
}

const ok = (msg) => console.log(`  ✓ ${msg}`);
// A slug unique to this run without Math.random/Date (kept deterministic-ish).
const slug = `mgmtsdk${process.pid}`;

const mgmt = new ManagementClient({ baseUrl: BASE_URL, token: TOKEN });

async function main() {
  // 1. Provision a tenant (platform token).
  const tenant = await mgmt.createTenant({ slug, displayName: "Mgmt SDK Co" });
  assert.equal(tenant.slug, slug, "tenant created with the requested slug");
  assert.ok(tenant.id, "tenant has an id");
  ok(`created tenant ${tenant.slug} (${tenant.id})`);

  // 2. Mint a tenant API key, scoped to what the steps below do with it.
  // Without `usage:read`, which step 8 needs absent to prove the gate refuses it.
  const key = await mgmt.createApiKey(tenant.id, {
    name: "sdk-ci",
    scopes: ["apps:write", "connections:write", "audit:read", "tenant:read"],
  });
  assert.ok(key.apiKey.startsWith("mk_"), "minted a prefixed API key");
  ok("minted a tenant API key");

  // A key with no scopes is not minted, and the refusal reaches the
  // caller as an error rather than as a key.
  await assert.rejects(
    () => mgmt.createApiKey(tenant.id, { name: "sdk-ci-unscoped", scopes: [] }),
    /** @param {any} e */
    (e) => {
      assert.equal(e.status, 400, "a key that names no scopes is refused");
      assert.match(e.message, /at least one scope/, "and the refusal says what to send");
      return true;
    },
  );
  ok("a key with no scopes is refused (400)");

  // 3. A tenant-scoped client can create an app in its own tenant (no tenantId).
  const tenantClient = new ManagementClient({ baseUrl: BASE_URL, token: key.apiKey });
  const app = await tenantClient.createApp({
    clientName: "SDK App",
    tokenEndpointAuthMethod: "client_secret_basic",
    grantTypes: ["authorization_code", "refresh_token"],
    redirectUris: ["https://sdk.example/cb"],
    scopes: ["openid", "profile", "email"],
    firstParty: true,
  });
  assert.ok(app.clientId, "app got a client_id");
  assert.ok(app.clientSecret, "a confidential app returned its secret once");
  ok(`created app ${app.clientId} via the tenant key`);

  // 4. It shows up in the listing.
  const apps = await tenantClient.listApps();
  assert.ok(apps.some((a) => a.clientId === app.clientId), "the new app appears in listApps");
  ok("listApps returns the new app");

  // 5. Configure a social connection; the secret is never echoed back.
  //
  // The redirect_uri has to be this server's own callback on a host of the
  // tenant, or the server refuses the write. That host is `<slug>.<base host>`.
  // BASE_URL's host is the base unless it is an IP address, which has no
  // subdomains: an integration run reaches the server at 127.0.0.1, and the base host
  // there is the issuer's, localhost. MGMT_TENANT_BASE_HOST overrides both.
  const base = new URL(BASE_URL);
  const baseIsIp = /^\d+(\.\d+){3}$/.test(base.hostname) || base.hostname.startsWith("[");
  const baseHost = process.env.MGMT_TENANT_BASE_HOST || (baseIsIp ? "localhost" : base.hostname);
  const callback = `${base.protocol}//${slug}.${baseHost}${base.port ? `:${base.port}` : ""}/login/google/callback`;
  const conn = await tenantClient.upsertConnection({
    provider: "google",
    clientId: "goog-client",
    clientSecret: "goog-secret",
    redirectUri: callback,
  });
  assert.equal(conn.provider, "google");
  assert.equal(conn.enabled, true);
  assert.ok(!JSON.stringify(conn).includes("goog-secret"), "the connection secret is not returned");
  const conns = await tenantClient.listConnections();
  assert.ok(conns.some((c) => c.provider === "google" && c.clientId === "goog-client"), "connection appears in listConnections");
  ok("configured and read back a google connection (secret withheld)");

  // 6. Branding round-trips through PATCH + GET.
  await mgmt.updateTenantBranding(tenant.id, { appName: "Mgmt SDK Login", primaryColor: "#0af" });
  const fetched = await mgmt.getTenant(tenant.id);
  assert.equal(fetched.branding?.appName, "Mgmt SDK Login", "branding persisted");
  assert.equal(fetched.branding?.primaryColor, "#0af");
  ok("branding updated and read back");

  // 7. The audit trail reflects the app + connection changes.
  const events = await tenantClient.listAudit({ limit: 50 });
  const types = new Set(events.map((e) => e.eventType));
  assert.ok(types.has("app.created"), "audit records app.created");
  assert.ok(types.has("connection.updated"), "audit records connection.updated");
  ok(`read ${events.length} audit events (incl. app.created, connection.updated)`);

  // 8. Usage. The platform token can always read it; a tenant key needs the
  //    `usage:read` scope, which the key minted above deliberately lacks — so
  //    this proves both halves of the gate rather than only the open one.
  const usage = await mgmt.getUsage({ tenantId: tenant.id });
  assert.equal(usage.metric, "monthly_active_users", "the metric names itself");
  assert.ok(Array.isArray(usage.series) && usage.series.length > 0, "a series came back");
  assert.equal(usage.series.at(-1).period, usage.period, "the headline is the last point");
  assert.ok(/calendar month/.test(usage.definition), "the definition travels with the number");
  ok(`read usage: ${usage.activeUsers} active in ${usage.period}, ${usage.series.length} months of history`);

  await assert.rejects(
    () => tenantClient.getUsage(),
    /** @param {any} e */
    (e) => {
      assert.equal(e.status, 403, "a tenant key without usage:read cannot read usage");
      return true;
    },
  );
  ok("a tenant key without usage:read is refused usage (403)");

  const usageKey = await mgmt.createApiKey(tenant.id, { name: "sdk-ci-usage", scopes: ["usage:read"] });
  const usageClient = new ManagementClient({ baseUrl: BASE_URL, token: usageKey.apiKey });
  const own = await usageClient.getUsage();
  assert.equal(typeof own.activeUsers, "number", "a scoped key reads its own usage");
  ok("a `usage:read` key reads its own tenant's usage");

  // 9. Cross-tenant isolation: a tenant key naming another tenant is refused.
  await assert.rejects(
    () => tenantClient.listApps({ tenantId: "00000000-0000-0000-0000-000000000001" }),
    /** @param {any} e */
    (e) => {
      assert.equal(e.status, 403, "cross-tenant access is forbidden");
      return true;
    },
  );
  ok("a tenant key is refused another tenant's data (403)");

  // 10. The incident path, end to end.
  //
  // These methods did not exist until the client reached the whole API, and
  // they are the ones a mock-fetch test proves least about: a suite of
  // self-consistent fixtures stays green no matter how far the wire has moved.
  // The sequence below is the real one an operator runs — find the account,
  // see what it holds, clear the factor, end the sessions, switch it off, and
  // switch it back on — so each step's output feeds the next and a wrong
  // mapping anywhere breaks the chain rather than being asserted around.
  const person = await mgmt.createUser({
    tenantId: tenant.id,
    username: "incident-subject",
    password: "correct horse battery staple 9",
  });
  ok(`created a user to run the incident path against (${person.id})`);

  const found = await mgmt.findUser("incident-subject", { tenantId: tenant.id });
  assert.equal(found.id, person.id, "findUser returns the account just created");
  assert.equal(found.isActive, true, "and reports it active");
  // `0`, not absent. A truthy mapping would report "no recovery codes left" and
  // "this response did not say" identically, and they are different answers.
  assert.equal(typeof found.mfa.recoveryCodesRemaining, "number", "second-factor status is a number");
  ok("findUser reads the account and its second-factor status");

  const reset = await mgmt.resetUserMfa(person.id, { tenantId: tenant.id, reason: "sdk-ci lost phone" });
  assert.equal(reset.userId, person.id, "the reset names the account it acted on");
  assert.equal(typeof reset.passkeysRemoved, "number", "and says how many passkeys went");
  ok("resetUserMfa clears the second factors and reports what it removed");

  const revoked = await mgmt.revokeUserSessions(person.id, {
    tenantId: tenant.id,
    reason: "sdk-ci compromise",
  });
  assert.ok(revoked.sessionsRevokedAt, "the revocation carries a timestamp");
  assert.match(revoked.performedBy, /platform-token|tenant-api-key/, "and names the credential that did it");
  ok("revokeUserSessions ends every session and records who did it");

  const off = await mgmt.deactivateUser(person.id, { tenantId: tenant.id, reason: "sdk-ci" });
  assert.equal(off.isActive, false, "the account is off");
  assert.equal(off.changed, true, "and it changed, because it was on");
  ok("deactivateUser switches the account off");

  // Twice, because `changed: false` is the field that tells a retry from a
  // no-op, and it is only observable by asking again.
  const again = await mgmt.deactivateUser(person.id, { tenantId: tenant.id, reason: "sdk-ci retry" });
  assert.equal(again.changed, false, "a repeat reports changed: false rather than failing");
  ok("and a repeat is reported as unchanged rather than as an error");

  const on = await mgmt.reactivateUser(person.id, { tenantId: tenant.id, reason: "sdk-ci cleared" });
  assert.equal(on.isActive, true, "the account is back on");
  assert.equal(on.sessionsRevokedAt, null, "reactivation restores no sessions, and says so");
  ok("reactivateUser switches it back on without restoring sessions");

  // 11. The other half of a leaked-credential response: rotate with an overlap,
  // then end the overlap. Both were unreachable from this client.
  // `tenantId` is not decoration on this call: `rotate_app_secret` binds
  // `Query<TenantQuery>`, so the platform token has nothing to scope to without
  // it. The client took no tenant at all until this test failed against a real
  // server with "tenant_id is required when using the platform token" — which
  // is the fourth parameter-placement bug this pass, and the second that only a
  // live request could find.
  const rotated = await mgmt.rotateAppSecret(app.clientId, { tenantId: tenant.id, overlapHours: 1 });
  assert.equal(rotated.clientId, app.clientId, "the rotation names the client");
  assert.ok(rotated.clientSecret, "and returns the new secret once");
  assert.ok(rotated.previousSecretExpiresAt, "and says when the old one stops working");
  ok("rotateAppSecret issues a new secret with an overlap");

  await mgmt.retireAppSecret(app.clientId, { tenantId: tenant.id });
  ok("retireAppSecret ends the overlap");

  // 12. An app can now be changed, not only created.
  const updated = await mgmt.updateApp(app.clientId, {
    tenantId: tenant.id,
    clientName: "Mgmt SDK App (renamed)",
  });
  assert.equal(updated.clientName, "Mgmt SDK App (renamed)", "updateApp renames the client");
  // The listing does not carry these two; the update response does. They are
  // different payloads, and this is where that stops being a claim.
  assert.ok(Array.isArray(updated.postLogoutRedirectUris), "and carries post-logout URIs");
  assert.ok(Array.isArray(updated.scopes), "and scopes");
  ok("updateApp changes a client and answers with the wider payload");

  // 13. Webhooks: the whole subsystem, previously absent.
  const hook = await mgmt.createWebhook({
    tenantId: tenant.id,
    name: "sdk-ci",
    url: "https://example.com/hook",
    secret: "sdk-ci-secret-value-long-enough",
    events: ["webhook.dead_letter"],
  });
  assert.ok(hook.id, "createWebhook returns an id");
  const hooks = await mgmt.listWebhooks({ tenantId: tenant.id });
  assert.ok(hooks.some((h) => h.id === hook.id), "and the endpoint is listed back");
  const one = await mgmt.getWebhook(hook.id, { tenantId: tenant.id });
  assert.equal(one.url, "https://example.com/hook", "and reads back with its URL");
  // Never returned, and this is the assertion that says so rather than a
  // comment claiming it.
  assert.ok(!("secret" in one), "the signing secret is never returned");
  await mgmt.deleteWebhook(hook.id, { tenantId: tenant.id });
  ok("webhooks can be created, listed, read and deleted");

  // 14. Session lifetime, and the three-state override.
  //
  // Driven from the PLATFORM client on both verbs, which is the whole point of
  // this section now. It used to read through the tenant key because
  // `get_session_lifetime` resolved its tenant from the credential and read no
  // `tenant_id` — so an operator could set a tenant's session lifetime and not
  // read it back. Writing this test with one credential against both verbs is
  // what surfaced that; the read takes a tenant now.
  const lifetime = await mgmt.getSessionLifetime({ tenantId: tenant.id });
  assert.equal(typeof lifetime.effectiveSessionTtlSeconds, "number", "an effective TTL always applies");
  assert.equal(lifetime.tenantId, tenant.id, "the read resolved the tenant it was given");
  // A value the tenant's plan offers: on FREE that is one of the three listed
  // choices (and the five-minute minimum is refused), on the paid plans the
  // minimum itself.
  const choice = lifetime.allowedSessionTtlSeconds?.[0] ?? lifetime.minSessionTtlSeconds;
  assert.equal(typeof lifetime.plan, "string", "the read says which plan the choices come from");
  const set = await mgmt.setSessionLifetime({
    tenantId: tenant.id,
    sessionTtlSeconds: choice,
  });
  assert.equal(set.sessionTtlSeconds, choice, "the override is set");
  const cleared = await mgmt.setSessionLifetime({ tenantId: tenant.id, sessionTtlSeconds: null });
  assert.equal(cleared.sessionTtlSeconds, null, "and an explicit null clears it");
  assert.equal(
    cleared.effectiveSessionTtlSeconds,
    lifetime.defaultSessionTtlSeconds,
    "falling back to the deployment default",
  );
  ok("setSessionLifetime tells apart setting an override from clearing it");

  // And the read a tenant key does for itself still works without naming one,
  // because `tenant_id` is optional rather than newly required.
  const ownLifetime = await tenantClient.getSessionLifetime();
  assert.equal(ownLifetime.tenantId, tenant.id, "a tenant key still reads its own without naming it");
  ok("both credentials can read the session lifetime, which was the whole defect");

  // 15. The audit export, which does not answer with JSON.
  const ndjson = await mgmt.exportAudit({ tenantId: tenant.id, limit: 5 });
  assert.equal(typeof ndjson, "string", "exportAudit returns raw text");
  for (const line of ndjson.split("\n").filter(Boolean)) {
    JSON.parse(line); // one object per line, or this throws
  }
  ok("exportAudit returns NDJSON, one parseable object per line");
}

main()
  .then(() => console.log("management client live integration: all checks passed"))
  .catch((e) => {
    console.error(`management client live integration FAILED: ${e.message}`);
    process.exit(1);
  });
