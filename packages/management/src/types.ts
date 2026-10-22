//! Public types for the Management API client. Everything is camelCase; the
//! client maps to/from the API's snake_case wire format.
//!
//! The value *sets* come from `./generated/enums`, which is produced from
//! `spec/openapi.json` and checked in CI. Field names stay hand-written
//! because they are camelCase here and snake_case on the wire; the members of a
//! union are identical on both sides and are exactly what went stale — this
//! file said `MfaPolicy = "optional" | "required"` for as long as the server
//! had a third policy, and declared `provider` two different ways, `string` on
//! one interface and a full union on another, for the same four values.

import type * as wire from "./generated/wire.js";
import type {
  BillingSource as WireBillingSource,
  ClientType as WireClientType,
  Interval as WireInterval,
  OverridePlan as WireOverridePlan,
  MfaPolicy as WireMfaPolicy,
  PasskeyAttestation as WirePasskeyAttestation,
  PlanBinding as WirePlanBinding,
  Provider as WireProvider,
  Severity as WireSeverity,
  SingleLogout as WireSingleLogout,
  TokenEndpointAuthMethod as WireTokenEndpointAuthMethod,
} from "./generated/enums.js";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ManagementClientConfig {
  /** Base URL of the Proteles server, e.g. `https://auth.proteles.com`. */
  baseUrl: string;
  /** A credential: the platform bootstrap token (full, cross-tenant access) or
   *  a per-tenant management API key (its own tenant only). Sent as a bearer. */
  token: string;
  /** Custom fetch; defaults to the global. */
  fetch?: FetchLike;
  /**
   * Per-request timeout in milliseconds (default 10000), the answer's body
   * included. A large `exportAudit` may need more.
   */
  timeoutMs?: number;
}

/** Re-exported so callers can name them without reaching into `generated/`. */
export type ClientType = WireClientType;
export type Provider = WireProvider;
export type Severity = WireSeverity;
/** Whether a SAML application can take part in single logout. */
export type SingleLogout = WireSingleLogout;
export type TokenEndpointAuthMethod = WireTokenEndpointAuthMethod;

export interface Branding {
  appName?: string;
  logoUri?: string;
  primaryColor?: string;
}

/**
 * `"optional"`, `"required"`, or `"passkey"`. Anything else the server rejects.
 *
 * `"passkey"` is `"required"` narrowed to one factor: TOTP does not satisfy it.
 * A user holding only TOTP is still challenged for it at sign-in and is then
 * made to register a passkey — the challenge is not skipped, because the
 * enrolment page is where a passkey gets registered and a password alone must
 * not reach it.
 *
 * Moving between `"required"` and `"passkey"` does not restart the rollout
 * window; the requirement has been running the whole time.
 */
export type MfaPolicy = WireMfaPolicy;
/** Whether a tenant demands an attestation chain when a passkey is enrolled. */
export type PasskeyAttestation = WirePasskeyAttestation;
/**
 * A tenant's plan. What it includes comes from {@link ManagementClient.getPlan},
 * read from the server's own table, so this client never carries a copy of the
 * pricing.
 */
export type Plan = wire.Plan;
/** A plan that is bought: what a subscription can be for. */
export type PaidPlan = wire.PaidPlan;
/**
 * Why a plan does or does not bind a tenant, in the server's order:
 * `"not_enforced"` — the deployment does not enforce plans (`PLANS_ENFORCED`
 * is off), checked first, for every tenant; `"platform_tenant"` — plans are
 * enforced and this is the platform's own (default) tenant, which no plan
 * limits; `"plan"` — held to its plan. The two reasons a plan does not bind
 * are told apart only here.
 */
export type PlanBinding = WirePlanBinding;

/**
 * What every tenant response carries: the three fields that identify it.
 *
 * `POST /tenants` and `GET /tenants` answer with exactly this and nothing more
 * — the server's list and create paths serialise three keys. Naming that shape
 * is what lets `Tenant` below stop lying.
 */
export interface TenantSummary {
  id: string;
  /** Always lowercase; the server normalises it on create. */
  slug: string;
  status: string;
}

/**
 * A tenant as `getTenant` and `updateTenant` return it — every setting present.
 *
 * **This type used to serve the listing too, and that is why every field below
 * was optional.** The cost was not cosmetic. `listTenants()` and
 * `createTenant()` handed back a value whose `mfaPolicy` was *always*
 * `undefined`, and because the field was optional that reads as "this tenant
 * has no MFA policy" rather than "this response does not say" — the type could
 * not tell the two apart, so the distinction lived in a doc comment no compiler
 * reads. An operator checking whether a tenant enforces MFA could get "no" from
 * a tenant that requires it.
 *
 * Two types say it instead: `listTenants` returns `TenantSummary[]`, which does
 * not have the field at all, so reading it is a compile error rather than a
 * confident wrong answer. Call `getTenant` when the policy matters — and now
 * the compiler tells you to.
 */
export interface Tenant extends TenantSummary {
  /**
   * The OpenID Connect issuer an application configures to sign this tenant's
   * users in — `https://<slug>.<base host>`, or the server's issuer for the
   * default tenant. `null` on a deployment with no tenant base host.
   */
  issuer: string | null;
  /** `{}` when nothing is configured; never absent. */
  branding: Branding;
  /** Whether a second factor is required of this tenant's users. */
  mfaPolicy: MfaPolicy;
  /** Days a user has to enrol after the requirement begins. `0` means at once. */
  mfaGraceDays: number;
  /** RFC 3339. When the requirement began; `null` while the policy is optional. */
  mfaRequiredSince: string | null;
  /** RFC 3339. When the window shuts — what an operator actually needs. */
  mfaGraceUntil: string | null;
  /** Hours a user has for self-service recovery; `null` when it is off. */
  mfaSelfRecoveryHours: number | null;
  /** Whether a mailed code counts as a second factor. */
  mfaEmailFactorEnabled: boolean;
  /**
   * Whether accounts with no confirmed email address may hold a saved
   * account-recovery code, spent at `/account/recover` to choose a new password.
   */
  accountRecoveryCodesEnabled: boolean;
  /**
   * Whether a person may make their own account on this tenant's hosted
   * sign-up page, with an address and a password.
   */
  passwordSignupEnabled: boolean;
  /**
   * Whether a first sign-in through a social connection makes an account. Off,
   * a person who already has one still signs in that way.
   */
  socialSignupEnabled: boolean;
  /** Whether an attestation chain is demanded when a passkey is enrolled. */
  passkeyAttestation: PasskeyAttestation;
  /** How many attestation CAs this tenant accepts. */
  attestationCaCount: number;
  /** The member ceiling; `null` when there is none. */
  maxMembers: number | null;
  /** Members held today. */
  memberCount: number;
  /**
   * How many of those members are owners: whether anybody can open the
   * tenant's console and hand out roles. A tenant made with `createTenant`
   * starts at `0`; `inviteTenantOwner` invites one. `null` when the server
   * could not count them. Absent from a server that predates `owner_count`.
   */
  ownerCount?: number | null;
  /** The plan in force: the operator's override when set, else the subscription. */
  plan: Plan;
  /** What the billing provider says the customer pays for. */
  planSubscribed: Plan;
  /** The operator's override, or `null`. */
  planOverride: Plan | null;
  /**
   * What a new member grant is held to: the lower of the plan's cap (five on
   * FREE and TEAM; none on BUSINESS, which sells seats; none on any plan where
   * `plansEnforced` is false) and `maxMembers`. `null` when neither caps.
   */
  seatCap: number | null;
  /**
   * Whether this tenant is held to its plan: the deployment enforces plans
   * (`PLANS_ENFORCED`) and the tenant is not the platform's own (the default
   * tenant, which no plan limits). `false`: `plan` is recorded and shown, and
   * limits nothing. Absent from a server that predates the switch, which
   * enforced every plan on every tenant.
   */
  plansEnforced?: boolean;
  /**
   * Why the plan does or does not bind: `"not_enforced"` (`PLANS_ENFORCED` is
   * off) or `"platform_tenant"` (the default tenant, plans enforced) where
   * `plansEnforced` is false, `"plan"` where it is true — so on the default
   * tenant this, not `plansEnforced`, says whether the deployment enforces
   * plans. Absent from a server before 2026-10-03.
   */
  planBinding?: PlanBinding;
}

export interface CreatedApiKey {
  /**
   * The key's id — what `revokeApiKey` and `rotateApiKey` take, and what a
   * SAML service provider registration's audit rows written with this key
   * name as `api_key_id`. Not secret.
   */
  id: string;
  /** The raw key — returned exactly once, never retrievable again. */
  apiKey: string;
  name: string;
  /**
   * Closed, and narrower than the listing's — which is the opposite of how
   * these two were typed.
   *
   * A key being minted right now cannot carry a scope the server does not know:
   * `create_api_key` checks every element against `KNOWN_SCOPES` and answers
   * 400 "unknown scope" before minting, then echoes back the same list. So the
   * response is exactly the set this union names.
   */
  scopes: ManagementScope[];
}

/**
 * The app a client is, for a mobile app: its Android package and signing
 * certificates, its Apple app ID, or both (at least one). Each redirect's
 * domain must vouch for it: `assetlinks.json` granting
 * `delegate_permission/common.handle_all_urls` to the package with one of the
 * fingerprints, and `apple-app-site-association` listing the app ID in
 * `webcredentials.apps`. The server reads both files when the identity is set
 * and whenever the redirects of a client that has one change, and refuses
 * with a 400 naming each host and what its file lacked.
 */
export interface AppIdentity {
  android?: {
    /** The application ID, for example `com.example.app`. */
    packageName: string;
    /** SHA-256 certificate fingerprints, `AB:CD:…` as `keytool` prints them. */
    sha256CertFingerprints: string[];
  };
  ios?: {
    /** Team ID, a dot, and the bundle ID: `ABCDE12345.com.example.app`. */
    appId: string;
  };
}

export interface App {
  clientId: string;
  clientName: string;
  /**
   * These four were optional here, and required in the document, with no
   * comment on either side saying why.
   *
   * The server settles it: `list_apps` builds its response with a `json!`
   * literal over a `ClientListing` whose `client_type`, `grant_types`,
   * `redirect_uris` and `first_party` are `ClientType`, `Vec<String>`,
   * `Vec<String>` and `bool` — none of them `Option`, and no
   * `skip_serializing_if` anywhere on the path. An empty list serialises as
   * `[]`, never as a missing key. So the document was right and this was
   * defensive, and the cost of that defence was every caller writing a guard
   * for a case the server cannot produce.
   */
  clientType: ClientType;
  /**
   * As a client sends them: the device grant reads
   * `urn:ietf:params:oauth:grant-type:device_code`, as `/register` and
   * discovery name it. Either spelling is accepted on the way in, so this list
   * can be passed back to `updateApp` unchanged.
   */
  grantTypes: string[];
  redirectUris: string[];
  /** Where the app may send users after logout. `[]` from a server that did not list them. */
  postLogoutRedirectUris: string[];
  firstParty: boolean;
  /**
   * RFC 3339. There is no activity signal on a client, so this is the only
   * thing a caller can age one by.
   */
  createdAt: string;
  /**
   * Whether the client may be used. **Inactive clients are still listed**, so a
   * caller that does not read this field shows disabled applications as live
   * ones — which is why it is required rather than optional.
   */
  isActive: boolean;
  /** True when the client registered itself rather than being provisioned. */
  selfRegistered: boolean;
  /** The app the client was registered as, or `null`. */
  appIdentity: AppIdentity | null;
  /**
   * Where the app receives logout tokens when a session it was issued an ID
   * token for ends (OIDC Back-Channel Logout 1.0), or `null` — also from a
   * server older than the field, whose listing does not say.
   */
  backchannelLogoutUri: string | null;
  /** Whether the app requires a `sid` in its logout tokens; every token carries one. */
  backchannelLogoutSessionRequired: boolean;
  /**
   * Where the app starts a sign-in a third party asks for (OpenID Connect
   * Dynamic Client Registration 1.0 §2) — an accepted invitation naming the
   * app sends its invitee there — or `null`, also from a server older than
   * the field.
   */
  initiateLoginUri: string | null;
}

export interface CreatedApp {
  clientId: string;
  clientName: string;
  /** Present only for confidential clients; returned exactly once. */
  clientSecret?: string;
  /** Present when the request carried one: as stored, fingerprints upper-cased. */
  appIdentity?: AppIdentity;
  /** Present when the request carried one: as stored. */
  backchannelLogoutUri?: string;
  /** Present beside `backchannelLogoutUri`. */
  backchannelLogoutSessionRequired?: boolean;
  /** Present when the request carried one: as stored. */
  initiateLoginUri?: string;
}

export interface Connection {
  /**
   * Open on purpose, unlike the request side below. This is a *response* field:
   * a client pinned to this SDK talking to a newer server can legitimately
   * receive a provider this version has never heard of, and a closed union
   * would make that a type error at the call site rather than a value to
   * handle. The generated half still cannot drift.
   */
  provider: WireProvider | (string & {});
  clientId: string;
  redirectUri: string;
  enabled: boolean;
  /**
   * Whether it works on the tenant's plan now: the enabled ones, oldest first,
   * up to the plan's number of social logins. A server before that limit
   * existed does not say, and limited nothing: read as `enabled`.
   */
  inUse: boolean;
}

export interface AuditEvent {
  eventType: string;
  severity: WireSeverity | (string & {});
  clientId: string | null;
  /**
   * The **subject** — the resource owner this event concerns, not whoever
   * caused it. An administrator deactivating an account leaves this set to the
   * deactivated user; see `causedByUserId` for the other end.
   */
  actorUserId: string | null;
  /**
   * The console member who **performed** the action, when one did.
   *
   * `null` for the whole authentication path, where nobody acted on anybody's
   * behalf, and also when the actor was not a user of this tenant — a platform
   * operator appears as `asserted_operator` inside `detailJson`, and a
   * management API key is named in `detail`.
   */
  causedByUserId: string | null;
  ip: string | null;
  detail: string | null;
  /**
   * The same event as JSON, as a **string** holding the stored bytes verbatim.
   * Not parsed and not re-serialised: the seal is computed over these exact
   * bytes, so anything that re-encodes them breaks verification. Parse a copy.
   */
  detailJson: string | null;
  /** Which hashing rule covers this row, for a consumer that verifies the seal. */
  leafVersion: number;
  createdAt: string;
}

/** One month of the usage series. */
export interface UsagePoint {
  /** The calendar month as an ISO date — the first of it, UTC: `2026-08-01`.
   *  A date rather than `YYYY-MM` because the column is a `DATE` and the first
   *  of the month is the period's identity; slice or format it for display. */
  period: string;
  activeUsers: number;
}

/**
 * A tenant's metered usage.
 *
 * `definition` travels with the number on purpose. A bare `activeUsers` invites
 * the reader to supply their own definition — rolling thirty days, sign-ins
 * only, per application — and each is a different figure. An invoice dispute is
 * a bad place to discover which was meant.
 */
export interface Usage {
  /** Always `monthly_active_users` today. Read it before trusting the number:
   *  a future metric would change what `activeUsers` counts. */
  metric: string;
  definition: string;
  /** The current period, as an ISO date (`2026-08-01`). Equal to the last point
   *  of `series`, read from the same query so the two cannot disagree. */
  period: string;
  /**
   * When `activeUsers` starts again from zero, as an RFC 3339 timestamp:
   * 00:00 UTC on the first of the month after `period`
   * (`2026-11-01T00:00:00Z`). Not the subscription's renewal date — the count
   * follows the calendar month in UTC. Absent from a server that predates it.
   */
  resetsAt?: string;
  activeUsers: number;
  /** Oldest first, with quiet months present as zeroes rather than omitted, so
   *  a chart needs no sorting and no gap-filling. */
  series: UsagePoint[];
  /** The tenant this report is for — the resolved one, which is not always the
   *  one the caller named. */
  tenantId: string;
  /** The tenant's own monthly-active-user soft cap, or `null` when it set none. */
  softCap?: number | null;
  /**
   * The cap that announces: `softCap` when set, else the plan's
   * `includedActiveUsers`; `null` when neither applies. Absent from a server
   * that predates it.
   */
  effectiveSoftCap?: number | null;
  /**
   * Whether `activeUsers` has passed `effectiveSoftCap` — the cap the audit
   * trail announces at. Computed server-side rather than left to the caller so
   * that every consumer answers it the same way.
   */
  overSoftCap?: boolean;
  /** The plan in force. Absent from a server that predates plans. */
  plan?: Plan;
  /**
   * How many monthly recurring users the plan includes: FREE's promised number (passing it
   * denies nobody anything), and where TEAM and BUSINESS start billing per user.
   * `null` where the tenant is not held to its plan (plans not enforced, or the
   * platform's own tenant).
   */
  includedActiveUsers?: number | null;
  /** Whether `activeUsers` has passed `includedActiveUsers`. */
  overIncluded?: boolean;
}

// --- inputs ----------------------------------------------------------------

export interface CreateTenantInput {
  slug: string;
  displayName?: string;
  /**
   * A contact address recorded on the tenant, and in its `tenant.created`
   * audit row.
   *
   * It creates no account, grants nothing and mails nobody: a tenant made with
   * it still has no owner, and nobody can open its console. `inviteTenantOwner`
   * is what gives it one.
   */
  ownerEmail?: string;
}

/**
 * A patch for `updateTenant`. Every field is optional and an omitted one is
 * left alone — the server reads absence as "do not touch", so sending a partial
 * patch is the normal case rather than a shortcut.
 */
export interface UpdateTenantInput {
  branding?: Branding;
  /**
   * Turning this to `"required"` changes the security posture of every account
   * in the tenant at once, and the server audits it at warning for that reason.
   * Set `mfaGraceDays` in the same call if you want a window: the server writes
   * the window first precisely so the requirement never exists without one.
   */
  mfaPolicy?: MfaPolicy;
  mfaGraceDays?: number;
  /**
   * The tenant's ceiling on self-registered (RFC 7591) clients.
   *
   * Three-state, and the difference is the whole point of a nullable override:
   * **omit** to leave it as it is, **`null`** to clear it and fall back to the
   * deployment default `REGISTRATION_MAX_CLIENTS_PER_TENANT`, or a **number** to
   * set it. Clearing and leaving alone are different requests, and a plain
   * optional number could not tell them apart — which is why `null` is in the
   * type rather than being the absent case.
   *
   * Platform-token only. A tenant key that could raise its own ceiling would
   * make the control advisory.
   */
  maxSelfRegisteredClients?: number | null;
  /**
   * The most members this tenant may hold.
   *
   * Three-state like `maxSelfRegisteredClients`: **omit** to leave it alone,
   * **`null`** to remove the limit, a **number** to set one. The floor is 1,
   * not 0 — the server refuses 0 with "a tenant with no members cannot
   * be administered".
   *
   * Platform-token only; a tenant key sending it gets 403, and the gate fires
   * on the key being *present*, so `{ maxMembers: null }` is refused too.
   */
  maxMembers?: number | null;
  /**
   * Puts the tenant on a plan by hand — a comp, an agreement, a test tenant —
   * or `null` to clear it and let the subscription decide.
   *
   * Platform-token only, like `maxMembers`: a plan a customer could set for
   * itself would be a price of zero. The billing provider never writes it, so an
   * override survives every subscription change.
   */
  planOverride?: Plan | null;
  /**
   * How long a user has to complete self-service MFA recovery, in hours.
   *
   * Three-state: **omit** to leave it alone, **`null`** to turn self-service
   * recovery off, a **number** in 1..=720 to set the delay. `0` is a 400 rather
   * than a synonym for off — the server's own message explains that the delay
   * is what makes an attempt visible to somebody who still holds a factor, so
   * there is no zero.
   */
  mfaSelfRecoveryHours?: number | null;
  /**
   * Whether a mailed code counts as a second factor for this tenant.
   *
   * Two-state, unlike the two fields above: the server reads this through a
   * plain `Option<bool>`, so `null` is indistinguishable from omission and is
   * accepted with 200 and no change. Send `true` or `false`, or omit it.
   *
   * Turning it off mid-incident is a real operation — the server audits the
   * change at warning severity as `tenant.mfa_email_factor_changed` — and it
   * was unreachable from this client until now.
   */
  mfaEmailFactorEnabled?: boolean;
  /**
   * Saved account-recovery codes: whether an account with a password and no
   * confirmed address may hold a code it can spend to choose a new password. It
   * never gets past a second factor. Off by default; turning it off withdraws no
   * code, it stops every one being accepted. Audited as
   * `tenant.account_recovery_codes_changed`. Send `true` or `false`, or omit it.
   */
  accountRecoveryCodesEnabled?: boolean;
  /**
   * The hosted sign-up page: whether a person may make their own account here
   * with an address and a password. Off by default; turning it off removes no
   * account. Audited as `tenant.password_signup_changed`. Send `true` or
   * `false`, or omit it.
   */
  passwordSignupEnabled?: boolean;
  /**
   * Whether a first sign-in through a social connection makes an account. Off,
   * one that matches no account is refused, and a person who already has an
   * account still signs in. Off by default for a new tenant. Audited as
   * `tenant.social_signup_changed`. Send `true` or `false`, or omit it.
   */
  socialSignupEnabled?: boolean;
  /**
   * Whether this tenant requires attested passkeys.
   *
   * Two-state; `null` is ignored rather than clearing. Setting `"required"`
   * before the tenant has at least one attestation CA is a **409**, not a 400:
   * every registration would fail the chain check. Register a CA through
   * `POST /api/v1/tenants/{tenant_id}/passkey-attestation/cas` first.
   */
  passkeyAttestation?: PasskeyAttestation;
}

/**
 * The scopes a management key may hold. Mirrors `KNOWN_SCOPES` on the server,
 * which rejects anything outside this set with a 400 — so a typo is a compile
 * error here rather than a round trip.
 */
export type ManagementScope =
  | "tenant:read"
  | "tenant:write"
  | "apps:read"
  | "apps:write"
  | "connections:read"
  | "connections:write"
  | "users:read"
  | "users:write"
  | "users:reset_mfa"
  | "users:revoke_sessions"
  | "audit:read"
  | "webhooks:read"
  | "webhooks:write"
  | "domains:write"
  | "mail:read"
  | "mail:write"
  | "usage:read"
  | "resources:read"
  | "resources:write"
  | "saml:read"
  | "saml:write"
  | "saml-sp:read"
  | "saml-sp:write";

export interface CreateApiKeyInput {
  name?: string;
  /**
   * What the key may do. **Required, with at least one scope.**
   *
   * A key that names no scope passes every scope check the server makes —
   * it is the most privileged key there is — and since 2026-10-01 the
   * server mints none: `scopes: []` is a 400,
   * which `createApiKey` throws as a `ManagementError`. Keys minted that way
   * before keep working, and `listApiKeys` shows them with no scopes.
   *
   * This type used to make it optional, and the documented example omitted it,
   * so the advertised way to mint a key minted an unrestricted one. Required
   * here, an omission is a compile error rather than a request.
   */
  scopes: ManagementScope[];
}

export interface CreateAppInput {
  /** Required when authenticating with the platform token; ignored (and must
   *  match) when using a tenant API key. */
  tenantId?: string;
  clientName?: string;
  /**
   * How the client proves who it is at the token endpoint.
   *
   * Aliased to the generated union rather than spelled out, because spelling it
   * out is what went wrong: this field was hand-written as three values while
   * the server accepted four, so `private_key_jwt` — the only method here that
   * does not hand the client a shared secret — could not be named through this
   * SDK at all. Every client an integrator created was therefore secret-based.
   * `null` and omission both mean `client_secret_basic`.
   */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  redirectUris?: string[];
  /**
   * Where the client may be sent after RP-initiated logout.
   *
   * Held to the same rule as `redirectUris` — the server runs both lists
   * through one registrability check (`docs/mobile-SDKs.md` §2.1), so a
   * fragment or any private-use scheme is a 400 here exactly as it is there.
   */
  postLogoutRedirectUris?: string[];
  /**
   * Omitted or empty, the server gives a web app's two grants,
   * `["authorization_code", "refresh_token"]`, so the app is issued refresh
   * tokens. A server from before October 2026 gives `authorization_code`
   * alone; name both to be sure. Name the grants to create a client without
   * `refresh_token`.
   */
  grantTypes?: string[];
  scopes?: string[];
  firstParty?: boolean;
  /**
   * For a mobile app, which is a public client: see {@link AppIdentity}.
   * Verified before the client is created; a refusal creates nothing.
   */
  appIdentity?: AppIdentity;
  /**
   * OIDC Back-Channel Logout 1.0 §2.2: where the app receives a signed logout
   * token when a session it was issued an ID token for ends. An absolute
   * `https` URI with no fragment and a public host; `http` only for a
   * confidential client on a server that allows it.
   */
  backchannelLogoutUri?: string;
  /** §2.2: requires a `sid` in each logout token. Needs `backchannelLogoutUri`. */
  backchannelLogoutSessionRequired?: boolean;
  /**
   * Where the app starts a sign-in a third party asks for (OpenID Connect
   * Dynamic Client Registration 1.0 §2). When an invitation naming this app
   * (`inviteUser` with `clientId`) is accepted, the invitee is signed in and
   * sent here with `iss`. With a Proteles SDK it is the app's
   * `/api/auth/login`. An absolute `https` URI on the same origin as one of
   * `redirectUris`, with no fragment, user name or `iss` of its own; `http`
   * only on a loopback host, as a redirect URI may.
   */
  initiateLoginUri?: string;
  /**
   * The RSA public key this client's authentication assertions are signed with.
   *
   * **Required when `tokenEndpointAuthMethod` is `"private_key_jwt"`, and
   * refused with every other method** — both are 400s from the server, so
   * the pairing is not advisory. RSA only: the
   * server parses it with `DecodingKey::from_rsa_pem`, so an EC or Ed25519 key
   * is rejected as unreadable.
   *
   * A `private_key_jwt` client is confidential and is issued **no**
   * `clientSecret` — `CreatedApp.clientSecret` is absent on that path, which is
   * the point of using it.
   */
  jwtAuthPublicKeyPem?: string;
  /**
   * Bind the new client to an existing service account in the same tenant.
   *
   * The server binds this **after** the client row is committed, and a bad id answers 400 without the generated
   * `client_id` or the one-time `client_secret` in the body — so the client
   * exists and its secret is gone. Pass an id you have already confirmed, or
   * omit it and bind afterwards through
   * `PUT /api/v1/apps/{client_id}/service-account`.
   */
  serviceAccountId?: string;
}

export interface UpsertConnectionInput {
  tenantId?: string;
  /**
   * Closed, unlike the response side. This is what the caller *sends*, and an
   * open union means a typo compiles and fails at the server instead of in the
   * editor.
   */
  provider: WireProvider;
  clientId: string;
  clientSecret: string;
  /**
   * The server's callback, not your app's: `https://<tenant host>/login/<provider>/callback`
   * on one of the tenant's own hosts, written exactly as the provider will be
   * sent it. Anything else is refused with a 400.
   */
  redirectUri: string;
  enabled?: boolean;
}

export interface TenantScope {
  /** Required with the platform token; derived from the key otherwise. */
  tenantId?: string;
}

export interface ListAuditOptions extends TenantScope {
  limit?: number;
  /**
   * Event types to include. Empty or absent means every type — never "match
   * nothing", which is the server's rule and is repeated here because a client
   * that turned an empty array into `event_type=` would ask a different
   * question than the one the caller wrote.
   *
   * An array is joined with commas, which is the wire encoding. Accepting the
   * array is the point: a caller should not have to know that, and a type that
   * happens to contain a comma is then unrepresentable rather than silently
   * two types.
   */
  eventType?: string | string[];
  /** `info`, `warning`, `critical`, each matched exactly: `warning` is warnings
   *  only, so ask for both to see the critical rows too. Same rule as `eventType`. */
  severity?: string | string[];
  /** Only events **about** this user — the subject. */
  actorUserId?: string;
  /** Only events this console member **performed**. Not the same question. */
  causedByUserId?: string;
  clientId?: string;
  /** RFC 3339. Inclusive lower bound; the server refuses one it cannot parse
   *  rather than ignoring it, so a typo is an error and not a silent full scan. */
  since?: string;
  /** RFC 3339. Exclusive upper bound, so `[midnight, next midnight)` cannot
   *  double-count the boundary row. */
  until?: string;
  /** Opaque, from a previous page's `nextCursor`. */
  cursor?: string;
}

/**
 * One page of the audit trail.
 *
 * `listAudit` returns the events alone and always will — it is the shape every
 * existing caller was written against. This is the additive half: the trail is
 * keyset-paged and a client that cannot see the cursor cannot read past the
 * first page, which for a tenant with any history at all is most of their own
 * trail.
 */
export interface AuditPage {
  events: AuditEvent[];
  /**
   * Pass as `cursor` to get the next page. `null` at the end — null rather than
   * absent, so a caller can tell "the end" from "this server does not
   * paginate". Opaque and sealed; its contents are not part of the contract.
   */
  nextCursor: string | null;
}

export interface GetUsageOptions extends TenantScope {
  /** How many months of history, oldest first. The server clamps this — asking
   *  for more than it will give is not an error, it is answered with the cap. */
  months?: number;
}

/** A key's metadata. The raw value is returned only once, at creation. */
export interface ApiKeySummary {
  id: string;
  name: string;
  /**
   * Open, and wider than the mint response's — deliberately.
   *
   * A key minted before a scope was retired keeps that value in its row, and
   * this endpoint reads rows. Typing it as the closed union would have the
   * compiler assert that a value the database can hold cannot appear, so a
   * `switch` over it would look exhaustive and silently fall through on exactly
   * the old key an operator is trying to find and revoke.
   *
   * `(string & {})` rather than plain `string[]`: the union still drives
   * autocomplete for the current scopes while accepting anything.
   */
  scopes: (ManagementScope | (string & {}))[];
  createdAt: string;
  revoked: boolean;
}

/** The DNS record that proves a domain claim. */
export interface DomainChallenge {
  /** Always `"TXT"`. The document declares it a constant, not an open set. */
  type: string;
  name: string;
  /**
   * The token to publish — 32 random bytes, base64url, 43 characters.
   *
   * **Nullable, and it was typed `string` here until a generated wire type
   * disagreed.** The column is nullable and the server models it
   * `Option<String>`, so a row claimed before verification existed serialises
   * `null`; verifying such a row is a 409, not a 400. A caller that took this
   * as a string would print "null" into DNS setup instructions.
   *
   * Nothing caught it: `sdk-interface-drift.mjs` compares field *names* on the
   * ten mapped interfaces, and `DomainChallenge` is nested inside one rather
   * than being one.
   */
  value: string | null;
}

/**
 * A custom hostname claimed by a tenant. It resolves nothing until `verified`.
 */
export interface TenantDomain {
  domain: string;
  verified: boolean;
  verifiedAt: string | null;
  createdAt: string;
  /**
   * Never absent. `domain_json` builds the challenge object unconditionally and
   * is the single serialiser behind the claim, the listing and the verify
   * endpoint, so there is no path that omits it — `value` inside it is the part
   * that can be `null`.
   */
  challenge: DomainChallenge;
}

// ---------------------------------------------------------------------------
// Users and principals
//
// Everything below reaches an endpoint the client could not call at all. The
// shape of what was missing is worth stating once: this SDK could create almost
// everything and change or act on almost nothing. An operator holding it could
// read an incident in full — the audit trail, a user's second factors, a
// tenant's MFA posture — and respond to none of it. Resetting a lost phone,
// ending a compromised session, switching a tenant off, rotating a leaked
// secret: all of it was a raw HTTP request.
// ---------------------------------------------------------------------------

/** What a user currently holds as a second factor. */
export interface UserMfaStatus {
  /** Whether an authenticator app is enrolled. */
  totp: boolean;
  /** How many passkeys are registered. */
  passkeys: number;
  /**
   * Recovery codes still unused.
   *
   * Zero with a factor enrolled is the state worth noticing: the user can sign
   * in today and has nothing left if they lose the device.
   */
  recoveryCodesRemaining: number;
  /** Whether email sign-in codes are armed (codes mailed to the account's address). */
  email: boolean;
  /** Whether a verified phone is enrolled for text-message sign-in codes. */
  sms: boolean;
}

/** One user, looked up by exact username. */
export interface UserLookup {
  id: string;
  username: string;
  email: string | null;
  isActive: boolean;
  mfa: UserMfaStatus;
}

export interface CreateUserInput {
  /** Required with the platform token; ignored (and must match) for a tenant key. */
  tenantId?: string;
  username: string;
  password: string;
  email?: string | null;
  /**
   * Whether to record the address as already verified.
   *
   * Only meaningful when the caller has verified it by some other means. The
   * default is unverified, which is the safe reading of "we do not know".
   */
  emailVerified?: boolean | null;
}

export interface CreatedUser {
  id: string;
  username: string;
  email?: string | null;
  emailVerified?: boolean;
}

export interface CreateServiceAccountInput {
  tenantId?: string | null;
  name: string;
}

/** A non-human principal a client can act as. */
export interface CreatedServiceAccount {
  id: string;
  name: string;
  /** Always `"service"`; the field exists so a caller can tell the kinds apart. */
  kind: "service";
}

/** One row of a user search. */
export interface UserSummary {
  id: string;
  username: string;
  email?: string | null;
  emailVerified?: boolean;
  isActive: boolean;
  createdAt: string;
}

/** A page of users, with the totals needed to walk the rest. */
export interface UserPage {
  users: UserSummary[];
  total: number;
  page: number;
  perPage: number;
}

export interface SearchUsersOptions extends TenantScope {
  /** Free-text match on username and email. Omit to list everyone. */
  q?: string;
  /** 1-based. */
  page?: number;
}

export interface BulkUsersInput extends TenantScope {
  userIds: string[];
  /**
   * `"deactivate"` or `"reactivate"`, spelled out rather than a boolean.
   *
   * The server's own comment says why: a body reading `{"active": false}` is
   * one typo from meaning its opposite, and this is the endpoint where a typo
   * lands on every account in the list at once.
   */
  action: "deactivate" | "reactivate";
  /** Required and non-empty. It is the only field that records why. */
  reason: string;
}

export interface BulkUsersResult {
  changed: number;
  /** Counted, not an error: asking twice is how a retry looks. */
  alreadyInThatState: number;
  /** Ids that named no user in this tenant. */
  notFound: string[];
  sessionsRevokedAt?: string | null;
}

export interface InviteUserInput extends TenantScope {
  email: string;
  /**
   * The app to return the invitee to once they accept: a client of
   * the tenant whose registration has an `initiateLoginUri`. A new account is
   * signed in — through the workspace's second-factor rule — and sent there;
   * omitted, accepting ends on the sign-in page, as before.
   */
  clientId?: string;
}

/** Who to invite to own a tenant. The tenant is the call's first argument. */
export interface InviteTenantOwnerInput {
  email: string;
}

/** What `inviteTenantOwner` sent. The link itself is never returned. */
export interface OwnerInvitation {
  email: string;
  /** What accepting grants: always `"owner"`. */
  role: "owner";
  /** 72 hours after it was sent. */
  expiresAt: string;
  /**
   * Whether the deployment's relay accepted the mail. `false` is an outcome,
   * not an error: the invitation exists and nobody received it, so send it
   * again once the relay works — the new link replaces this one.
   */
  delivered: boolean;
  /**
   * The addresses of the platform's other live owner invitations in this
   * tenant, withdrawn by this one: their links no longer work. Usually empty;
   * one entry when the previous invitation went to another address.
   */
  replaced: string[];
}

/** Whose owner invitation to withdraw. The tenant is the call's first argument. */
export interface WithdrawTenantOwnerInvitationInput {
  email: string;
}

/** What `withdrawTenantOwnerInvitation` did. */
export interface OwnerInvitationWithdrawal {
  email: string;
  /**
   * `true` when a live invitation from the platform was withdrawn; `false`
   * when there was none — accepted, expired, never sent, or sent by somebody
   * else.
   */
  withdrawn: boolean;
}

export interface Invitation {
  email: string;
  expiresAt: string;
  /**
   * Whether the mail actually went out.
   *
   * `false` is a real outcome rather than an error — the invitation exists and
   * the address did not receive it, which is a thing an operator must be told
   * rather than a thing to retry blindly.
   */
  delivered: boolean;
  /** Present when the request named one: the app the invitee is returned to. */
  clientId?: string;
}

/** What clearing a user's second factors actually removed. */
export interface ResetMfaResult {
  userId: string;
  username: string;
  totpRemoved: boolean;
  passkeysRemoved: number;
  /** Whether email sign-in codes were removed. */
  emailRemoved: boolean;
  /** Whether a phone enrolled for text-message codes was removed. */
  smsRemoved: boolean;
  note: string;
}

/** What ending a user's sessions actually did. */
export interface RevokeSessionsResult {
  userId: string;
  username: string;
  sessionsRevokedAt: string;
  reason: string;
  /** Which credential did it — the audit trail records this beside the reason. */
  performedBy: "platform-token" | "tenant-api-key";
  note: string;
}

export interface UserActivationInput extends TenantScope {
  /** Required and non-empty. It is the only field that records why. */
  reason: string;
}

/** The outcome of switching an account off or back on. */
export interface UserActivationChanged {
  userId: string;
  username: string;
  isActive: boolean;
  /**
   * `false` when the account was already in this state.
   *
   * Audited either way, so this is not "nothing happened" — it is "nothing
   * changed", which is what a retry looks like and what a second operator
   * arriving at the same incident looks like.
   */
  changed: boolean;
  /**
   * When sessions were ended, or `null`.
   *
   * Null on reactivation always — turning an account back on does not restore
   * sessions, and it should not. Null on *deactivation* means something else:
   * the account was switched off and the revocation did not complete, so the
   * user may still hold a live session. That case needs a follow-up
   * `revokeUserSessions`.
   */
  sessionsRevokedAt: string | null;
  performedBy: string;
}

// ---------------------------------------------------------------------------
// Applications, and the credentials behind them
// ---------------------------------------------------------------------------

export interface UpdateAppInput extends TenantScope {
  clientName?: string;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
  grantTypes?: string[];
  scopes?: string[];
  /**
   * Whether the client may be used.
   *
   * The reversible half of `deleteApp`: an inactive client keeps its id, its
   * secret and its history, and stops working. For a client you suspect rather
   * than one you are finished with, this is the call.
   */
  isActive?: boolean;
  firstParty?: boolean;
  /**
   * Set the app identity (verified against the redirect URIs the client ends
   * up with), or `null` to clear it. Omitted leaves it as it is; the redirects
   * of a client that has one are verified again whenever they change.
   */
  appIdentity?: AppIdentity | null;
  /**
   * Set where the app receives logout tokens, or `null` to stop it being told
   * (which clears `backchannelLogoutSessionRequired` too). Omitted leaves it.
   */
  backchannelLogoutUri?: string | null;
  /** Omitted leaves it. `true` needs a `backchannelLogoutUri`, set or kept. */
  backchannelLogoutSessionRequired?: boolean;
  /**
   * Set where the app starts a sign-in a third party asks for, or `null` to
   * clear it. Omitted leaves it — but a stored one is checked again when
   * `redirectUris` change, and one left on an origin none of them has is
   * refused: move or clear it in the same call.
   */
  initiateLoginUri?: string | null;
}

/**
 * A client after an update.
 *
 * Not the `App` a listing returns: it carries `scopes`, which the listing
 * leaves out, and not the listing's `createdAt` or `selfRegistered`. They are
 * genuinely different payloads, so they are different types rather than one
 * with optional halves.
 */
export interface UpdatedApp {
  clientId: string;
  clientName: string;
  clientType: ClientType;
  /**
   * As a client sends them: the device grant reads
   * `urn:ietf:params:oauth:grant-type:device_code`, as `/register` and
   * discovery name it. Either spelling is accepted on the way in, so this list
   * can be passed back to `updateApp` unchanged.
   */
  grantTypes: string[];
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  firstParty: boolean;
  isActive: boolean;
  appIdentity: AppIdentity | null;
  backchannelLogoutUri: string | null;
  backchannelLogoutSessionRequired: boolean;
  initiateLoginUri: string | null;
}

export interface RotateAppSecretInput extends TenantScope {
  /**
   * How long the old secret keeps working, in hours.
   *
   * The whole point of the endpoint. A rotation with no overlap is an outage
   * for every consumer that has not been redeployed yet; the overlap is what
   * lets you rotate first and roll out second. `retireAppSecret` ends it early
   * once every consumer is on the new one.
   */
  overlapHours?: number;
}

export interface RotatedAppSecret {
  clientId: string;
  /** Returned exactly once. */
  clientSecret: string;
  previousSecretExpiresAt: string;
}

export interface BoundServiceAccount {
  clientId: string;
  /** `null` after clearing the binding, which is what an omitted id means. */
  serviceAccountId: string | null;
}

// ---------------------------------------------------------------------------
// Tenant lifecycle
// ---------------------------------------------------------------------------

export interface DeleteTenantInput {
  /**
   * The tenant's own slug, typed back.
   *
   * The server compares it and refuses a mismatch. This is not ceremony: the
   * call it guards removes every user, client and key belonging to the tenant,
   * and an id in the wrong variable is otherwise indistinguishable from an id
   * in the right one.
   */
  confirmSlug: string;
}

/** What deleting a tenant actually removed. */
export interface TenantDeleted {
  id: string;
  slug: string;
  deleted: boolean;
  users: number;
  clients: number;
  apiKeys: number;
  /**
   * Why the audit rows are still there — one hash chain covers every tenant, so
   * removing a tenant's leaves would break it for everybody.
   */
  auditRows: string;
  /**
   * **True.** The retained rows can still name the deleted tenant's people, and
   * an erasure request has to be answered with that in mind rather than with
   * "the tenant is gone".
   */
  auditRowsMayContainIdentifiers: boolean;
}

export interface SetTenantStatusInput {
  status: "active" | "suspended";
  reason?: string;
}

export interface TenantStatusChanged {
  id: string;
  status: "active" | "suspended";
  previousStatus: string;
}

export interface DataKeyRotated {
  tenantId: string;
  version: number;
  previousVersion: number;
  notice?: string;
}

export interface SigningKeyRotated {
  kid: string;
  alg: "RS256";
}

export interface RotatedApiKey {
  id: string;
  name?: string;
  /** Returned exactly once. */
  apiKey: string;
  /** The id of the key this one replaces. */
  replaces: string;
  previousKeyExpiresAt: string;
}

export interface SessionLifetime {
  tenantId: string;
  /** The tenant's own override, or `null` when it follows the deployment. */
  sessionTtlSeconds: number | null;
  /** What actually applies — the override if there is one, else the default. */
  effectiveSessionTtlSeconds: number;
  defaultSessionTtlSeconds: number;
  minSessionTtlSeconds: number;
  maxSessionTtlSeconds: number;
  /** The plan the choices below come from. */
  plan: Plan;
  /**
   * What this plan may choose: a list on FREE (one, three or seven days, in
   * seconds), `null` on TEAM and BUSINESS — and on every plan where the tenant
   * is not held to it (plans not enforced, or the platform's own tenant) —
   * where anything from min to max goes.
   */
  allowedSessionTtlSeconds: number[] | null;
}

/**
 * What a tenant gets, as the server applies it: its plan's own table where the
 * tenant is held to its plan (`TenantPlan.enforced`), and the unrestricted set
 * where it is not — the three numbers `null`, any session lifetime, SMS
 * allowed.
 */
export interface PlanEntitlements {
  /** `null` where `enforced` is false: nothing is counted against a plan. */
  includedActiveUsers: number | null;
  activeUserOverageBilled: boolean;
  /** `null` where `enforced` is false: only `maxMembers` caps seats. */
  includedSeats: number | null;
  /** When false `includedSeats` is a cap; when true seats past it are sold. */
  extraSeatsBilled: boolean;
  /** `null` where `enforced` is false: no window, nothing deleted by plan. */
  logRetentionDays: number | null;
  allowedSessionTtlSeconds: number[] | null;
  /**
   * Allowed where `enforced` is false — except at a tenant that self-service
   * sign-up made, which follows its plan either way: FREE has none until the
   * operator's plan override includes it.
   */
  sms: boolean;
  enhancedSupport: boolean;
  /**
   * How many social-login connections work, oldest first; `null`: no limit.
   * A server before migration 0174 limits none of these three.
   */
  maxSocialConnections: number | null;
  /** Whether SAML works, in both directions. */
  saml: boolean;
  /** Whether service accounts, client_credentials and private_key_jwt work. */
  machineIdentity: boolean;
}

export interface TenantPlan {
  tenantId: string;
  plan: Plan;
  /**
   * Who decided it: `override` (the operator), `subscription` (a paid plan
   * from the billing provider), or `none` (nothing did — FREE).
   */
  source: WireBillingSource;
  /**
   * Whether this tenant is held to its plan: the deployment enforces plans
   * (`PLANS_ENFORCED`) and the tenant is not the platform's own (the default
   * tenant, which no plan limits). `false`: `entitlements` is the unrestricted
   * set, whatever `plan` says.
   */
  enforced: boolean;
  /**
   * Why: `"not_enforced"` or `"platform_tenant"` where `enforced` is false,
   * `"plan"` where it is true (see {@link PlanBinding}). Absent from a server
   * before 2026-10-03.
   */
  planBinding?: PlanBinding;
  entitlements: PlanEntitlements;
}

/**
 * Which plan a tenant is on, and why (`GET /api/v1/billing`). Read-only: plans
 * are bought and changed in the tenant console by an owner, and written by the
 * billing provider's webhook.
 */
export interface Billing {
  tenantId: string;
  /** The plan in force. */
  plan: Plan;
  /**
   * Why: `override` (the platform operator set one, and it wins),
   * `subscription` (a subscription in force pays for it), or `none` (nothing
   * does, so FREE).
   */
  source: WireBillingSource;
  overridePlan: WireOverridePlan;
  /** Whether this deployment sells plans at all. */
  billingEnabled: boolean;
  /** The tenant's subscription, in force or ended; `null` if it never had one. */
  subscription: BillingSubscription | null;
}

export interface BillingSubscription {
  /** What it is for. Whether it is in force is `inForce`. */
  plan: PaidPlan;
  /** The billing provider's status, verbatim (`active`, `past_due`, `canceled`, …). */
  status: string;
  /** `active`, `trialing` and `past_due` keep the paid plan; anything else is FREE. */
  inForce: boolean;
  interval: WireInterval;
  /** The renewal date, or the end date when `cancelAtPeriodEnd`. */
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
  /** Seats billed beyond the plan's included ones. */
  extraSeats: number;
}

export interface SessionLifetimeSet {
  tenantId: string;
  sessionTtlSeconds: number | null;
  effectiveSessionTtlSeconds: number;
}

/** The SMS second factor at one tenant: the switch, the plan, and the month's texts. */
export interface SmsFactor {
  tenantId: string;
  /** The tenant's switch, as set. A downgrade leaves it alone. */
  smsFactorEnabled: boolean;
  plan: Plan;
  /**
   * Whether this tenant may switch SMS on. TEAM and BUSINESS include it and
   * FREE does not, where plans bind; where they do not, every tenant the
   * operator made may, and one self-service sign-up made only once the
   * operator's plan override includes it.
   */
  planIncludesSms: boolean;
  /** The switch and the plan together: whether a person here may set it up. */
  offered: boolean;
  /** Whether the deployment can send a text at all. */
  deliverable: boolean;
  /** Texts the tenant may send in a UTC day. */
  dailyLimit: number;
  sentToday: number;
  sentThisMonth: number;
  /** Of this month's, the ones the provider accepted. */
  acceptedThisMonth: number;
}

export interface AttestationCa {
  id: string;
  label: string;
  aaguid: string;
  /** The certificate's fingerprint, so two CAs can be told apart without it. */
  certSha256: string;
}

/**
 * A tenant's attestation posture and the CAs behind it.
 *
 * Returned together because the two are only meaningful together: `"required"`
 * with an empty `cas` is a tenant whose users can enrol no passkey at all, and
 * the server refuses to *set* that state for the same reason.
 */
export interface AttestationCaList {
  passkeyAttestation: PasskeyAttestation;
  cas: AttestationCa[];
}

export interface SoftCapSet {
  tenantId: string;
  softCap: number | null;
}

export interface AddAttestationCaInput {
  /** Refused when blank — it is the only thing naming what you later remove. */
  label: string;
  /** Attestation is verified per authenticator model, so this is required. */
  aaguid: string;
  /** PEM. Shape-checked on the way in rather than at a user's registration. */
  certPem: string;
}

// ---------------------------------------------------------------------------
// Webhooks
//
// The whole subsystem, absent from this client until now: twelve operations
// covering the endpoints themselves, what happened to each notification, and
// the events a tenant was never told about. Proteles' own console has reached
// all of them for as long as they have existed.
// ---------------------------------------------------------------------------

/**
 * The events a tenant can be notified about. Closed: the server enforces it.
 *
 * Re-exported from `generated/wire.ts` rather than `generated/enums.ts`: the
 * enum generator reads `properties[*].enum`, and this one is a top-level schema
 * with no properties, so only the wire generator sees it.
 */
export type WebhookEventName = wire.WebhookEventName;

/** Why an endpoint stopped being delivered to. */
export type WebhookDisabledReason = "too_many_dead_letters" | "operator" | null;

/**
 * The platform's per-tenant switch for SAML sign-in as a service provider
 * (phase 1). Acting as an identity provider is {@link TenantSamlIdpEnabled}.
 *
 * Separate from a connection's own `enabled`: this is the operator saying "this
 * customer may use SAML", and that is the customer saying "this provider is
 * live". Both must be on. Only the platform token can set this — no API key
 * scope grants it.
 */
export interface TenantSamlEnabled {
  enabled: boolean;
}

/**
 * The platform's per-tenant switch for SAML phase 2: whether this tenant may act
 * as an identity provider — sign assertions for its registered service providers
 * and publish IdP metadata.
 *
 * Separate from {@link TenantSamlEnabled}, which is phase 1 (consuming
 * assertions); allowing one never allows the other. Only the platform token can
 * set this.
 */
export interface TenantSamlIdpEnabled {
  enabled: boolean;
  /**
   * Where this tenant's SAML SSO endpoint lives — its own origin, pinned the
   * first time the platform enabled phase 2, with the tenant's UUID beneath it.
   * `null` until then.
   *
   * It is not derived from the issuer: session cookies are host-only, so the
   * endpoint has to be on the host where the person's session actually is. The
   * pin never moves once it is set, because a service provider stores this URL.
   */
  ssoUrl: string | null;
}

/**
 * A tenant's inbound SAML connection: which identity provider they federate to,
 * and on what terms.
 *
 * The certificates are here because an X.509 certificate is a public key with a
 * name on it — the provider publishes it, and an administrator who cannot read
 * back the one they configured cannot answer "is this the one we rotated to".
 * The scope guarding it is strict all the same: the row is a map of how to
 * impersonate the tenant convincingly, which is worth a scope no unscoped key
 * inherits.
 */
export interface SamlConnection {
  id: string;
  name: string;
  idpEntityId: string;
  idpSsoUrl: string;
  certificatePem: string;
  certificateNextPem: string | null;
  spEntityId: string;
  acsUrl: string;
  /**
   * Which assertion attribute names the person.
   *
   * When set it is used *instead of* `NameID`, with no fallback — an operator
   * sets this because their provider's `NameID` is unstable, and falling back
   * would let the provider choose which identifier this server keys on.
   */
  attrUsername: string | null;
  attrEmail: string | null;
  maxAssertionLifetimeSeconds: number;
  allowUnsolicited: boolean;
  relayStateHosts: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

/**
 * The whole configuration, for create and for replace alike.
 *
 * There is no partial update: every field is needed for a connection to be
 * usable, and a half-applied trust configuration — a new certificate under the
 * old entity id — is a state nobody should be able to leave one in.
 *
 * The policy fields are optional and default to the refusing answer: disabled,
 * no unsolicited responses, no RelayState hosts, a ten-minute lifetime.
 */
export interface SamlConnectionInput extends TenantScope {
  name: string;
  idpEntityId: string;
  idpSsoUrl: string;
  certificatePem: string;
  certificateNextPem?: string;
  spEntityId: string;
  /**
   * Where the provider posts: an address this deployment answers on — its
   * issuer's host, a host beneath a configured base host, or a verified custom
   * domain (on a loopback issuer, on the issuer's own port). Anything else is
   * refused. For sign-in to work it must also reach this tenant: its own
   * `<slug>.<base host>`, one of its verified custom domains, or the issuer's
   * host for the default tenant.
   */
  acsUrl: string;
  attrUsername?: string;
  attrEmail?: string;
  maxAssertionLifetimeSeconds?: number;
  allowUnsolicited?: boolean;
  relayStateHosts?: string[];
  enabled?: boolean;
}

/**
 * An application this tenant may sign users into, with Proteles as the identity
 * provider.
 *
 * The inverse of {@link SamlConnection}. That says whose word about your staff
 * you accept; this says which application you will hand a signed statement about
 * them to — and `acsUrls` is the allowlist that decides where it goes.
 */
export interface SamlServiceProvider {
  id: string;
  name: string;
  /** Compared byte for byte at sign-in. Nothing normalises it. */
  spEntityId: string;
  /**
   * Where an assertion may be delivered. Absolute https, matched exactly.
   *
   * An `AssertionConsumerServiceURL` that is not byte-equal to one of these is
   * refused — never delivered to the closest match or to the first entry. The
   * order means nothing: a request carrying an `AssertionConsumerServiceIndex`
   * is refused, and the default is {@link defaultAcsUrl}.
   */
  acsUrls: string[];
  /**
   * Where a request that names no destination is answered. Always one of
   * `acsUrls`, byte for byte.
   */
  defaultAcsUrl: string;
  /**
   * Verifies a signed `AuthnRequest` from this application, and when set every
   * request must be signed.
   *
   * `null` means it does not sign its requests — and a signed request from it
   * cannot be checked, so it is refused: an application that signs must have
   * its certificate here. It is never a fallback: a signed request that fails
   * verification is refused, not retried as an unsigned one.
   */
  requestSigningCertificatePem: string | null;
  nameIdFormat: string;
  /**
   * Whether this application may be sent an identifier for somebody it has
   * never seen — what `NameIDPolicy AllowCreate` asks, answered for the
   * requests that do not ask it, which is most of them. An explicit
   * `AllowCreate="false"` is still honoured.
   *
   * Not about *which* users may reach the application; only about minting the
   * identifier the assertion carries.
   */
  enrolOnFirstSignIn: boolean;
  /**
   * Where this application receives front-channel single-logout messages.
   *
   * `null` means it does not take part in single logout. Validated exactly as
   * {@link acsUrls} are — absolute https, and never an address on the
   * Proteles deployment itself.
   */
  sloUrl: string | null;
  /**
   * Whether this application can take part in single logout, derived from
   * {@link sloUrl} and {@link requestSigningCertificatePem}:
   *
   * - `takes_part` — its own logout requests are honoured, and it is told when
   *   another SAML application signs the person out;
   * - `no_logout_endpoint` — its own requests are honoured, but it is never
   *   told when another application signs the person out, so that logout is
   *   answered `PartialLogout`;
   * - `no_certificate` — its logout requests are refused and its answers
   *   cannot be verified, so a logout started elsewhere passes it over;
   * - `no_logout_endpoint_or_certificate` — neither.
   *
   * Signing out at Proteles itself tells no SAML application.
   */
  singleLogout: SingleLogout;
  /**
   * Whether every user of the tenant may be asserted to this application.
   *
   * `false` — the default — means only the people listed at
   * {@link ManagementClient.listSamlServiceProviderAssignments} may. The
   * permissive answer is never inferred: it is a flag an administrator sets,
   * so that "who is the finance app for" is written down rather than left as
   * the absence of a check.
   */
  openToEveryTenantUser: boolean;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

/** One person's access to one SAML application. */
export interface SamlServiceProviderAssignment {
  userId: string;
  /**
   * When access was granted. Assigning somebody who is already assigned does
   * not move it — the trail answers "since when".
   */
  createdAt: string;
}

/** Who may reach one registration: the flag and the named set together. */
export interface SamlServiceProviderAssignments {
  /**
   * When true, every user of the tenant may be asserted to this registration
   * and {@link assignments} is not consulted.
   *
   * It travels with the list because an empty array means "nobody" only when
   * this is false.
   */
  openToEveryTenantUser: boolean;
  assignments: SamlServiceProviderAssignment[];
}

/**
 * The whole registration, for create and for replace alike.
 *
 * There is no partial update, and the reason is sharper here than for a
 * connection: a partial update of an allowlist is a way to add a destination
 * without stating the whole set you meant to allow.
 */
export interface SamlServiceProviderInput extends TenantScope {
  name: string;
  spEntityId: string;
  /**
   * At least one, at most ten. Each must be an absolute https URL with no
   * userinfo, fragment, query, `.`/`..` segment, percent-encoded separator,
   * backslash or whitespace, and must survive its own parser unchanged.
   * Wildcards and patterns are refused rather than stored literally, and so is
   * a duplicate.
   */
  acsUrls: string[];
  /**
   * Where a request that names no destination is answered: one of `acsUrls`,
   * exactly as written there.
   *
   * Required when `acsUrls` names more than one destination, because the
   * list's order does not decide it — otherwise a new URL added at the top
   * would move sign-ins onto it. With one destination it may be omitted and
   * means that one. A replacement states it again.
   */
  defaultAcsUrl?: string;
  /**
   * Set it for an application that signs its `AuthnRequest`s: with it, unsigned
   * requests are refused; without it, signed ones are, because they cannot be
   * checked.
   */
  requestSigningCertificatePem?: string;
  /** Defaults to the persistent (opaque, per-SP) format. */
  nameIdFormat?: string;
  /**
   * Whether this application may be sent an identifier for somebody it has
   * never seen. **Defaults to true**, unlike every other policy field here: a
   * registration that refused its own first sign-in would be met as a broken
   * deployment rather than as a policy, and an explicit `AllowCreate="false"`
   * in a request is honoured whatever this says.
   */
  enrolOnFirstSignIn?: boolean;
  /**
   * Where this application receives front-channel single-logout messages.
   * Omit it — or send an empty string — for an application that does not take
   * part in single logout.
   */
  sloUrl?: string;
  /**
   * Whether every user of the tenant may be asserted to this application.
   *
   * **Defaults to false**, on a create and on a replace alike: the assignment
   * policy starts empty. Assign people one at a time with
   * {@link ManagementClient.assignSamlServiceProviderUser}.
   */
  openToEveryTenantUser?: boolean;
  /** Defaults to false. */
  enabled?: boolean;
}

/**
 * Where a SAML signing key is in its life.
 *
 * Four states rather than a boolean, because a planned rotation and a
 * compromise want opposite things and an `active` flag cannot tell them apart.
 *
 * - `published` — in this tenant's metadata, signing nothing. The state that
 *   makes a rotation safe: a service provider that refreshes metadata weekly has
 *   to have seen the certificate before the first assertion uses it, and there
 *   is no in-band way to ask whether it has.
 * - `signing` — what signs today. Exactly one per tenant.
 * - `retired` — no longer signing, still published for the overlap, so an
 *   assertion minted a second before the rotation still verifies.
 * - `revoked` — compromised. Out of metadata immediately and never back.
 */
export type SamlIdpKeyState = "published" | "signing" | "retired" | "revoked";

/**
 * One of this tenant's SAML identity-provider signing keys.
 *
 * **The private half is not in this type, and not in any response.** The
 * certificate is: it is a public key with a name on it, and it is served
 * unauthenticated at the metadata endpoint anyway.
 */
export interface SamlIdpKey {
  /**
   * Per tenant, never global. Two tenants may hold the same `kid` and they are
   * different keys — two customers running the same off-the-shelf software
   * would otherwise collide.
   */
  kid: string;
  state: SamlIdpKeyState;
  certificatePem: string;
  /**
   * SHA-256 of the certificate DER, lowercase hex.
   *
   * What an administrator reads out to a service provider's owner, and what that
   * owner compares against what they pinned. MetaIOP strips PKI semantics from a
   * SAML certificate, so there is no CA to appeal to — this fingerprint is the
   * whole out-of-band check.
   */
  certificateSha256: string;
  /**
   * Jittered per tenant at mint, so a bulk onboarding does not give a thousand
   * customers the same morning to fail on.
   */
  notAfter: string;
  /**
   * When the signer stops using this key: a day before `notAfter`. After this
   * the tenant cannot sign with it.
   */
  signingRefusedFrom: string;
  /**
   * When the expiry warning starts — the same schedule as the operator's alert
   * and the `saml_idp_key.expiring` audit row. A rotation started by then can
   * finish before `signingRefusedFrom`.
   */
  rotationWarningFrom: string;
  /**
   * Whether this certificate belongs in the tenant's metadata document now. A
   * retired key stops belonging once the rotation overlap has passed. The
   * document itself is served only while the tenant is enabled as an identity
   * provider and active.
   */
  published: boolean;
  createdAt: string;
  /** Null until promoted. */
  signingSince: string | null;
  /** Null until a successor is promoted. The overlap is measured from here. */
  retiredAt: string | null;
}

/**
 * What a revocation did.
 *
 * `replacement` is null when the revoked key was not the one signing — revoking
 * a merely-published key is a tenant deciding not to go ahead with a rotation,
 * and minting them a key they did not ask for would be the endpoint inventing
 * work.
 */
export interface SamlIdpKeyRevocation {
  revokedKid: string;
  replacement: SamlIdpKey | null;
}

export interface WebhookEndpoint {
  id: string;
  name: string;
  url: string;
  events: WebhookEventName[];
  enabled: boolean;
  maxDeliveriesPerMinute: number;
  /**
   * How many dead letters disable the endpoint.
   *
   * The circuit breaker. An endpoint that has been failing long enough stops
   * being delivered to, which is why `disabledReason` exists and why it is
   * worth reading before assuming an endpoint is merely quiet.
   */
  disableAfterDeadLetters: number;
  disabledReason: WebhookDisabledReason;
  disabledAt: string | null;
  disabledBy: string | null;
}

export interface CreateWebhookInput extends TenantScope {
  name?: string;
  url: string;
  /** The shared secret deliveries are signed with. Sent once, never returned. */
  secret: string;
  events: WebhookEventName[];
  enabled?: boolean;
  maxDeliveriesPerMinute?: number;
  disableAfterDeadLetters?: number;
}

/**
 * A full replacement, not a patch — `PUT`, and the server means it.
 *
 * `url` and `events` are required because leaving them out sets them to
 * nothing, not to what they were. `secret` is the exception: omit it to keep
 * the current one.
 */
export interface ReplaceWebhookInput extends TenantScope {
  name?: string;
  url: string;
  secret?: string;
  events: WebhookEventName[];
  enabled?: boolean;
  maxDeliveriesPerMinute?: number;
  disableAfterDeadLetters?: number;
}

/** What a create or replace wrote. Carries no secret and no disabled state. */
export interface WrittenWebhook {
  id: string;
  name: string;
  url: string;
  events: WebhookEventName[];
  enabled: boolean;
  maxDeliveriesPerMinute: number;
  disableAfterDeadLetters: number;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string | null;
  webhookName: string | null;
  eventId: string;
  eventType: WebhookEventName;
  status: "pending" | "delivered";
  attempts: number;
  nextAttemptAt: string | null;
  lastError: string | null;
  /** The HTTP status the endpoint answered with, or `null` if it never did. */
  lastStatus: number | null;
  createdAt: string;
  completedAt: string | null;
}

export interface ListDeliveriesOptions extends TenantScope {
  webhookId?: string;
  limit?: number;
}

export interface ReplayDeliveriesInput extends TenantScope {
  webhookId?: string;
  status?: "exhausted" | "delivered";
  since?: string;
  /** Specific delivery ids. Omit to replay everything the filters match. */
  ids?: string[];
}

export interface ReplayResult {
  requeued: number;
  /**
   * Whether the batch hit its cap.
   *
   * `true` means call again — this is not "some failed", it is "there is more".
   */
  moreMayRemain: boolean;
}

/**
 * An event the tenant was never told about.
 *
 * It carries the `body` that could not be delivered, so the payload is
 * recoverable from here rather than lost — which is why acknowledging is
 * separate from discarding.
 */
export interface WebhookDeadLetter {
  id: string;
  webhookId: string | null;
  endpointName: string;
  endpointUrl: string;
  eventId: string;
  eventType: WebhookEventName;
  body: string;
  attempts: number;
  lastError: string | null;
  lastStatus: number | null;
  firstQueuedAt: string;
  diedAt: string;
  revivedAt: string | null;
  revivals: number;
  acknowledgedAt: string | null;
  acknowledgedBy: string | null;
}

export interface DeadLetterPage {
  /** How many are still unacknowledged — the number worth alerting on. */
  outstanding: number;
  outstandingByEndpoint: Record<string, number>;
  retentionDays: number;
  deadLetters: WebhookDeadLetter[];
}

export interface ListDeadLettersOptions extends TenantScope {
  webhookId?: string;
  includeAcknowledged?: boolean;
  limit?: number;
}

export interface AcknowledgeDeadLettersInput extends TenantScope {
  /** Specific ids, or omit and pass `webhookId` to take a whole endpoint's. */
  ids?: string[];
  webhookId?: string;
}

export interface DiscardDeadLettersInput extends TenantScope {
  /** Required. There is no "discard everything" — deletion is not a filter. */
  ids: string[];
}

export interface DiscardResult {
  discarded: number;
  /**
   * How many were asked for.
   *
   * Compare with `discarded`: a gap means some ids named nothing, which is
   * worth noticing before concluding the queue is clear.
   */
  requested: number;
}

// ---------------------------------------------------------------------------
// Resource servers, scopes, mail, and the rest
// ---------------------------------------------------------------------------

/** One scope name and what it means. */
export interface ScopeDefinition {
  id: string;
  /**
   * The resource server it belongs to, or `null` for a tenant-wide scope.
   *
   * The two live in one table and are told apart by this field alone, which is
   * why `listResources` returns them separately rather than making a caller
   * partition the list.
   */
  resourceServerId?: string | null;
  name: string;
  description: string;
  createdAt?: string;
}

/** An audience a token can be minted for. */
export interface ResourceServer {
  id: string;
  /** What goes in a token's `aud`. */
  identifier: string;
  displayName: string;
  createdAt?: string;
  updatedAt?: string;
  scopes?: ScopeDefinition[];
}

export interface ResourceServerList {
  resources: ResourceServer[];
  /** Scopes that belong to no audience — tenant-wide rather than per-resource. */
  tenantScopes: ScopeDefinition[];
}

export interface CreateResourceInput extends TenantScope {
  identifier: string;
  displayName: string;
}

export interface DefineScopeInput extends TenantScope {
  /** Omit for a tenant-wide scope. */
  resourceServerId?: string | null;
  name: string;
  /** Shown to a user on the consent screen, so it is required rather than optional. */
  description: string;
}

/**
 * Where a tenant's mail goes out from.
 *
 * Every field but `configured` is optional, and that is the shape rather than
 * an accident: a tenant on the platform relay answers with `configured: false`
 * and nothing else to report.
 */
export interface MailSettings {
  configured: boolean;
  using?: string;
  host?: string;
  port?: number;
  username?: string | null;
  /** Whether a password is stored. The password itself is never returned. */
  passwordSet?: boolean;
  fromAddress?: string;
  /**
   * The name people see as the sender: `Proteles` in
   * `From: Proteles <noreply@proteles.com>`. One saved before the server
   * refused addresses here, and refused now, is still returned, and left off
   * the mail.
   */
  fromName?: string | null;
  encryption?: "starttls" | "implicit" | "none";
  enabled?: boolean;
  lastSuccessAt?: string | null;
  lastError?: string | null;
  lastErrorAt?: string | null;
  updatedAt?: string;
}

export interface SetMailSettingsInput extends TenantScope {
  host: string;
  port: number;
  username?: string | null;
  /** Omit to keep the stored password. */
  password?: string;
  fromAddress: string;
  /**
   * The name people see as the sender, such as `Proteles`: not an address.
   * A name containing `@`, `<` or `>`, a control character, a line break or a
   * text-direction mark, one starting with a dot, or one over 100 characters
   * is refused (400 `invalid_request`). Trimmed before it is checked and
   * stored. A comma, a double quote or a non-ASCII name is sent as typed.
   */
  fromName?: string | null;
  encryption: "starttls" | "implicit" | "none";
  enabled?: boolean;
}

export interface MailTestResult {
  /**
   * Whether the message actually went out.
   *
   * `false` arrives with a 200 and an `error`, because a relay that refuses the
   * message is an answer about the configuration rather than a failure of the
   * call. Check this field, not the status code.
   */
  sent: boolean;
  to: string;
  via?: string;
  error?: string;
}

/** Operational numbers for the deployment, not for one tenant. */
export interface FleetHealth {
  webhookQueueDepth: number;
  deadLettersOutstanding: number;
  /** How far the audit export has fallen behind, in seals. */
  auditExportLagSeals: number;
  auditUnsealedRows: number;
}

/**
 * What a plan version includes, costs and says on the pricing page — the
 * catalog editor's fields (decision E1). Money is in cents, overage in
 * millionths of a dollar per user.
 */
export interface PlanVersionFields {
  includedMru: number;
  includedSeats: number;
  /** `null`: no limit on applications. */
  maxApps: number | null;
  logRetentionDays: number;
  /** Lifetimes to pick from, in days, including 1; `null` for any length up to `sessionMaxDays`. */
  sessionChoiceDays: number[] | null;
  sessionMaxDays: number;
  sms: boolean;
  enhancedSupport: boolean;
  monthlyCents: number;
  annualCents: number;
  mruOverageMicros: number;
  extraSeatMonthlyCents: number;
  extraSeatAnnualCents: number;
  tagline: string;
  features: string[];
  /** How many social-login connections work, oldest first; `null`: no limit, `0`: none. */
  maxSocialConnections: number | null;
  /** Whether SAML works, in both directions. */
  saml: boolean;
  /** Whether service accounts, the client_credentials grant and private_key_jwt work. */
  machineIdentity: boolean;
}

/** What moving every Free workspace onto a version did. */
export interface PlanMoveResult {
  /** The version moved onto. */
  id: number;
  version: number;
  /** How many workspaces moved. */
  moved: number;
}

/** One of a version's prices at the billing provider. */
export interface PlanVersionPrice {
  priceRef: string;
  kind: "base" | "seat" | "overage";
  interval: WireInterval;
  /** Whether new checkouts use it; the others are only recognised. */
  sold: boolean;
}

/** A plan version, and where it stands in the catalog. */
export interface PlanVersion extends PlanVersionFields {
  id: number;
  plan: Plan;
  name: string;
  version: number;
  status: "draft" | "published";
  /** The tier's highest published version: what new sign-ups and plan changes get. */
  current: boolean;
  /** Tenants holding it, for their subscription or an override. */
  tenants: number;
  publishedAt: string | null;
  publishedBy: string | null;
  prices: PlanVersionPrice[];
}

export interface PlanVersionList {
  versions: PlanVersion[];
  /** Whether publishing a paid version makes prices at a billing provider. */
  billingEnabled: boolean;
}

export interface SetSoftCapInput extends TenantScope {
  /** `null` removes the cap. Zero is refused — it reads as "no access". */
  softCap: number | null;
}

/**
 * Everything a departing tenant may take with them.
 *
 * `tables` is keyed by table name. `truncated` names tables where the export
 * hit its per-table row cap, and `excluded` names every table deliberately left
 * out with the reason — so the omissions are part of the answer rather than
 * silence.
 */
export interface TenantExport {
  tenant: Record<string, unknown>;
  tables: Record<string, Record<string, unknown>[]>;
  truncated: string[];
  excluded: { table?: string; disposition?: "ephemeral" | "never"; reason?: string }[];
}

/** How much a `checkApp` finding matters: `ok` as it should be, `info` worth
 *  knowing, `warning` works and probably not as meant, `problem` will fail for
 *  somebody. */
export type AppCheckLevel = wire.AppCheckFinding["level"];

/** One thing `checkApp` found. */
export interface AppCheckFinding {
  /** Which check, for a script to match on: `active`, `refresh_token`,
   *  `openid`, `redirect_uris`, `post_logout_redirect_uris` or
   *  `backchannel_logout`. A check may report more than one finding. */
  check: string;
  level: AppCheckLevel;
  /** The finding, in a sentence for a person. */
  message: string;
}

/** What an app's registration will do (`checkApp`). */
export interface AppCheck {
  clientId: string;
  clientName: string;
  /** `false` when any finding is a `problem`. */
  ready: boolean;
  findings: AppCheckFinding[];
}
