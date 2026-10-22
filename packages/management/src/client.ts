//! The Management API client — a thin, typed wrapper over `/api/v1/*`. It maps
//! camelCase inputs/outputs to the API's snake_case wire format, attaches the
//! bearer credential, and normalizes errors to `ManagementError`.

import { ManagementError } from "./errors.js";
import type * as wire from "./generated/wire.js";
import type {
  AcknowledgeDeadLettersInput,
  AddAttestationCaInput,
  ApiKeySummary,
  App,
  AppCheck,
  AppCheckFinding,
  AppIdentity,
  AttestationCaList,
  AuditEvent,
  AuditPage,
  Billing,
  BoundServiceAccount,
  Branding,
  BulkUsersInput,
  BulkUsersResult,
  Connection,
  CreateApiKeyInput,
  CreateAppInput,
  CreatedApiKey,
  CreatedApp,
  CreatedServiceAccount,
  CreatedUser,
  CreateResourceInput,
  CreateServiceAccountInput,
  CreateTenantInput,
  CreateUserInput,
  CreateWebhookInput,
  DataKeyRotated,
  DeadLetterPage,
  DefineScopeInput,
  DeleteTenantInput,
  DiscardDeadLettersInput,
  DiscardResult,
  FetchLike,
  FleetHealth,
  Plan,
  PlanVersion,
  PlanVersionFields,
  PlanMoveResult,
  PlanVersionList,
  GetUsageOptions,
  Invitation,
  InviteTenantOwnerInput,
  InviteUserInput,
  OwnerInvitation,
  OwnerInvitationWithdrawal,
  WithdrawTenantOwnerInvitationInput,
  ListAuditOptions,
  ListDeadLettersOptions,
  ListDeliveriesOptions,
  MailSettings,
  MailTestResult,
  ManagementClientConfig,
  ManagementScope,
  MfaPolicy,
  PasskeyAttestation,
  ReplaceWebhookInput,
  ReplayDeliveriesInput,
  ReplayResult,
  ResetMfaResult,
  ResourceServer,
  ResourceServerList,
  RevokeSessionsResult,
  RotateAppSecretInput,
  RotatedApiKey,
  RotatedAppSecret,
  ScopeDefinition,
  SearchUsersOptions,
  SessionLifetime,
  SessionLifetimeSet,
  SmsFactor,
  SetMailSettingsInput,
  SetSoftCapInput,
  SetTenantStatusInput,
  SigningKeyRotated,
  SoftCapSet,
  Tenant,
  TenantPlan,
  TenantDeleted,
  TenantDomain,
  TenantExport,
  SamlConnection,
  SamlIdpKey,
  SamlIdpKeyRevocation,
  SamlServiceProvider,
  SamlServiceProviderAssignment,
  SamlServiceProviderAssignments,
  SamlServiceProviderInput,
  SamlConnectionInput,
  TenantSamlEnabled,
  TenantSamlIdpEnabled,
  TenantScope,
  TenantStatusChanged,
  TenantSummary,
  UpdateAppInput,
  UpdatedApp,
  UpdateTenantInput,
  UpsertConnectionInput,
  Usage,
  UserActivationChanged,
  UserActivationInput,
  UserLookup,
  UserPage,
  WebhookDeadLetter,
  WebhookDelivery,
  WebhookEndpoint,
  WrittenWebhook,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;

export class ManagementClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly fetchFn: FetchLike;
  private readonly timeoutMs: number;

  constructor(config: ManagementClientConfig) {
    if (!config.baseUrl) throw new ManagementError("baseUrl is required");
    if (!config.token) throw new ManagementError("token is required");
    const fetchFn = config.fetch ?? (globalThis.fetch as FetchLike | undefined);
    if (!fetchFn) throw new ManagementError("no fetch implementation available; pass config.fetch");
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.token = config.token;
    this.fetchFn = fetchFn;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  // --- tenants -----------------------------------------------------------

  /**
   * Provision a new tenant. Requires the platform token.
   *
   * Returns a `TenantSummary`, not a `Tenant`: `POST /api/v1/tenants` answers
   * with `{id, slug, status}` and nothing else. This used to return the wider
   * type with every setting `undefined`, so `(await createTenant(...)).mfaPolicy`
   * was always undefined and read as "no policy". Follow with `getTenant` when
   * you need the settings.
   */
  async createTenant(input: CreateTenantInput): Promise<TenantSummary> {
    const body = await this.request<wire.TenantSummary>("POST", "/api/v1/tenants", {
      body: {
        slug: input.slug,
        display_name: input.displayName,
        // Omitted rather than sent as `undefined`: the server reads an absent
        // key as "not set", and `JSON.stringify` drops undefined values anyway —
        // being explicit here so the intent survives a future refactor that
        // builds the body differently.
        ...(input.ownerEmail === undefined ? {} : { owner_email: input.ownerEmail }),
      },
    });
    return toTenantSummary(body);
  }

  /**
   * Mail a tenant's owner an invitation. Requires the platform token.
   *
   * For a tenant nobody can administer: one `createTenant` made, which has no
   * account in it, or one whose owners have left. The invitee chooses their own
   * password from a single-use link, valid for 72 hours, and becomes the
   * tenant's owner when they open it (or, when the address already has an
   * account in the tenant, enters that account's password). The link is never
   * returned.
   *
   * The mail goes through the deployment's own relay, never a relay the tenant
   * configured; a deployment without one is refused (`409
   * mail_not_configured`) and no invitation is created. Sending again to the
   * same address replaces the earlier link, and the platform keeps one live
   * owner invitation per tenant: sending to another address withdraws the
   * earlier one, which `replaced` names. `withdrawTenantOwnerInvitation` takes
   * one back without sending another.
   */
  async inviteTenantOwner(tenantId: string, input: InviteTenantOwnerInput): Promise<OwnerInvitation> {
    const w = await this.request<wire.OwnerInvitationSent>(
      "POST",
      `/api/v1/tenants/${segment(tenantId)}/owner-invitations`,
      { body: { email: input.email } },
    );
    return { email: w.email, role: w.role, expiresAt: w.expires_at, delivered: w.delivered, replaced: w.replaced };
  }

  /**
   * Withdraw the owner invitation the platform sent an address, so its link
   * stops working: for one that went to the wrong address. Requires the
   * platform token.
   *
   * Only what the platform sent: an owner's or a key's invitation to the same
   * address is left alone. `withdrawn: false` is an answer, not an error —
   * there was no live invitation from the platform to that address.
   */
  async withdrawTenantOwnerInvitation(
    tenantId: string,
    input: WithdrawTenantOwnerInvitationInput,
  ): Promise<OwnerInvitationWithdrawal> {
    const w = await this.request<wire.OwnerInvitationWithdrawn>(
      "DELETE",
      `/api/v1/tenants/${segment(tenantId)}/owner-invitations`,
      { body: { email: input.email } },
    );
    return { email: w.email, withdrawn: w.withdrawn };
  }

  /**
   * Every tenant. Requires the platform token (a tenant key is refused).
   *
   * `TenantSummary[]`, because the listing returns three fields per tenant.
   * Reading a policy off one of these is now a compile error rather than a
   * confident `undefined`.
   */
  async listTenants(): Promise<TenantSummary[]> {
    const body = await this.request<{ tenants: wire.TenantSummary[] }>("GET", "/api/v1/tenants");
    return (body.tenants ?? []).map(toTenantSummary);
  }

  /** Fetch a tenant and its branding. */
  async getTenant(tenantId: string): Promise<Tenant> {
    const body = await this.request<wire.TenantDetail>("GET", `/api/v1/tenants/${segment(tenantId)}`);
    return toTenant(body);
  }

  /**
   * Update a tenant: branding, MFA policy, or the self-registration ceiling.
   *
   * Omitted fields are left alone. The one exception is
   * `maxSelfRegisteredClients`, which is three-state — see `UpdateTenantInput`.
   */
  async updateTenant(tenantId: string, patch: UpdateTenantInput): Promise<Tenant> {
    const body: Record<string, unknown> = {};
    if (patch.branding !== undefined) body.branding = toWireBranding(patch.branding);
    if (patch.mfaPolicy !== undefined) body.mfa_policy = patch.mfaPolicy;
    if (patch.mfaGraceDays !== undefined) body.mfa_grace_days = patch.mfaGraceDays;
    // `!== null` is not the test here: `null` is a request — clear the override
    // — and the `!== undefined` spelling used above would send it, but writing
    // it that way invites someone to "tidy" it into a truthiness check later,
    // which would silently drop both `null` and a deliberate ceiling of 0.
    if (patch.maxSelfRegisteredClients !== undefined) {
      body.max_self_registered_clients = patch.maxSelfRegisteredClients;
    }
    // Same three-state reasoning as above: `null` clears, absent leaves alone.
    if (patch.maxMembers !== undefined) body.max_members = patch.maxMembers;
    // Same three-state shape: `null` clears the override, absent leaves it.
    if (patch.planOverride !== undefined) body.plan_override = patch.planOverride;
    if (patch.mfaSelfRecoveryHours !== undefined) {
      body.mfa_self_recovery_hours = patch.mfaSelfRecoveryHours;
    }
    // These two are two-state on the server — a plain `Option`, so `null` is
    // read as absence and changes nothing. Guarding on `!== undefined` keeps
    // that faithful: a caller who writes `null` gets the server's own no-op
    // rather than a client-side surprise.
    if (patch.mfaEmailFactorEnabled !== undefined) {
      body.mfa_email_factor_enabled = patch.mfaEmailFactorEnabled;
    }
    if (patch.accountRecoveryCodesEnabled !== undefined) {
      body.account_recovery_codes_enabled = patch.accountRecoveryCodesEnabled;
    }
    if (patch.passwordSignupEnabled !== undefined) {
      body.password_signup_enabled = patch.passwordSignupEnabled;
    }
    if (patch.socialSignupEnabled !== undefined) {
      body.social_signup_enabled = patch.socialSignupEnabled;
    }
    if (patch.passkeyAttestation !== undefined) {
      body.passkey_attestation = patch.passkeyAttestation;
    }
    const detail = await this.request<wire.TenantDetail>("PATCH", `/api/v1/tenants/${segment(tenantId)}`, {
      body,
    });
    return toTenant(detail);
  }

  /**
   * Update a tenant's branding.
   *
   * Kept as the narrow spelling of `updateTenant({ branding })`, which is what
   * it now calls.
   */
  async updateTenantBranding(tenantId: string, branding: Branding): Promise<Tenant> {
    return this.updateTenant(tenantId, { branding });
  }

  /** Mint a tenant API key. Requires the platform token. The raw key is
   *  returned exactly once. */
  /**
   * Mints a management key for a tenant. The raw value is returned once.
   *
   * `input.scopes` is required: the server reads an absent or empty list as
   * *unrestricted*, and this method's own default used to be `{}` — so the
   * documented call minted a key with full authority over the tenant.
   */
  /**
   * Every key this tenant holds, metadata only — the raw value exists once, at
   * creation, and is never retrievable.
   *
   * A key's `id`, which `revokeApiKey` needs, is also returned by
   * `createApiKey`; this is how to find the id of a key minted elsewhere.
   */
  async listApiKeys(tenantId: string): Promise<ApiKeySummary[]> {
    const body = await this.request<{ keys: wire.TenantApiKeySummary[] }>(
      "GET",
      `/api/v1/tenants/${segment(tenantId)}/keys`,
    );
    return (body.keys ?? []).map((k) => ({
      id: k.id,
      name: k.name,
      // The cast that used to be here — `as ManagementScope[]` — was the
      // inversion in one line: it asserted a listed key holds only scopes the
      // server still knows, which is the one thing a listing cannot promise.
      scopes: k.scopes ?? [],
      createdAt: k.created_at,
      revoked: k.revoked,
    }));
  }

  /**
   * Revokes one key. Idempotent: revoking twice keeps the original timestamp,
   * so a retry cannot rewrite who stopped it or when.
   */
  async revokeApiKey(tenantId: string, keyId: string): Promise<void> {
    await this.request<{ revoked: boolean; id: string }>(
      "DELETE",
      `/api/v1/tenants/${segment(tenantId)}/keys/${segment(keyId)}`,
    );
  }

  /** Every custom hostname this tenant has claimed, verified or not. */
  async listDomains(tenantId: string): Promise<TenantDomain[]> {
    const body = await this.request<{ domains: WireDomain[] }>(
      "GET",
      `/api/v1/tenants/${segment(tenantId)}/domains`,
    );
    return (body.domains ?? []).map(toDomain);
  }

  /**
   * Claims a hostname. It routes nothing until `verifyDomain` proves it — the
   * returned `challenge` is the TXT record to publish first.
   */
  async claimDomain(tenantId: string, domain: string): Promise<TenantDomain> {
    return toDomain(
      await this.request<WireDomain>("POST", `/api/v1/tenants/${segment(tenantId)}/domains`, {
        body: { domain },
      }),
    );
  }

  /**
   * Checks the TXT record and, if it matches, marks the claim verified.
   *
   * A 503 means DNS could not be reached — which is not a failed proof, and is
   * worth retrying. A 400 means the record was absent or wrong.
   */
  async verifyDomain(tenantId: string, domain: string): Promise<wire.TenantDomainVerified> {
    return this.request<wire.TenantDomainVerified>(
      "POST",
      `/api/v1/tenants/${segment(tenantId)}/domains/${segment(domain)}/verify`,
    );
  }

  /** Releases a claim. A verified hostname stops resolving immediately. */
  async releaseDomain(tenantId: string, domain: string): Promise<void> {
    await this.request<void>(
      "DELETE",
      `/api/v1/tenants/${segment(tenantId)}/domains/${segment(domain)}`,
    );
  }

  async createApiKey(tenantId: string, input: CreateApiKeyInput): Promise<CreatedApiKey> {
    const body = await this.request<wire.TenantApiKeyCreated>(
      "POST",
      `/api/v1/tenants/${segment(tenantId)}/keys`,
      { body: { name: input.name, scopes: input.scopes } },
    );
    return { id: body.id, apiKey: body.api_key, name: body.name, scopes: body.scopes ?? [] };
  }

  // --- apps --------------------------------------------------------------

  /**
   * Create a client (app) in the tenant. `clientSecret` is returned once for
   * confidential clients — and **not at all** for `private_key_jwt`, which is
   * confidential and authenticates with a signed assertion instead.
   *
   * Every field of `CreateAppRequest` is sent. It used to send seven of ten,
   * and the three it omitted were not decoration: without
   * `jwtAuthPublicKeyPem` a `private_key_jwt` client cannot be created at all
   * (the server 400s on the missing key), so every client made through this
   * method authenticated with a shared secret.
   */
  async createApp(input: CreateAppInput): Promise<CreatedApp> {
    const body = await this.request<wire.AppsCreatedApp>(
      "POST",
      "/api/v1/apps",
      {
        body: {
          tenant_id: input.tenantId,
          client_name: input.clientName,
          token_endpoint_auth_method: input.tokenEndpointAuthMethod,
          redirect_uris: input.redirectUris,
          post_logout_redirect_uris: input.postLogoutRedirectUris,
          grant_types: input.grantTypes,
          scopes: input.scopes,
          first_party: input.firstParty,
          jwt_auth_public_key_pem: input.jwtAuthPublicKeyPem,
          service_account_id: input.serviceAccountId,
          app_identity: input.appIdentity === undefined ? undefined : toWireAppIdentity(input.appIdentity),
          backchannel_logout_uri: input.backchannelLogoutUri,
          backchannel_logout_session_required: input.backchannelLogoutSessionRequired,
          initiate_login_uri: input.initiateLoginUri,
        },
      },
    );
    return {
      clientId: body.client_id,
      clientName: body.client_name,
      clientSecret: body.client_secret,
      ...(body.app_identity === undefined ? {} : { appIdentity: fromWireAppIdentity(body.app_identity) }),
      ...(body.backchannel_logout_uri === undefined
        ? {}
        : {
            backchannelLogoutUri: body.backchannel_logout_uri,
            backchannelLogoutSessionRequired: body.backchannel_logout_session_required ?? false,
          }),
      ...(body.initiate_login_uri === undefined ? {} : { initiateLoginUri: body.initiate_login_uri }),
    };
  }

  /** List a tenant's apps. */
  async listApps(scope: TenantScope = {}): Promise<App[]> {
    const body = await this.request<wire.AppsListResponse>("GET", "/api/v1/apps", {
      query: { tenant_id: scope.tenantId },
    });
    return (body.apps ?? []).map(toApp);
  }

  // --- connections -------------------------------------------------------

  /** Create or update a social connection for the tenant. The client secret is
   *  encrypted at rest by the server and never returned. */
  async upsertConnection(input: UpsertConnectionInput): Promise<Connection> {
    const body = await this.request<WireConnection>("POST", "/api/v1/connections", {
      body: {
        tenant_id: input.tenantId,
        provider: input.provider,
        client_id: input.clientId,
        client_secret: input.clientSecret,
        redirect_uri: input.redirectUri,
        enabled: input.enabled,
      },
    });
    return toConnection(body);
  }

  /** List the tenant's connections (secrets are never returned). */
  async listConnections(scope: TenantScope = {}): Promise<Connection[]> {
    const body = await this.request<wire.ConnectionsListResponse>("GET", "/api/v1/connections", {
      query: { tenant_id: scope.tenantId },
    });
    return (body.connections ?? []).map(toConnection);
  }

  // --- audit -------------------------------------------------------------

  /**
   * The tenant's audit events, newest first.
   *
   * **This took `limit` and nothing else until the filters below were added**,
   * while the API had taken seven since the audit search shipped. So the search
   * was reachable from `curl` and not from the
   * client a customer integrates with — and the workaround, paging the whole
   * trail and filtering in the caller, is the one thing keyset paging exists to
   * avoid.
   *
   * Returns the events alone, as it always has. `listAuditPage` is the one that
   * carries the cursor.
   */
  async listAudit(options: ListAuditOptions = {}): Promise<AuditEvent[]> {
    return (await this.listAuditPage(options)).events;
  }

  /**
   * One page of the audit trail, with the cursor for the next.
   *
   * Additive rather than a change to `listAudit`'s return type: every existing
   * caller was written against the array. Without this, a client could not read
   * past the first page at all, which for a tenant with any history is most of
   * their own trail.
   */
  async listAuditPage(options: ListAuditOptions = {}): Promise<AuditPage> {
    const body = await this.request<{ events: WireAuditEvent[]; next_cursor?: string | null }>(
      "GET",
      "/api/v1/audit",
      {
        query: auditQuery(options),
      },
    );
    return {
      events: (body.events ?? []).map(toAuditEvent),
      // `?? null` because the key is documented as present-and-null at the end
      // of the list, and a client that returned `undefined` for one and `null`
      // for the other would make "the end" two different values.
      nextCursor: body.next_cursor ?? null,
    };
  }

  // --- usage ---------------------------------------------------------------

  /**
   * The tenant's metered usage: this month's active users, and the history.
   *
   * Read-only, and there is deliberately no counterpart that writes one — these
   * numbers are produced by people signing in, and an endpoint that could adjust
   * them would be an endpoint that could adjust an invoice.
   *
   * Requires the `usage:read` scope on a tenant key. It is not a credential and
   * moving it takes nothing over, but it is the tenant\'s commercial position —
   * how many customers they have and how fast that is changing — so it is not
   * something an unscoped integration key acquires by default.
   */
  async getUsage(options: GetUsageOptions = {}): Promise<Usage> {
    const body = await this.request<WireUsage>("GET", "/api/v1/usage", {
      query: { tenant_id: options.tenantId, months: options.months },
    });
    return {
      metric: body.metric,
      definition: body.definition,
      period: body.period,
      // Copied only when present: a server from before it says nothing about
      // when the count starts again, and guessing would be the renewal date.
      ...(body.resets_at !== undefined ? { resetsAt: body.resets_at } : {}),
      activeUsers: body.active_users,
      series: (body.series ?? []).map((p) => ({
        period: p.period,
        activeUsers: p.active_users,
      })),
      tenantId: body.tenant_id,
      // Copied only when present, so an older server that does not send a cap
      // reads as "this response did not say" rather than as "no cap" — the
      // distinction the whole point of `over_soft_cap` depends on.
      ...(body.soft_cap !== undefined ? { softCap: body.soft_cap } : {}),
      ...(body.effective_soft_cap !== undefined ? { effectiveSoftCap: body.effective_soft_cap } : {}),
      ...(body.over_soft_cap !== undefined ? { overSoftCap: body.over_soft_cap } : {}),
      // Copied only when present, for the reason above: a server from before
      // plans says nothing about them, which is not the same as FREE.
      ...(body.plan !== undefined ? { plan: body.plan } : {}),
      ...(body.included_active_users !== undefined ? { includedActiveUsers: body.included_active_users } : {}),
      ...(body.over_included !== undefined ? { overIncluded: body.over_included } : {}),
    };
  }

  // --- users and principals ----------------------------------------------

  /**
   * Look one user up by exact username, with their second-factor status.
   *
   * Exact, not a search — `searchUsers` is the one that matches. This is the
   * call for "the person on the phone says they are alice@acme": it answers
   * with the id every other user method needs, and with what they currently
   * hold, so an operator can tell a lost phone from a forgotten password before
   * doing anything irreversible.
   */
  async findUser(username: string, scope: TenantScope = {}): Promise<UserLookup> {
    const w = await this.request<wire.UsersLookupResponse>("GET", "/api/v1/users", {
      query: { username, tenant_id: scope.tenantId },
    });
    return {
      id: w.id,
      username: w.username,
      email: w.email,
      isActive: w.is_active,
      mfa: {
        totp: w.mfa.totp,
        passkeys: w.mfa.passkeys,
        recoveryCodesRemaining: w.mfa.recovery_codes_remaining,
        email: w.mfa.email,
        sms: w.mfa.sms,
      },
    };
  }

  /** Create a password user in a tenant. */
  async createUser(input: CreateUserInput): Promise<CreatedUser> {
    const w = await this.request<wire.UserCreated>("POST", "/api/v1/users", {
      body: {
        tenant_id: input.tenantId,
        username: input.username,
        password: input.password,
        email: input.email,
        email_verified: input.emailVerified,
      },
    });
    return { id: w.id, username: w.username, email: w.email, emailVerified: w.email_verified };
  }

  /**
   * Create a non-human principal.
   *
   * The thing a client binds to with `createApp({ serviceAccountId })` or
   * `bindAppServiceAccount`, so that tokens it mints act as somebody rather
   * than as itself.
   */
  async createServiceAccount(input: CreateServiceAccountInput): Promise<CreatedServiceAccount> {
    const w = await this.request<wire.ServiceAccountCreated>("POST", "/api/v1/service-accounts", {
      body: { tenant_id: input.tenantId, name: input.name },
    });
    return { id: w.id, name: w.name, kind: w.kind };
  }

  /** List and filter a tenant's users, one page at a time. */
  async searchUsers(options: SearchUsersOptions = {}): Promise<UserPage> {
    const w = await this.request<wire.UserSearchResults>("GET", "/api/v1/users/search", {
      query: { q: options.q, page: options.page, tenant_id: options.tenantId },
    });
    return {
      users: (w.users ?? []).map((u) => ({
        id: u.id,
        username: u.username,
        email: u.email,
        emailVerified: u.email_verified,
        isActive: u.is_active,
        createdAt: u.created_at,
      })),
      total: w.total,
      page: w.page,
      perPage: w.per_page,
    };
  }

  /** Invite somebody to create their own account. */
  async inviteUser(input: InviteUserInput): Promise<Invitation> {
    const w = await this.request<wire.UserInvited>("POST", "/api/v1/users/invite", {
      body: { tenant_id: input.tenantId, email: input.email, client_id: input.clientId },
    });
    return {
      email: w.email,
      expiresAt: w.expires_at,
      delivered: w.delivered,
      ...(w.client_id === undefined ? {} : { clientId: w.client_id }),
    };
  }

  /**
   * Clear a user's second factors — the lost-phone response.
   *
   * Removes TOTP and every passkey, so the account falls back to its password
   * alone until the user enrols again. That is a real reduction in the
   * account's protection, which is why the server asks for a reason and records
   * it, and why the result says exactly what was removed rather than just
   * succeeding.
   */
  async resetUserMfa(userId: string, input: { tenantId?: string | null; reason?: string } = {}): Promise<ResetMfaResult> {
    const w = await this.request<wire.UsersResetMfaResponse>(
      "POST",
      `/api/v1/users/${segment(userId)}/mfa/reset`,
      { body: { tenant_id: input.tenantId, reason: input.reason } },
    );
    return {
      userId: w.user_id,
      username: w.username,
      totpRemoved: w.totp_removed,
      passkeysRemoved: w.passkeys_removed,
      emailRemoved: w.email_removed,
      smsRemoved: w.sms_removed,
      note: w.note,
    };
  }

  /**
   * End every session and refresh token a user holds — the compromise response.
   *
   * Not reversible and not meant to be: the user signs in again. Pair it with
   * `deactivateUser` when the account itself is the problem rather than a
   * stolen session.
   */
  async revokeUserSessions(
    userId: string,
    input: { tenantId?: string | null; reason?: string } = {},
  ): Promise<RevokeSessionsResult> {
    const w = await this.request<wire.UsersRevokeSessionsResponse>(
      "POST",
      `/api/v1/users/${segment(userId)}/sessions/revoke`,
      { body: { tenant_id: input.tenantId, reason: input.reason } },
    );
    return {
      userId: w.user_id,
      username: w.username,
      sessionsRevokedAt: w.sessions_revoked_at,
      reason: w.reason,
      performedBy: w.performed_by,
      note: w.note,
    };
  }

  /**
   * Turn an account off and end its sessions.
   *
   * Read `sessionsRevokedAt` on the result. `null` here does not mean "no
   * sessions" — it means the account was switched off and the revocation did
   * not complete, so the user may still be holding a live one. Follow with
   * `revokeUserSessions` when that happens.
   */
  async deactivateUser(userId: string, input: UserActivationInput): Promise<UserActivationChanged> {
    return this.setUserActive(userId, "deactivate", input);
  }

  /**
   * Turn an account back on.
   *
   * Does not restore sessions — they were revoked, and revocation is not
   * reversible. `sessionsRevokedAt` is always `null` on this path.
   */
  async reactivateUser(userId: string, input: UserActivationInput): Promise<UserActivationChanged> {
    return this.setUserActive(userId, "reactivate", input);
  }

  private async setUserActive(
    userId: string,
    action: "deactivate" | "reactivate",
    input: UserActivationInput,
  ): Promise<UserActivationChanged> {
    const w = await this.request<wire.UserDeactivated | wire.UserReactivated>(
      "POST",
      `/api/v1/users/${segment(userId)}/${action}`,
      { body: { tenant_id: input.tenantId, reason: input.reason } },
    );
    return {
      userId: w.user_id,
      username: w.username,
      isActive: w.is_active,
      changed: w.changed,
      sessionsRevokedAt: w.sessions_revoked_at,
      performedBy: w.performed_by,
    };
  }

  /**
   * Deactivate or reactivate many accounts in one call.
   *
   * The server caps how many one call may touch and answers with three
   * separate numbers rather than a boolean: what changed, what was already in
   * that state, and which ids named nobody. All three matter — a retry shows up
   * entirely in the second, and a typo shows up entirely in the third.
   */
  async bulkUpdateUsers(input: BulkUsersInput): Promise<BulkUsersResult> {
    const w = await this.request<wire.BulkUsersResult>("POST", "/api/v1/users/bulk", {
      body: {
        tenant_id: input.tenantId,
        user_ids: input.userIds,
        action: input.action,
        reason: input.reason,
      },
    });
    return {
      changed: w.changed,
      alreadyInThatState: w.already_in_that_state,
      notFound: w.not_found ?? [],
      sessionsRevokedAt: w.sessions_revoked_at,
    };
  }

  // --- applications, and the credentials behind them ----------------------

  /**
   * Change an existing client's configuration.
   *
   * The counterpart `createApp` never had: a client could be created through
   * this SDK and never modified through it, so adding one redirect URI meant
   * dropping to raw HTTP or recreating the client with a new id.
   */
  async updateApp(clientId: string, patch: UpdateAppInput): Promise<UpdatedApp> {
    const w = await this.request<wire.AppUpdated>(
      "PATCH",
      `/api/v1/apps/${segment(clientId)}`,
      {
        body: {
          tenant_id: patch.tenantId,
          client_name: patch.clientName,
          redirect_uris: patch.redirectUris,
          post_logout_redirect_uris: patch.postLogoutRedirectUris,
          grant_types: patch.grantTypes,
          scopes: patch.scopes,
          is_active: patch.isActive,
          first_party: patch.firstParty,
          // `null` is sent, and clears the identity; omitted is left out.
          app_identity:
            patch.appIdentity === undefined ? undefined : patch.appIdentity === null ? null : toWireAppIdentity(patch.appIdentity),
          // `null` is sent, and stops the app being told; omitted is left out.
          backchannel_logout_uri: patch.backchannelLogoutUri,
          backchannel_logout_session_required: patch.backchannelLogoutSessionRequired,
          // `null` is sent, and clears it; omitted is left out.
          initiate_login_uri: patch.initiateLoginUri,
        },
      },
    );
    return {
      clientId: w.client_id,
      clientName: w.client_name,
      clientType: w.client_type,
      grantTypes: w.grant_types,
      redirectUris: w.redirect_uris,
      postLogoutRedirectUris: w.post_logout_redirect_uris,
      scopes: w.scopes,
      firstParty: w.first_party,
      isActive: w.is_active,
      appIdentity: w.app_identity == null ? null : fromWireAppIdentity(w.app_identity),
      backchannelLogoutUri: w.backchannel_logout_uri ?? null,
      backchannelLogoutSessionRequired: w.backchannel_logout_session_required ?? false,
      initiateLoginUri: w.initiate_login_uri ?? null,
    };
  }

  /**
   * Delete a **self-registered** client.
   *
   * Deliberately narrow: the server answers 404 for an operator-provisioned
   * one, so this cannot be used to remove a production client and cascade its
   * sessions — and the 404 is chosen over a 403 so it is no oracle either.
   * `updateApp(clientId, { isActive: false })` is the reversible answer for a
   * client you merely suspect.
   */
  async deleteApp(clientId: string, scope: TenantScope = {}): Promise<void> {
    await this.request<void>("DELETE", `/api/v1/apps/${segment(clientId)}`, {
      query: { tenant_id: scope.tenantId },
    });
  }

  /**
   * Issue a new client secret while the old one still works.
   *
   * The overlap is the feature. Rotate, roll out, then `retireAppSecret` once
   * every consumer is on the new secret — rather than rotating and racing a
   * deploy.
   */
  async rotateAppSecret(clientId: string, input: RotateAppSecretInput = {}): Promise<RotatedAppSecret> {
    const w = await this.request<wire.SecretRotated>(
      "POST",
      `/api/v1/apps/${segment(clientId)}/rotate-secret`,
      // `tenant_id` in the QUERY and `overlap_hours` in the body, because the
      // handler reads the tenant from `Query<TenantQuery>` and the body as a
      // `RotateSecretRequest`, which holds `overlap_hours` and nothing else.
      // A tenant sent in the body is refused as a field it does not know.
      { query: { tenant_id: input.tenantId }, body: { overlap_hours: input.overlapHours } },
    );
    return {
      clientId: w.client_id,
      clientSecret: w.client_secret,
      previousSecretExpiresAt: w.previous_secret_expires_at,
    };
  }

  /**
   * End the overlap early, once every consumer holds the new secret.
   *
   * The other half of a leaked-secret response: `rotateAppSecret` stops the
   * leak spreading, this one stops the leaked secret working.
   */
  async retireAppSecret(clientId: string, scope: TenantScope = {}): Promise<void> {
    await this.request<void>("POST", `/api/v1/apps/${segment(clientId)}/retire-secret`, {
      query: { tenant_id: scope.tenantId },
    });
  }

  /**
   * "Test this app": what the app's registration will do, before a real person
   * finds out. Whether it is on, whether a refresh token is issued, its
   * redirect and post-logout addresses, `openid`, and its back-channel logout
   * address. Read-only, from the registration alone; `ready` is false when any
   * finding is a `problem`. Under `apps:read`.
   */
  async checkApp(clientId: string, scope: TenantScope = {}): Promise<AppCheck> {
    const w = await this.request<wire.AppCheck>("GET", `/api/v1/apps/${segment(clientId)}/check`, {
      query: { tenant_id: scope.tenantId },
    });
    const findings = w.findings.map(toAppCheckFinding);
    return {
      clientId: w.client_id,
      clientName: w.client_name,
      ready: w.ready,
      findings,
    };
  }

  /**
   * Bind a client to a service account, or clear the binding.
   *
   * Also the recovery path for a `createApp` that named a bad
   * `serviceAccountId`: that call binds after the client row is committed, so a
   * bad id leaves a working client, an unbound principal, and a 400 that
   * carried away neither the client id nor the one-time secret.
   *
   * Omit `serviceAccountId` to clear the binding.
   */
  async bindAppServiceAccount(
    clientId: string,
    input: { tenantId?: string | null; serviceAccountId?: string | null } = {},
  ): Promise<BoundServiceAccount> {
    const w = await this.request<wire.ServiceAccountBound>(
      "PUT",
      `/api/v1/apps/${segment(clientId)}/service-account`,
      { body: { tenant_id: input.tenantId, service_account_id: input.serviceAccountId ?? null } },
    );
    return { clientId: w.client_id, serviceAccountId: w.service_account_id };
  }

  // --- tenant lifecycle ---------------------------------------------------

  /**
   * Delete a tenant and everything belonging to it.
   *
   * `confirmSlug` must be the tenant's own slug; the server refuses a mismatch.
   *
   * Read `auditRowsMayContainIdentifiers` on the result. It is `true`: one hash
   * chain covers every tenant, so the audit rows stay, and they can still name
   * the deleted tenant's people. An erasure request has to be answered with
   * that in mind rather than with "the tenant is gone".
   */
  async deleteTenant(tenantId: string, input: DeleteTenantInput): Promise<TenantDeleted> {
    const w = await this.request<wire.TenantDeleted>(
      "DELETE",
      `/api/v1/tenants/${segment(tenantId)}`,
      { body: { confirm_slug: input.confirmSlug } },
    );
    return {
      id: w.id,
      slug: w.slug,
      deleted: w.deleted,
      users: w.users,
      clients: w.clients,
      apiKeys: w.api_keys,
      auditRows: w.audit_rows,
      auditRowsMayContainIdentifiers: w.audit_rows_may_contain_identifiers,
    };
  }

  /**
   * Switch a tenant off, or back on.
   *
   * The reversible answer when a whole tenant is the incident — unlike
   * `deleteTenant`, which is not.
   */
  async setTenantStatus(tenantId: string, input: SetTenantStatusInput): Promise<TenantStatusChanged> {
    const w = await this.request<wire.TenantStatusChanged>(
      "PUT",
      `/api/v1/tenants/${segment(tenantId)}/status`,
      { body: { status: input.status, reason: input.reason } },
    );
    return { id: w.id, status: w.status, previousStatus: w.previous_status };
  }

  /** Rotate the tenant's data encryption key. */
  async rotateDataKey(tenantId: string): Promise<DataKeyRotated> {
    const w = await this.request<wire.DataKeyRotated>(
      "POST",
      `/api/v1/tenants/${segment(tenantId)}/data-key/rotate`,
    );
    return {
      tenantId: w.tenant_id,
      version: w.version,
      previousVersion: w.previous_version,
      notice: w.notice,
    };
  }

  /**
   * Rotate the tenant's token-**signing** key.
   *
   * Not the same thing as `rotateApiKey`, and the paths are one segment apart:
   * this is `/keys/rotate`, that is `/keys/{key_id}/rotate`. This one changes
   * how tokens are signed; that one replaces a management credential.
   */
  async rotateSigningKey(tenantId: string): Promise<SigningKeyRotated> {
    const w = await this.request<wire.SigningKeyRotated>(
      "POST",
      `/api/v1/tenants/${segment(tenantId)}/keys/rotate`,
    );
    return { kid: w.signing_key.kid, alg: w.signing_key.alg };
  }

  /**
   * Mint a successor management key and give this one a deadline.
   *
   * The overlap equivalent of `rotateAppSecret`, for the credential this client
   * itself authenticates with.
   */
  async rotateApiKey(tenantId: string, keyId: string): Promise<RotatedApiKey> {
    const w = await this.request<wire.ApiKeyRotated>(
      "POST",
      `/api/v1/tenants/${segment(tenantId)}/keys/${segment(keyId)}/rotate`,
    );
    return {
      id: w.id,
      name: w.name,
      apiKey: w.api_key,
      replaces: w.replaces,
      previousKeyExpiresAt: w.previous_key_expires_at,
    };
  }

  /**
   * How long sign-ins last for this tenant, with the bounds it must sit in.
   *
   * Took no scope until the server grew one. `get_session_lifetime` resolved
   * its tenant from the credential alone, so a platform operator could SET any
   * tenant's session lifetime through `setSessionLifetime` — which has always
   * read `tenant_id` from its body — and then not read it back. Two verbs of one
   * setting disagreeing about who may address a tenant. The fix is the
   * obvious one: give the read the same optional `tenantId` the write already
   * takes.
   */
  async getSessionLifetime(scope: TenantScope = {}): Promise<SessionLifetime> {
    const w = await this.request<wire.SessionLifetime>("GET", "/api/v1/tenant/session-lifetime", {
      query: { tenant_id: scope.tenantId },
    });
    return {
      tenantId: w.tenant_id,
      sessionTtlSeconds: w.session_ttl_seconds,
      effectiveSessionTtlSeconds: w.effective_session_ttl_seconds,
      defaultSessionTtlSeconds: w.default_session_ttl_seconds,
      minSessionTtlSeconds: w.min_session_ttl_seconds,
      maxSessionTtlSeconds: w.max_session_ttl_seconds,
      plan: w.plan,
      allowedSessionTtlSeconds: w.allowed_session_ttl_seconds,
    };
  }

  /**
   * The plan in force for this tenant and what it includes.
   *
   * Requires `tenant:read` on a tenant key. The entitlements are the ones the
   * server applies — its own table where the tenant is held to its plan
   * (`enforced`), the unrestricted set where it is not — so a billing screen
   * built on this cannot drift from what the server enforces.
   */
  async getPlan(scope: TenantScope = {}): Promise<TenantPlan> {
    const w = await this.request<wire.TenantPlan>("GET", "/api/v1/plan", {
      query: { tenant_id: scope.tenantId },
    });
    const e = w.entitlements;
    return {
      tenantId: w.tenant_id,
      plan: w.plan,
      source: w.source,
      enforced: w.enforced,
      // Copied only when present: a server before 2026-10-03 does not say why.
      ...(w.plan_binding !== undefined ? { planBinding: w.plan_binding } : {}),
      entitlements: {
        includedActiveUsers: e.included_active_users,
        activeUserOverageBilled: e.active_user_overage_billed,
        includedSeats: e.included_seats,
        extraSeatsBilled: e.extra_seats_billed,
        logRetentionDays: e.log_retention_days,
        allowedSessionTtlSeconds: e.allowed_session_ttl_seconds,
        sms: e.sms,
        enhancedSupport: e.enhanced_support,
        // Absent from a server before migration 0174, which limited none of
        // the three: read as no limit, which is what that server did.
        maxSocialConnections: e.max_social_connections ?? null,
        saml: e.saml ?? true,
        machineIdentity: e.machine_identity ?? true,
      },
    };
  }

  /**
   * Set or clear this tenant's session lifetime.
   *
   * `null` clears the override and falls back to the deployment default; a
   * number sets it. Omitting the field entirely is not the same request, so it
   * is spelled `sessionTtlSeconds: null` rather than left out.
   */
  async setSessionLifetime(
    input: TenantScope & { sessionTtlSeconds: number | null },
  ): Promise<SessionLifetimeSet> {
    const w = await this.request<wire.SessionLifetimeSet>("PUT", "/api/v1/tenant/session-lifetime", {
      body: { tenant_id: input.tenantId, session_ttl_seconds: input.sessionTtlSeconds },
    });
    return {
      tenantId: w.tenant_id,
      sessionTtlSeconds: w.session_ttl_seconds,
      effectiveSessionTtlSeconds: w.effective_session_ttl_seconds,
    };
  }

  /**
   * Which plan this tenant is on, and why: the plan in force, whether a
   * subscription or the operator's override puts it there, and the
   * subscription's status, interval and renewal. No billing-provider ids.
   *
   * Read-only by design. A plan is bought or changed by an owner in the
   * tenant console, and written by the billing provider's webhook — never by
   * an API key.
   */
  async getBilling(scope: TenantScope = {}): Promise<Billing> {
    const w = await this.request<wire.Billing>("GET", "/api/v1/billing", {
      query: { tenant_id: scope.tenantId },
    });
    const s = w.subscription;
    return {
      tenantId: w.tenant_id,
      plan: w.plan,
      source: w.source,
      overridePlan: w.override_plan,
      billingEnabled: w.billing_enabled,
      subscription:
        s === null
          ? null
          : {
              plan: s.plan,
              status: s.status,
              inForce: s.in_force,
              interval: s.interval,
              currentPeriodEnd: s.current_period_end,
              cancelAtPeriodEnd: s.cancel_at_period_end,
              extraSeats: s.extra_seats,
            },
    };
  }

  /**
   * The SMS second factor: whether the tenant has switched it on, whether its
   * plan includes it, whether the deployment can send at all, and the month's
   * texts. Included in TEAM and BUSINESS and not billed per message; the
   * counts make the cost visible.
   */
  async getSmsFactor(scope: TenantScope = {}): Promise<SmsFactor> {
    const w = await this.request<wire.SmsFactor>("GET", "/api/v1/tenant/sms-factor", {
      query: { tenant_id: scope.tenantId },
    });
    return smsFactorFromWire(w);
  }

  /**
   * Turn the SMS second factor on or off.
   *
   * On needs a plan that includes SMS (TEAM or BUSINESS); FREE is refused with
   * a `403`. Off is always allowed and removes nobody's factor — it stops new
   * enrolments, and keeps SMS at sign-in only for the accounts it is the one
   * way into.
   */
  async setSmsFactor(input: TenantScope & { enabled: boolean }): Promise<SmsFactor> {
    const w = await this.request<wire.SmsFactor>("PUT", "/api/v1/tenant/sms-factor", {
      body: { tenant_id: input.tenantId, enabled: input.enabled },
    });
    return smsFactorFromWire(w);
  }

  /** The CAs a tenant accepts attested authenticators from, and its posture. */
  async listAttestationCas(tenantId: string): Promise<AttestationCaList> {
    const w = await this.request<wire.AttestationCaList>(
      "GET",
      `/api/v1/tenants/${segment(tenantId)}/passkey-attestation/cas`,
    );
    return {
      passkeyAttestation: w.passkey_attestation,
      cas: (w.cas ?? []).map((c) => ({
        id: c.id,
        label: c.label,
        aaguid: c.aaguid,
        certSha256: c.cert_sha256,
      })),
    };
  }

  /**
   * Register a CA whose authenticators this tenant will accept.
   *
   * Do this before setting `passkeyAttestation: "required"`. The server refuses
   * that transition with a 409 while the list is empty, because every
   * registration would fail the chain check.
   */
  async addAttestationCa(tenantId: string, input: AddAttestationCaInput): Promise<{ id: string }> {
    const w = await this.request<wire.AttestationCaAdded>(
      "POST",
      `/api/v1/tenants/${segment(tenantId)}/passkey-attestation/cas`,
      { body: { label: input.label, aaguid: input.aaguid, cert_pem: input.certPem } },
    );
    return { id: w.id };
  }

  /** Remove a CA from a tenant's attestation list. */
  async removeAttestationCa(tenantId: string, caId: string): Promise<void> {
    await this.request<void>(
      "DELETE",
      `/api/v1/tenants/${segment(tenantId)}/passkey-attestation/cas/${segment(caId)}`,
    );
  }

  // --- webhooks -----------------------------------------------------------

  /** The tenant's notification endpoints. */
  async listWebhooks(scope: TenantScope = {}): Promise<WebhookEndpoint[]> {
    const w = await this.request<wire.WebhookEndpointList>("GET", "/api/v1/webhooks", {
      query: { tenant_id: scope.tenantId },
    });
    return (w.webhooks ?? []).map(toWebhookEndpoint);
  }

  /**
   * Whether the platform has allowed this tenant to sign its people in with
   * SAML, as a service provider (phase 1). Acting as an identity provider is
   * {@link getTenantSamlIdp}.
   *
   * Platform token only. A tenant API key cannot read or set it however it is
   * scoped — the switch exists so an operator decides who may reach a surface
   * they have not finished reviewing.
   */
  async getTenantSaml(tenantId: string): Promise<TenantSamlEnabled> {
    const w = await this.request<wire.TenantSamlEnabled>("GET", `/api/v1/tenants/${segment(tenantId)}/saml`, {});
    return { enabled: w.enabled };
  }

  /** Turn SAML sign-in (phase 1) on or off for a tenant. Takes effect on the next request. */
  async setTenantSaml(tenantId: string, enabled: boolean): Promise<TenantSamlEnabled> {
    const w = await this.request<wire.TenantSamlEnabled>("PUT", `/api/v1/tenants/${segment(tenantId)}/saml`, {
      body: { enabled },
    });
    return { enabled: w.enabled };
  }

  /**
   * Whether the platform has allowed this tenant to act as a SAML identity
   * provider (phase 2). Not the same switch as {@link getTenantSaml}.
   *
   * Platform token only, like the phase 1 switch.
   */
  async getTenantSamlIdp(tenantId: string): Promise<TenantSamlIdpEnabled> {
    const w = await this.request<wire.TenantSamlIdpEnabled>("GET", `/api/v1/tenants/${segment(tenantId)}/saml-idp`, {});
    return { enabled: w.enabled, ssoUrl: w.sso_url };
  }

  /**
   * Turn the SAML identity provider on or off for a tenant. Takes effect on the
   * next request: metadata stops being served and no key is minted. Signing
   * keys already minted are kept, and can still be listed, promoted and
   * revoked.
   */
  async setTenantSamlIdp(tenantId: string, enabled: boolean): Promise<TenantSamlIdpEnabled> {
    const w = await this.request<wire.TenantSamlIdpEnabled>("PUT", `/api/v1/tenants/${segment(tenantId)}/saml-idp`, {
      body: { enabled },
    });
    return { enabled: w.enabled, ssoUrl: w.sso_url };
  }

  /**
   * The tenant's SAML connections, enabled or not.
   *
   * Needs `saml:read`, which is strict: an API key with no scopes does not have
   * it. `saml:write` does not imply it either — the strict family does not do
   * the write-implies-read favour the others do.
   */
  async listSamlConnections(scope: TenantScope = {}): Promise<SamlConnection[]> {
    const w = await this.request<wire.SamlConnectionList>("GET", "/api/v1/saml/connections", {
      query: { tenant_id: scope.tenantId },
    });
    return (w.connections ?? []).map(toSamlConnection);
  }

  /** One SAML connection, with the certificates it trusts. */
  async getSamlConnection(id: string, scope: TenantScope = {}): Promise<SamlConnection> {
    const w = await this.request<wire.SamlConnection>("GET", `/api/v1/saml/connections/${segment(id)}`, {
      query: { tenant_id: scope.tenantId },
    });
    return toSamlConnection(w);
  }

  /**
   * Configure an identity provider this tenant's users may sign in through.
   *
   * The certificate is checked before it is stored, with the same loader
   * verification uses, so an unusable PEM is a 400 here rather than a broken
   * login later. A connection is disabled unless `enabled` says otherwise.
   */
  async createSamlConnection(input: SamlConnectionInput): Promise<SamlConnection> {
    const w = await this.request<wire.SamlConnection>("POST", "/api/v1/saml/connections", {
      body: {
        tenant_id: input.tenantId,
        name: input.name,
        idp_entity_id: input.idpEntityId,
        idp_sso_url: input.idpSsoUrl,
        certificate_pem: input.certificatePem,
        certificate_next_pem: input.certificateNextPem,
        sp_entity_id: input.spEntityId,
        acs_url: input.acsUrl,
        attr_username: input.attrUsername,
        attr_email: input.attrEmail,
        max_assertion_lifetime_seconds: input.maxAssertionLifetimeSeconds,
        allow_unsolicited: input.allowUnsolicited,
        relay_state_hosts: input.relayStateHosts,
        enabled: input.enabled,
      },
    });
    return toSamlConnection(w);
  }

  /**
   * Replace a connection wholesale. There is no patch, and the server means it:
   * an omitted field is not the one it was, it is the default.
   */
  async replaceSamlConnection(id: string, input: SamlConnectionInput): Promise<SamlConnection> {
    const w = await this.request<wire.SamlConnection>("PUT", `/api/v1/saml/connections/${segment(id)}`, {
      body: {
        tenant_id: input.tenantId,
        name: input.name,
        idp_entity_id: input.idpEntityId,
        idp_sso_url: input.idpSsoUrl,
        certificate_pem: input.certificatePem,
        certificate_next_pem: input.certificateNextPem,
        sp_entity_id: input.spEntityId,
        acs_url: input.acsUrl,
        attr_username: input.attrUsername,
        attr_email: input.attrEmail,
        max_assertion_lifetime_seconds: input.maxAssertionLifetimeSeconds,
        allow_unsolicited: input.allowUnsolicited,
        relay_state_hosts: input.relayStateHosts,
        enabled: input.enabled,
      },
    });
    return toSamlConnection(w);
  }

  /** Remove a connection. Sign-in through that provider stops immediately. */
  async deleteSamlConnection(id: string, scope: TenantScope = {}): Promise<void> {
    await this.request<void>("DELETE", `/api/v1/saml/connections/${segment(id)}`, {
      query: { tenant_id: scope.tenantId },
    });
  }

  /**
   * The applications this tenant may sign users into, with Proteles as the IdP.
   *
   * Needs `saml-sp:read`, which is strict and is *not* `saml:read`. Federating
   * your staff to a provider and handing an application a signed assertion about
   * them are different powers held by different people.
   */
  async listSamlServiceProviders(scope: TenantScope = {}): Promise<SamlServiceProvider[]> {
    const w = await this.request<wire.SamlServiceProviderList>("GET", "/api/v1/saml/service-providers", {
      query: { tenant_id: scope.tenantId },
    });
    return (w.service_providers ?? []).map(toSamlServiceProvider);
  }

  /** One registration, with the allowlist it may deliver to. */
  async getSamlServiceProvider(id: string, scope: TenantScope = {}): Promise<SamlServiceProvider> {
    const w = await this.request<wire.SamlServiceProvider>("GET", `/api/v1/saml/service-providers/${segment(id)}`, {
      query: { tenant_id: scope.tenantId },
    });
    return toSamlServiceProvider(w);
  }

  /**
   * Register an application this tenant may sign users into.
   *
   * Every destination in `acsUrls` is checked before it is stored, by the same
   * predicate the delivery path uses — so a URL that could not be delivered to
   * safely is a 400 here rather than a signed assertion somewhere unexpected
   * later. With more than one destination, `defaultAcsUrl` must say which one
   * a request naming none is answered at. A registration is disabled unless
   * `enabled` says otherwise.
   *
   * Refused with a 403 until the platform operator has enabled this tenant as
   * a SAML identity provider.
   */
  async createSamlServiceProvider(input: SamlServiceProviderInput): Promise<SamlServiceProvider> {
    const w = await this.request<wire.SamlServiceProvider>("POST", "/api/v1/saml/service-providers", {
      body: {
        tenant_id: input.tenantId,
        name: input.name,
        sp_entity_id: input.spEntityId,
        acs_urls: input.acsUrls,
        default_acs_url: input.defaultAcsUrl,
        request_signing_certificate_pem: input.requestSigningCertificatePem,
        name_id_format: input.nameIdFormat,
        enrol_on_first_sign_in: input.enrolOnFirstSignIn,
        slo_url: input.sloUrl,
        open_to_every_tenant_user: input.openToEveryTenantUser,
        enabled: input.enabled,
      },
    });
    return toSamlServiceProvider(w);
  }

  /**
   * Replace a registration wholesale. An omitted field is not the one it was, it
   * is the default — which for `acsUrls` means the set you send is the set that
   * may receive an assertion. `defaultAcsUrl` has no default once `acsUrls`
   * names more than one destination: state it again, or the replacement is a
   * 400.
   *
   * `spEntityId` and `nameIdFormat` must be the registration's own (an omitted
   * `nameIdFormat` means persistent): a 409 otherwise, because an application's
   * trust is bound to its entity id and it knows each person by the NameID
   * format. A new entity id is a new service provider; a new format means
   * deleting this one and registering it again, which discards every
   * identifier issued under it. Refused with a 403 while the tenant is not
   * enabled as an identity provider.
   */
  async replaceSamlServiceProvider(id: string, input: SamlServiceProviderInput): Promise<SamlServiceProvider> {
    const w = await this.request<wire.SamlServiceProvider>("PUT", `/api/v1/saml/service-providers/${segment(id)}`, {
      body: {
        tenant_id: input.tenantId,
        name: input.name,
        sp_entity_id: input.spEntityId,
        acs_urls: input.acsUrls,
        default_acs_url: input.defaultAcsUrl,
        request_signing_certificate_pem: input.requestSigningCertificatePem,
        name_id_format: input.nameIdFormat,
        enrol_on_first_sign_in: input.enrolOnFirstSignIn,
        slo_url: input.sloUrl,
        open_to_every_tenant_user: input.openToEveryTenantUser,
        enabled: input.enabled,
      },
    });
    return toSamlServiceProvider(w);
  }

  /**
   * Remove a registration. New sign-ins to that application stop immediately;
   * assertions already delivered are not recalled, and any session the
   * application minted from one is the application's to end. Allowed even
   * while the tenant is not enabled as an identity provider.
   */
  async deleteSamlServiceProvider(id: string, scope: TenantScope = {}): Promise<void> {
    await this.request<void>("DELETE", `/api/v1/saml/service-providers/${segment(id)}`, {
      query: { tenant_id: scope.tenantId },
    });
  }

  /**
   * Who may reach this registration.
   *
   * Returns the whole set, and the `openToEveryTenantUser` flag beside it: an
   * empty list means nobody only when that flag is false.
   */
  async listSamlServiceProviderAssignments(
    id: string,
    scope: TenantScope = {},
  ): Promise<SamlServiceProviderAssignments> {
    const w = await this.request<wire.SamlServiceProviderAssignmentList>(
      "GET",
      `/api/v1/saml/service-providers/${segment(id)}/assignments`,
      { query: { tenant_id: scope.tenantId } },
    );
    return {
      openToEveryTenantUser: w.open_to_every_tenant_user,
      assignments: (w.assignments ?? []).map(toSamlServiceProviderAssignment),
    };
  }

  /**
   * Let one person reach this application.
   *
   * Idempotent: assigning somebody already assigned answers with the grant
   * they already had, and does not move its `createdAt`. A 404 means no such
   * registration or no such user *in this tenant*; a 409 means the
   * registration has as many people assigned as it may have, and an
   * application meant for everybody wants `openToEveryTenantUser` instead.
   * Refused with a 403 while the tenant is not enabled as an identity provider.
   */
  async assignSamlServiceProviderUser(
    id: string,
    userId: string,
    scope: TenantScope = {},
  ): Promise<SamlServiceProviderAssignment> {
    const w = await this.request<wire.SamlServiceProviderAssignment>(
      "PUT",
      `/api/v1/saml/service-providers/${segment(id)}/assignments/${segment(userId)}`,
      { query: { tenant_id: scope.tenantId } },
    );
    return toSamlServiceProviderAssignment(w);
  }

  /**
   * Stop one person reaching this application — one call, so that offboarding
   * two people at once cannot lose one of the two removals to a lost update.
   *
   * Idempotent, and succeeds whether or not they were assigned. Allowed even
   * while the tenant is not enabled as an identity provider: taking access
   * away is the call an administrator makes *after* turning SAML off.
   */
  async unassignSamlServiceProviderUser(
    id: string,
    userId: string,
    scope: TenantScope = {},
  ): Promise<void> {
    await this.request<void>(
      "DELETE",
      `/api/v1/saml/service-providers/${segment(id)}/assignments/${segment(userId)}`,
      { query: { tenant_id: scope.tenantId } },
    );
  }

  /**
   * Every SAML signing key this tenant has, revoked ones included, newest first.
   *
   * Deliberately not the list the metadata document publishes: that one drops
   * revoked keys, and a management list that did the same could not confirm the
   * revocation it was opened to confirm. The private half is never present.
   */
  async listSamlIdpKeys(scope: TenantScope = {}): Promise<SamlIdpKey[]> {
    const w = await this.request<wire.SamlIdpKeyList>("GET", "/api/v1/saml/idp-keys", {
      query: { tenant_id: scope.tenantId },
    });
    return (w.idp_keys ?? []).map(toSamlIdpKey);
  }

  /**
   * Mint a signing key. It is published and signs nothing.
   *
   * **Phase one of three.** The new certificate appears in this tenant's
   * metadata alongside the current one; two signing `KeyDescriptor`s are the
   * only in-band way a service provider learns a second key is coming, and an SP
   * that has seen one key has no way to prepare. The server makes the wait:
   * while another key signs, {@link promoteSamlIdpKey} refuses this one until
   * it has been published for the configured overlap.
   *
   * There is no way to supply key material, here or anywhere: an endpoint that
   * took a PEM would be a key-substitution attack reachable from a phishing link
   * sent to a tenant administrator.
   */
  async mintSamlIdpKey(scope: TenantScope = {}): Promise<SamlIdpKey> {
    const w = await this.request<wire.SamlIdpKey>("POST", "/api/v1/saml/idp-keys", {
      query: { tenant_id: scope.tenantId },
    });
    return toSamlIdpKey(w);
  }

  /**
   * Start signing with a published key. **Phase two.**
   *
   * The incumbent retires in the same transaction and keeps being published for
   * the overlap, so an assertion minted a second before this call still verifies
   * at a service provider that has not refetched.
   *
   * Throws `conflict`, with one of three reasons in the error's code:
   *
   * - `publication_wait_open` — another key signs and this one has not been
   *   published long enough: the whole overlap, or, when that can no longer
   *   finish before the signing key is refused, the longest metadata cache. The
   *   message names the time. Never for a tenant's first key, nor behind a key
   *   the signer already refuses.
   * - `rotation_overlap_open` — the previous rotation's overlap is still open.
   *   Not a race to retry through: rotating twice inside the overlap retires a
   *   key service providers only just started trusting and strands them on a
   *   certificate that now signs nothing.
   * - `certificate_expires_too_soon` — this key's certificate is already inside
   *   the expiry warning window; mint a new key.
   *
   * If the signing key is compromised, call {@link revokeSamlIdpKey} — a
   * different operation, not a flag on this one.
   */
  async promoteSamlIdpKey(kid: string, scope: TenantScope = {}): Promise<SamlIdpKey> {
    const w = await this.request<wire.SamlIdpKey>(
      "POST",
      `/api/v1/saml/idp-keys/${segment(kid)}/promote`,
      { query: { tenant_id: scope.tenantId } },
    );
    return toSamlIdpKey(w);
  }

  /**
   * Revoke a compromised key, with no overlap.
   *
   * The key leaves published metadata immediately, can never be published or
   * promoted again, and — if it was the one signing, and the platform still has
   * the tenant enabled as an identity provider — a replacement is minted and
   * promoted in its place, returned as `replacement`. Otherwise `replacement`
   * is null.
   *
   * Overlap is what makes a planned rotation safe and is exactly what must not
   * happen here: every second a compromised certificate stays in metadata is a
   * second an attacker holding the key mints assertions every service provider
   * accepts. Revoking an already-revoked key succeeds with a null replacement.
   */
  async revokeSamlIdpKey(kid: string, scope: TenantScope = {}): Promise<SamlIdpKeyRevocation> {
    const w = await this.request<wire.SamlIdpKeyRevocation>(
      "POST",
      `/api/v1/saml/idp-keys/${segment(kid)}/revoke`,
      { query: { tenant_id: scope.tenantId } },
    );
    return {
      revokedKid: w.revoked_kid,
      replacement: w.replacement ? toSamlIdpKey(w.replacement) : null,
    };
  }

  /** One notification endpoint. */
  async getWebhook(id: string, scope: TenantScope = {}): Promise<WebhookEndpoint> {
    const w = await this.request<wire.WebhookEndpoint>("GET", `/api/v1/webhooks/${segment(id)}`, {
      query: { tenant_id: scope.tenantId },
    });
    return toWebhookEndpoint(w);
  }

  /** Add a notification endpoint. The secret is sent once and never returned. */
  async createWebhook(input: CreateWebhookInput): Promise<WrittenWebhook> {
    const w = await this.request<wire.WebhookEndpointWriteResult>("POST", "/api/v1/webhooks", {
      body: {
        tenant_id: input.tenantId,
        name: input.name,
        url: input.url,
        secret: input.secret,
        events: input.events,
        enabled: input.enabled,
        max_deliveries_per_minute: input.maxDeliveriesPerMinute,
        disable_after_dead_letters: input.disableAfterDeadLetters,
      },
    });
    return toWrittenWebhook(w);
  }

  /**
   * Replace an endpoint's settings.
   *
   * A full replacement, not a patch — `url` and `events` are required because
   * omitting them sets them to nothing rather than leaving them alone. Omitting
   * `secret` is the one exception: that keeps the current one.
   */
  async replaceWebhook(id: string, input: ReplaceWebhookInput): Promise<WrittenWebhook> {
    const w = await this.request<wire.WebhookEndpointWriteResult>(
      "PUT",
      `/api/v1/webhooks/${segment(id)}`,
      {
        body: {
          tenant_id: input.tenantId,
          name: input.name,
          url: input.url,
          secret: input.secret,
          events: input.events,
          enabled: input.enabled,
          max_deliveries_per_minute: input.maxDeliveriesPerMinute,
          disable_after_dead_letters: input.disableAfterDeadLetters,
        },
      },
    );
    return toWrittenWebhook(w);
  }

  /** Stop sending to an endpoint, permanently. */
  async deleteWebhook(id: string, scope: TenantScope = {}): Promise<void> {
    await this.request<void>("DELETE", `/api/v1/webhooks/${segment(id)}`, {
      query: { tenant_id: scope.tenantId },
    });
  }

  /**
   * What happened to recent notifications.
   *
   * No status filter, deliberately: `DeliveryQuery` on the server reads
   * `webhook_id` and `limit` and nothing else, so a `status` option would be
   * one the caller believes they asked with. `status` is on each row — filter
   * the result. `replayDeliveries` is the endpoint that does take one.
   */
  async listDeliveries(options: ListDeliveriesOptions = {}): Promise<WebhookDelivery[]> {
    const w = await this.request<wire.WebhookDeliveryList>("GET", "/api/v1/webhook/deliveries", {
      query: {
        tenant_id: options.tenantId,
        webhook_id: options.webhookId,
        limit: options.limit,
      },
    });
    return (w.deliveries ?? []).map(toDelivery);
  }

  /**
   * Retry a batch of deliveries.
   *
   * Read `moreMayRemain`: `true` means the batch hit its cap and there is more
   * to do, not that anything failed.
   */
  async replayDeliveries(input: ReplayDeliveriesInput = {}): Promise<ReplayResult> {
    const w = await this.request<wire.WebhookReplayResult>("POST", "/api/v1/webhook/deliveries/replay", {
      body: {
        tenant_id: input.tenantId,
        webhook_id: input.webhookId,
        status: input.status,
        since: input.since,
        ids: input.ids,
      },
    });
    return { requeued: w.requeued, moreMayRemain: w.more_may_remain };
  }

  /**
   * Try one delivery again.
   *
   * `tenant_id` goes in the QUERY here, unlike the batch `replayDeliveries`
   * beside it, which reads it from a body. The server binds
   * `Query<TenantQuery>` on this route and `Json<ReplayRequest>` on that one, so
   * the two neighbours genuinely differ — and a body sent here is ignored, which
   * means a platform token would be told it must name a tenant while looking at
   * code that names one.
   *
   * The id may come from either list. An operator reading the dead-letter list
   * should not have to know it is a different table from the delivery log, so
   * the server tries the queue first and then the dead letters.
   */
  async replayDelivery(id: string, scope: TenantScope = {}): Promise<number> {
    const w = await this.request<wire.WebhookReplayOneResult>(
      "POST",
      `/api/v1/webhook/deliveries/${segment(id)}/replay`,
      { query: { tenant_id: scope.tenantId } },
    );
    return w.requeued;
  }

  /**
   * Events this tenant was never told about.
   *
   * Each carries the `body` that could not be delivered, so the payload is
   * recoverable from here. `outstanding` is the number worth alerting on.
   */
  async listDeadLetters(options: ListDeadLettersOptions = {}): Promise<DeadLetterPage> {
    const w = await this.request<wire.WebhookDeadLetterList>("GET", "/api/v1/webhook/dead-letters", {
      query: {
        tenant_id: options.tenantId,
        webhook_id: options.webhookId,
        include_acknowledged: options.includeAcknowledged,
        limit: options.limit,
      },
    });
    return {
      outstanding: w.outstanding,
      outstandingByEndpoint: w.outstanding_by_endpoint ?? {},
      retentionDays: w.retention_days,
      deadLetters: (w.dead_letters ?? []).map(toDeadLetter),
    };
  }

  /**
   * Mark dead letters as dealt with.
   *
   * Acknowledging keeps the row and its body; `discardDeadLetters` removes it.
   * The two are separate precisely because the body is the only remaining copy
   * of an event the tenant never received.
   */
  async acknowledgeDeadLetters(input: AcknowledgeDeadLettersInput = {}): Promise<number> {
    const w = await this.request<wire.WebhookAcknowledgeResult>(
      "POST",
      "/api/v1/webhook/dead-letters/acknowledge",
      { body: { tenant_id: input.tenantId, ids: input.ids, webhook_id: input.webhookId } },
    );
    return w.acknowledged;
  }

  /**
   * Delete the named dead letters.
   *
   * `ids` is required: there is no "discard everything", because deletion is
   * not a filter. Compare `discarded` with `requested` — a gap means some ids
   * named nothing.
   */
  async discardDeadLetters(input: DiscardDeadLettersInput): Promise<DiscardResult> {
    const w = await this.request<wire.WebhookDiscardResult>("POST", "/api/v1/webhook/dead-letters/discard", {
      body: { tenant_id: input.tenantId, ids: input.ids },
    });
    return { discarded: w.discarded, requested: w.requested };
  }

  /** Delete one dead letter. */
  async discardDeadLetter(id: string, scope: TenantScope = {}): Promise<void> {
    await this.request<wire.WebhookDiscardOneResult>(
      "DELETE",
      `/api/v1/webhook/dead-letters/${segment(id)}`,
      { query: { tenant_id: scope.tenantId } },
    );
  }

  // --- resource servers and scopes ----------------------------------------

  /** The tenant's audiences and their scopes. */
  async listResources(scope: TenantScope = {}): Promise<ResourceServerList> {
    const w = await this.request<wire.ResourceServerList>("GET", "/api/v1/resources", {
      query: { tenant_id: scope.tenantId },
    });
    return {
      resources: (w.resources ?? []).map(toResourceServer),
      tenantScopes: (w.tenant_scopes ?? []).map(toScopeDefinition),
    };
  }

  /** Register an audience a token can be minted for. */
  async createResource(input: CreateResourceInput): Promise<ResourceServer> {
    const w = await this.request<wire.ResourceServer>("POST", "/api/v1/resources", {
      body: {
        tenant_id: input.tenantId,
        identifier: input.identifier,
        display_name: input.displayName,
      },
    });
    return toResourceServer(w);
  }

  /** Remove an audience. */
  async deleteResource(id: string, scope: TenantScope = {}): Promise<void> {
    await this.request<void>("DELETE", `/api/v1/resources/${segment(id)}`, {
      query: { tenant_id: scope.tenantId },
    });
  }

  /**
   * Give a scope name a meaning.
   *
   * The description is required because it is what a user reads on the consent
   * screen; a scope with no description consents them to a bare string.
   */
  async defineScope(input: DefineScopeInput): Promise<ScopeDefinition> {
    const w = await this.request<wire.ScopeDefinition>("POST", "/api/v1/scopes", {
      body: {
        tenant_id: input.tenantId,
        resource_server_id: input.resourceServerId,
        name: input.name,
        description: input.description,
      },
    });
    return toScopeDefinition(w);
  }

  /** Remove a scope definition. */
  async deleteScope(id: string, scope: TenantScope = {}): Promise<void> {
    await this.request<void>("DELETE", `/api/v1/scopes/${segment(id)}`, {
      query: { tenant_id: scope.tenantId },
    });
  }

  // --- mail ---------------------------------------------------------------

  /** Where this tenant's mail goes out from. */
  async getMailSettings(scope: TenantScope = {}): Promise<MailSettings> {
    const w = await this.request<wire.MailSettings>("GET", "/api/v1/mail", {
      query: { tenant_id: scope.tenantId },
    });
    return toMailSettings(w);
  }

  /** Set or replace the relay. Omit `password` to keep the stored one. */
  async setMailSettings(input: SetMailSettingsInput): Promise<MailSettings> {
    const w = await this.request<wire.MailSettings>("PUT", "/api/v1/mail", {
      body: {
        tenant_id: input.tenantId,
        host: input.host,
        port: input.port,
        username: input.username,
        password: input.password,
        from_address: input.fromAddress,
        from_name: input.fromName,
        encryption: input.encryption,
        enabled: input.enabled,
      },
    });
    return toMailSettings(w);
  }

  /** Fall back to the platform relay. */
  async clearMailSettings(scope: TenantScope = {}): Promise<void> {
    await this.request<void>("DELETE", "/api/v1/mail", { query: { tenant_id: scope.tenantId } });
  }

  /**
   * Send a test message through the stored configuration.
   *
   * Check `sent` on the result, not the status code: a relay that refuses the
   * message answers 200 with `sent: false` and an `error`, because that is a
   * fact about the configuration rather than a failure of this call.
   */
  async sendTestMail(input: TenantScope & { to: string }): Promise<MailTestResult> {
    const w = await this.request<wire.MailTestResult>("POST", "/api/v1/mail/test", {
      body: { tenant_id: input.tenantId, to: input.to },
    });
    return { sent: w.sent, to: w.to, via: w.via, error: w.error };
  }

  // --- everything else ----------------------------------------------------

  /** The operational numbers for the deployment. Requires the platform token. */
  async getFleetHealth(): Promise<FleetHealth> {
    const w = await this.request<wire.FleetHealth>("GET", "/api/v1/fleet-health");
    return {
      webhookQueueDepth: w.webhook_queue_depth,
      deadLettersOutstanding: w.dead_letters_outstanding,
      auditExportLagSeals: w.audit_export_lag_seals,
      auditUnsealedRows: w.audit_unsealed_rows,
    };
  }

  /**
   * Every version of every plan, drafts included. **Platform token only.**
   * A published version never changes, and a tenant keeps the version it
   * bought until it changes plan.
   */
  async listPlanVersions(): Promise<PlanVersionList> {
    const w = await this.request<wire.PlanVersionList>("GET", "/api/v1/plan-versions");
    return {
      versions: (w.versions ?? []).map((v) => planVersionFromWire(v)),
      billingEnabled: w.billing_enabled,
    };
  }

  /** Start a draft of `plan`'s next version, a copy of its current one. **Platform token only.** */
  async createPlanDraft(plan: Plan): Promise<PlanVersion> {
    const w = await this.request<wire.PlanVersion>("POST", "/api/v1/plan-versions", { body: { plan } });
    return planVersionFromWire(w);
  }

  /** Replace a draft's fields — all of them. **Platform token only.** */
  async updatePlanDraft(id: number, fields: PlanVersionFields): Promise<PlanVersion> {
    const w = await this.request<wire.PlanVersion>("PUT", `/api/v1/plan-versions/${segment(String(id))}`, {
      body: { ...planVersionFieldsToWire(fields) },
    });
    return planVersionFromWire(w);
  }

  /** Throw a draft away. **Platform token only.** */
  async discardPlanDraft(id: number): Promise<void> {
    await this.request<void>("DELETE", `/api/v1/plan-versions/${segment(String(id))}`);
  }

  /**
   * Publish a draft: new sign-ups and plan changes get it from now on, and
   * nobody holding an earlier version is moved. Where billing is set up, its
   * prices are made at the provider first. **Platform token only.**
   */
  async publishPlanVersion(id: number): Promise<PlanVersion> {
    const w = await this.request<wire.PlanVersion>(
      "POST",
      `/api/v1/plan-versions/${segment(String(id))}/publish`,
    );
    return planVersionFromWire(w);
  }

  /**
   * Move every workspace on another Free version onto this published Free
   * version, and say how many moved: the one exception to "your plan does not
   * change under you", for Free only. **Platform token only.**
   */
  async moveFreeWorkspaces(id: number): Promise<PlanMoveResult> {
    return this.request<wire.PlanMoveResult>(
      "POST",
      `/api/v1/plan-versions/${segment(String(id))}/move-free-workspaces`,
    );
  }

  /** Set or clear the monthly-active-user soft cap. `null` removes it. */
  async setSoftCap(input: SetSoftCapInput): Promise<SoftCapSet> {
    const w = await this.request<wire.SoftCapSet>("PUT", "/api/v1/usage/cap", {
      body: { tenant_id: input.tenantId, soft_cap: input.softCap },
    });
    return { tenantId: w.tenant_id, softCap: w.soft_cap };
  }

  /** Remove a tenant's upstream login connection. */
  async deleteConnection(provider: string, scope: TenantScope = {}): Promise<void> {
    await this.request<void>("DELETE", `/api/v1/connections/${segment(provider)}`, {
      query: { tenant_id: scope.tenantId },
    });
  }

  /**
   * Everything a departing tenant may take with them.
   *
   * Read `excluded` as part of the answer rather than as a footnote: it names
   * every table deliberately left out and why, so "this is all of it" is a
   * claim the response itself supports. `truncated` names tables that hit the
   * per-table row cap.
   */
  async exportTenant(tenantId: string): Promise<TenantExport> {
    const w = await this.request<wire.TenantExport>(
      "GET",
      `/api/v1/tenants/${segment(tenantId)}/export`,
    );
    return {
      tenant: w.tenant,
      tables: w.tables,
      truncated: w.truncated ?? [],
      excluded: w.excluded ?? [],
    };
  }

  /**
   * Download the filtered audit trail as NDJSON.
   *
   * Returns the raw body rather than parsed events: it is one JSON object per
   * line and can be large, so parsing it is the caller's call. Every filter
   * `listAudit` takes applies here.
   */
  async exportAudit(options: ListAuditOptions = {}): Promise<string> {
    const url = new URL("/api/v1/audit/export", this.baseUrl);
    for (const [k, v] of Object.entries(auditQuery(options))) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res: Response;
    let text: string;
    try {
      res = await this.fetchFn(url.toString(), {
        method: "GET",
        headers: { authorization: `Bearer ${this.token}` },
        signal: controller.signal,
      });
      // The body under the same deadline as the headers (see
      // `request`). A large export may need a larger `timeoutMs`.
      text = await res.text();
    } catch (e) {
      throw new ManagementError(`request to /api/v1/audit/export failed: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      const parsed = safeJsonParse(text) as { error?: string; message?: string; detail?: string } | null;
      throw new ManagementError(
        parsed?.message ?? `audit export failed with ${res.status}`,
        parsed?.error,
        res.status,
        parsed?.detail,
      );
    }
    return text;
  }

  // --- internals ---------------------------------------------------------

  private async request<T>(
    method: string,
    path: string,
    // `boolean` because the API has boolean query parameters —
    // `include_acknowledged` on the dead-letter listing is one. `String(v)`
    // below already renders them correctly; the type was simply narrower than
    // the endpoints it serves.
    opts: { body?: Record<string, unknown>; query?: Record<string, string | number | boolean | undefined> } = {},
  ): Promise<T> {
    const url = new URL(`${this.baseUrl}${path}`);
    if (opts.query) {
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined) url.searchParams.set(k, String(v));
      }
    }

    const headers: Record<string, string> = { authorization: `Bearer ${this.token}` };
    let payload: string | undefined;
    if (opts.body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(pruneUndefined(opts.body));
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res: Response;
    let text: string;
    try {
      res = await this.fetchFn(url.toString(), { method, headers, body: payload, signal: controller.signal });
      // Read before the timer is cleared: it was
      // cleared on the headers, and a server that then stalled the body held
      // the caller with no deadline at all.
      text = await res.text();
    } catch (e) {
      throw new ManagementError(`request to ${path} failed: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    const data = text ? safeJsonParse(text) : undefined;
    if (!res.ok) {
      const err = (data ?? {}) as { error?: string; message?: string; detail?: string };
      throw new ManagementError(
        err.message ?? `Management API returned HTTP ${res.status}`,
        err.error,
        res.status,
        err.detail,
      );
    }
    return data as T;
  }
}

/**
 * One caller-supplied id as one path segment, or a `ManagementError` before
 * anything is sent.
 *
 * `encodeURIComponent` leaves `.` alone, and `new URL` then resolves a segment
 * of `.` or `..` away, so such an id addressed another endpoint with the
 * caller's token: `replayDelivery(".")` posted to the bulk replay, and
 * `getTenant("..")` read `/api/v1/`. An empty id drops the segment the same
 * way. None of the three is an id the API issues.
 */
function segment(id: string): string {
  if (id === "" || id === "." || id === "..") {
    throw new ManagementError(`${JSON.stringify(id)} is not a usable id: in a URL path it would address another endpoint`);
  }
  return encodeURIComponent(id);
}

// --- wire types + mappers --------------------------------------------------

// The wire shapes are no longer written here. They are generated from
// `spec/openapi.json` into `generated/wire.ts`, one per schema, and aliased
// below under the names this file already used.
//
// What made that safe is not the generator. It is that the spec is now held to
// a real server body — Proteles' server tests validate seventeen operations
// against it, covering every schema aliased here. Generating from an unchecked
// document would have laundered hand-written prose into a compiler-enforced
// type, which is the objection that kept these hand-written.
//
// The MAPPERS below stay hand-written. They are where the camelCase API is
// decided, and that is a deliberate interface rather than a transcript.
type WireBranding = wire.TenantBranding;

type WireApp = wire.AppsAppSummary;
type WireConnection = wire.ConnectionsConnection;
type WireUsage = wire.UsageReport;
type WireAuditEvent = wire.AuditEventRecord;

function toBranding(w: WireBranding | null | undefined): Branding | undefined {
  if (!w) return undefined;
  const b: Branding = {};
  if (w.app_name != null) b.appName = w.app_name;
  if (w.logo_uri != null) b.logoUri = w.logo_uri;
  if (w.primary_color != null) b.primaryColor = w.primary_color;
  return b;
}

function toWireBranding(b: Branding): WireBranding {
  return { app_name: b.appName, logo_uri: b.logoUri, primary_color: b.primaryColor };
}

function toTenantSummary(w: wire.TenantSummary): TenantSummary {
  return { id: w.id, slug: w.slug, status: w.status };
}

/**
 * The detail body, every field present.
 *
 * This function used to be one mapper for both shapes, guarding each field with
 * `!== undefined` so a summary "stayed a summary". The guards were right about
 * the wire and wrong about the type they produced: what came out was a `Tenant`
 * whose absent fields were indistinguishable from fields the server had set to
 * nothing. Two wire types and two mappers make the distinction structural, so
 * there is nothing left to guard.
 *
 * `branding` is not optional on the wire either — the server sends `{}` when
 * nothing is configured, because every field inside it is
 * `skip_serializing_if` and a read failure falls back to the default.
 */
function toTenant(w: wire.TenantDetail): Tenant {
  return {
    id: w.id,
    slug: w.slug,
    status: w.status,
    issuer: w.issuer,
    branding: toBranding(w.branding) ?? {},
    mfaPolicy: w.mfa_policy,
    mfaGraceDays: w.mfa_grace_days,
    mfaRequiredSince: w.mfa_required_since,
    mfaGraceUntil: w.mfa_grace_until,
    mfaSelfRecoveryHours: w.mfa_self_recovery_hours,
    mfaEmailFactorEnabled: w.mfa_email_factor_enabled,
    accountRecoveryCodesEnabled: w.account_recovery_codes_enabled,
    passwordSignupEnabled: w.password_signup_enabled,
    socialSignupEnabled: w.social_signup_enabled,
    passkeyAttestation: w.passkey_attestation,
    attestationCaCount: w.attestation_ca_count,
    maxMembers: w.max_members,
    memberCount: w.member_count,
    // Copied only when present: a server that predates `owner_count` sends none.
    ...(w.owner_count !== undefined ? { ownerCount: w.owner_count } : {}),
    plan: w.plan,
    planSubscribed: w.plan_subscribed,
    planOverride: w.plan_override,
    seatCap: w.seat_cap,
    // Copied only when present: a server from before the switch enforced
    // every plan, and says nothing.
    ...(w.plans_enforced !== undefined ? { plansEnforced: w.plans_enforced } : {}),
    // Likewise from a server before 2026-10-03, which did not say why.
    ...(w.plan_binding !== undefined ? { planBinding: w.plan_binding } : {}),
  };
}

function toApp(w: WireApp): App {
  return {
    clientId: w.client_id,
    clientName: w.client_name,
    clientType: w.client_type,
    grantTypes: w.grant_types,
    redirectUris: w.redirect_uris,
    // Listed since 2026-10-07; an older server's list does not say.
    postLogoutRedirectUris: w.post_logout_redirect_uris ?? [],
    firstParty: w.first_party,
    createdAt: w.created_at,
    isActive: w.is_active,
    selfRegistered: w.self_registered,
    appIdentity: w.app_identity == null ? null : fromWireAppIdentity(w.app_identity),
    // Listed since back-channel logout's step 3; an older server's list does not say.
    backchannelLogoutUri: w.backchannel_logout_uri ?? null,
    backchannelLogoutSessionRequired: w.backchannel_logout_session_required ?? false,
    // Listed by servers since invitations could name an app; an older server's list does not say.
    initiateLoginUri: w.initiate_login_uri ?? null,
  };
}

function toWireAppIdentity(i: AppIdentity): wire.AppIdentity {
  return {
    android: i.android && { package_name: i.android.packageName, sha256_cert_fingerprints: i.android.sha256CertFingerprints },
    ios: i.ios && { app_id: i.ios.appId },
  };
}

function fromWireAppIdentity(w: wire.AppIdentity): AppIdentity {
  return {
    ...(w.android ? { android: { packageName: w.android.package_name, sha256CertFingerprints: w.android.sha256_cert_fingerprints } } : {}),
    ...(w.ios ? { ios: { appId: w.ios.app_id } } : {}),
  };
}

function toConnection(w: WireConnection): Connection {
  return {
    provider: w.provider,
    clientId: w.client_id,
    redirectUri: w.redirect_uri,
    enabled: w.enabled,
    inUse: w.in_use ?? w.enabled,
  };
}

/**
 * Joins a repeatable filter into the comma-separated form the API takes.
 *
 * An empty array becomes `undefined`, not `""`. The server reads an empty
 * filter as "no constraint" — never "match nothing", because a cleared checkbox
 * list that hid a full trail reads as data loss — so both spellings return the
 * same rows. Sending nothing is still right: a request should carry what the
 * caller asked for and no more.
 *
 * Values are trimmed and blanks dropped, so `["login.failure", ""]` cannot
 * produce a trailing comma the server would then parse as an empty type.
 */
function commaList(value: string | string[] | undefined): string | undefined {
  if (value === undefined) return undefined;
  const parts = (Array.isArray(value) ? value : value.split(","))
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  return parts.length ? parts.join(",") : undefined;
}

function toAuditEvent(w: WireAuditEvent): AuditEvent {
  return {
    eventType: w.event_type,
    severity: w.severity,
    clientId: w.client_id ?? null,
    actorUserId: w.actor_user_id ?? null,
    causedByUserId: w.caused_by_user_id ?? null,
    ip: w.ip ?? null,
    detail: w.detail ?? null,
    // `?? null` normalises an absent field to the documented `null`. The bytes
    // themselves are passed through untouched: the audit seal is computed over
    // exactly these, so parsing and re-serialising here would hand callers a
    // string that no longer verifies.
    detailJson: w.detail_json ?? null,
    leafVersion: w.leaf_version,
    createdAt: w.created_at,
  };
}

function pruneUndefined(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) out[k] = v;
  }
  return out;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

type WireDomain = wire.TenantDomainClaim;

function toDomain(w: WireDomain): TenantDomain {
  return {
    domain: w.domain,
    verified: w.verified,
    // `verified_at` is genuinely nullable and the wire type says so, so this
    // stays a real coalesce. `challenge` is not: it was `?? null` here on the
    // strength of a hand-written wire type that guessed, and the guess is what
    // put `| null` into the public type nobody could take out.
    verifiedAt: w.verified_at,
    createdAt: w.created_at,
    challenge: w.challenge,
  };
}

function toSamlServiceProvider(w: wire.SamlServiceProvider): SamlServiceProvider {
  return {
    id: w.id,
    name: w.name,
    spEntityId: w.sp_entity_id,
    acsUrls: w.acs_urls,
    defaultAcsUrl: w.default_acs_url,
    requestSigningCertificatePem: w.request_signing_certificate_pem ?? null,
    nameIdFormat: w.name_id_format,
    enrolOnFirstSignIn: w.enrol_on_first_sign_in,
    sloUrl: w.slo_url ?? null,
    singleLogout: w.single_logout,
    openToEveryTenantUser: w.open_to_every_tenant_user,
    enabled: w.enabled,
    createdAt: w.created_at,
    updatedAt: w.updated_at,
  };
}

function toSamlServiceProviderAssignment(
  w: wire.SamlServiceProviderAssignment,
): SamlServiceProviderAssignment {
  return { userId: w.user_id, createdAt: w.created_at };
}

function toSamlIdpKey(w: wire.SamlIdpKey): SamlIdpKey {
  return {
    kid: w.kid,
    state: w.state,
    certificatePem: w.certificate_pem,
    certificateSha256: w.certificate_sha256,
    notAfter: w.not_after,
    signingRefusedFrom: w.signing_refused_from,
    rotationWarningFrom: w.rotation_warning_from,
    published: w.published,
    createdAt: w.created_at,
    signingSince: w.signing_since ?? null,
    retiredAt: w.retired_at ?? null,
  };
}

function toSamlConnection(w: wire.SamlConnection): SamlConnection {
  return {
    id: w.id,
    name: w.name,
    idpEntityId: w.idp_entity_id,
    idpSsoUrl: w.idp_sso_url,
    certificatePem: w.certificate_pem,
    certificateNextPem: w.certificate_next_pem ?? null,
    spEntityId: w.sp_entity_id,
    acsUrl: w.acs_url,
    attrUsername: w.attr_username ?? null,
    attrEmail: w.attr_email ?? null,
    maxAssertionLifetimeSeconds: w.max_assertion_lifetime_seconds,
    allowUnsolicited: w.allow_unsolicited,
    relayStateHosts: w.relay_state_hosts,
    enabled: w.enabled,
    createdAt: w.created_at,
    updatedAt: w.updated_at,
  };
}

function toWebhookEndpoint(w: wire.WebhookEndpoint): WebhookEndpoint {
  return {
    id: w.id,
    name: w.name,
    url: w.url,
    events: w.events,
    enabled: w.enabled,
    maxDeliveriesPerMinute: w.max_deliveries_per_minute,
    disableAfterDeadLetters: w.disable_after_dead_letters,
    disabledReason: w.disabled_reason,
    disabledAt: w.disabled_at,
    disabledBy: w.disabled_by,
  };
}

function toWrittenWebhook(w: wire.WebhookEndpointWriteResult): WrittenWebhook {
  return {
    id: w.id,
    name: w.name,
    url: w.url,
    events: w.events,
    enabled: w.enabled,
    maxDeliveriesPerMinute: w.max_deliveries_per_minute,
    disableAfterDeadLetters: w.disable_after_dead_letters,
  };
}

function toDelivery(w: wire.WebhookDelivery): WebhookDelivery {
  return {
    id: w.id,
    webhookId: w.webhook_id,
    webhookName: w.webhook_name,
    eventId: w.event_id,
    eventType: w.event_type,
    status: w.status,
    attempts: w.attempts,
    nextAttemptAt: w.next_attempt_at,
    lastError: w.last_error,
    lastStatus: w.last_status,
    createdAt: w.created_at,
    completedAt: w.completed_at,
  };
}

function toDeadLetter(w: wire.WebhookDeadLetter): WebhookDeadLetter {
  return {
    id: w.id,
    webhookId: w.webhook_id,
    endpointName: w.endpoint_name,
    endpointUrl: w.endpoint_url,
    eventId: w.event_id,
    eventType: w.event_type,
    body: w.body,
    attempts: w.attempts,
    lastError: w.last_error,
    lastStatus: w.last_status,
    firstQueuedAt: w.first_queued_at,
    diedAt: w.died_at,
    revivedAt: w.revived_at,
    revivals: w.revivals,
    acknowledgedAt: w.acknowledged_at,
    acknowledgedBy: w.acknowledged_by,
  };
}

function toAppCheckFinding(w: wire.AppCheckFinding): AppCheckFinding {
  return { check: w.check, level: w.level, message: w.message };
}

function toScopeDefinition(w: wire.ScopeDefinition): ScopeDefinition {
  return {
    id: w.id,
    resourceServerId: w.resource_server_id,
    name: w.name,
    description: w.description,
    createdAt: w.created_at,
  };
}

function toResourceServer(w: wire.ResourceServer): ResourceServer {
  return {
    id: w.id,
    identifier: w.identifier,
    displayName: w.display_name,
    createdAt: w.created_at,
    updatedAt: w.updated_at,
    ...(w.scopes === undefined ? {} : { scopes: w.scopes.map(toScopeDefinition) }),
  };
}

function toMailSettings(w: wire.MailSettings): MailSettings {
  return {
    configured: w.configured,
    using: w.using,
    host: w.host,
    port: w.port,
    username: w.username,
    passwordSet: w.password_set,
    fromAddress: w.from_address,
    fromName: w.from_name,
    encryption: w.encryption,
    enabled: w.enabled,
    lastSuccessAt: w.last_success_at,
    lastError: w.last_error,
    lastErrorAt: w.last_error_at,
    updatedAt: w.updated_at,
  };
}

/**
 * The query `/api/v1/audit` and `/api/v1/audit/export` both take.
 *
 * One function rather than two copies, because the export endpoint accepts
 * every filter the listing does and a client that supported a filter on one and
 * not the other would be worse than one that supported it on neither: a caller
 * would export a wider trail than they asked for and not be told.
 *
 * `commaList` returns undefined for an empty list, and that is the load-bearing
 * part: the server reads an empty `event_type=` as no constraint, so sending
 * one would be harmless — but sending a parameter the caller did not ask for is
 * how a client and a server come to disagree about what was requested.
 */
function auditQuery(options: ListAuditOptions): Record<string, string | number | boolean | undefined> {
  return {
    tenant_id: options.tenantId,
    limit: options.limit,
    event_type: commaList(options.eventType),
    severity: commaList(options.severity),
    actor_user_id: options.actorUserId,
    caused_by_user_id: options.causedByUserId,
    client_id: options.clientId,
    since: options.since,
    until: options.until,
    cursor: options.cursor,
  };
}

/** The one mapping of the SMS factor's wire shape, shared by its read and write. */
function smsFactorFromWire(w: wire.SmsFactor): SmsFactor {
  return {
    tenantId: w.tenant_id,
    smsFactorEnabled: w.sms_factor_enabled,
    plan: w.plan,
    planIncludesSms: w.plan_includes_sms,
    offered: w.offered,
    deliverable: w.deliverable,
    dailyLimit: w.daily_limit,
    sentToday: w.sent_today,
    sentThisMonth: w.sent_this_month,
    acceptedThisMonth: w.accepted_this_month,
  };
}

function planVersionFromWire(w: wire.PlanVersion): PlanVersion {
  return {
    includedMru: w.included_mru,
    includedSeats: w.included_seats,
    maxApps: w.max_apps,
    logRetentionDays: w.log_retention_days,
    sessionChoiceDays: w.session_choice_days,
    sessionMaxDays: w.session_max_days,
    sms: w.sms,
    enhancedSupport: w.enhanced_support,
    monthlyCents: w.monthly_cents,
    annualCents: w.annual_cents,
    mruOverageMicros: w.mru_overage_micros,
    extraSeatMonthlyCents: w.extra_seat_monthly_cents,
    extraSeatAnnualCents: w.extra_seat_annual_cents,
    tagline: w.tagline,
    features: w.features,
    maxSocialConnections: w.max_social_connections,
    saml: w.saml,
    machineIdentity: w.machine_identity,
    id: w.id,
    plan: w.plan,
    name: w.name,
    version: w.version,
    status: w.status,
    current: w.current,
    tenants: w.tenants,
    publishedAt: w.published_at,
    publishedBy: w.published_by,
    prices: (w.prices ?? []).map((p) => ({
      priceRef: p.price_ref,
      kind: p.kind,
      interval: p.interval,
      sold: p.sold,
    })),
  };
}

function planVersionFieldsToWire(f: PlanVersionFields): wire.PlanVersionFields {
  return {
    included_mru: f.includedMru,
    included_seats: f.includedSeats,
    max_apps: f.maxApps,
    log_retention_days: f.logRetentionDays,
    session_choice_days: f.sessionChoiceDays,
    session_max_days: f.sessionMaxDays,
    sms: f.sms,
    enhanced_support: f.enhancedSupport,
    monthly_cents: f.monthlyCents,
    annual_cents: f.annualCents,
    mru_overage_micros: f.mruOverageMicros,
    extra_seat_monthly_cents: f.extraSeatMonthlyCents,
    extra_seat_annual_cents: f.extraSeatAnnualCents,
    tagline: f.tagline,
    features: f.features,
    max_social_connections: f.maxSocialConnections,
    saml: f.saml,
    machine_identity: f.machineIdentity,
  };
}
