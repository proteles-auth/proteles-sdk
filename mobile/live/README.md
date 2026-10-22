# Live server for the native SDKs

`run-live.sh` gives the native SDKs' live suites a real Proteles server, and
a test the values it needs as environment variables. This is the live
verification in `docs/mobile-SDKs.md` §10.8. `curl-check.sh` runs the SDK's
requests against it with curl, so the harness is proven without any SDK code.

The server is not part of this repository, so there are two ways to give it
one:

- **Binaries** from the Proteles server repository (private): `run-live.sh`
  starts them on loopback and seeds the server the way Proteles' integration
  tests do. This is the mode below.
- **A server already running and seeded**, such as a dev image: set
  `PROTELES_LIVE_ISSUER` and the other values in [What a test
  gets](#what-a-test-gets) yourself, and `run-live.sh -- CMD` starts nothing.
  It checks that the server's discovery document names exactly that issuer,
  then runs `CMD` against it. See [Against a server you already
  run](#against-a-server-you-already-run).

## Run it

```sh
# Start, run one command with the variables set, stop. Exits with the command's status.
PROTELES_LIVE_BIN_DIR=/path/to/prebuilt/bins \
  mobile/live/run-live.sh -- mobile/live/curl-check.sh

# Or leave the server running while you work:
eval "$(mobile/live/run-live.sh start)"   # progress goes to stderr, only the exports go to stdout
mobile/live/run-live.sh env               # print the exports again
mobile/live/run-live.sh stop
```

Nothing is built. `PROTELES_LIVE_BIN_DIR` must hold `oauth-server` and
`admin-cli` built from the server repository; there is no default. The script needs
`psql`, `curl`, `openssl`, `lsof` and `perl`, and an existing Postgres
(default `localhost:5432`, user and password `oauth`). Each start drops and
recreates the database `proteles_sdk_live_<port>`, one per port, so two runs
at once — the iOS and the Android suites side by side — cannot drop each
other's. Databases of that name are the only ones it touches. It does not drop
the database on stop, so you can inspect it afterwards.

The server binds `127.0.0.1` on the first free port from 18480, within
18400–18499. Its log and the state file go to `PROTELES_LIVE_DIR`, which
defaults to `${TMPDIR:-/tmp}/proteles-sdk-live`; a start refuses while a
server it recorded there is still running, so give a second concurrent run its
own `PROTELES_LIVE_DIR`. The file header of
`run-live.sh` lists the other settings you can change, including a shorter
`ACCESS_TOKEN_TTL_SECONDS` for testing refresh at half-life.

## What a test gets

| Variable | Value |
|---|---|
| `PROTELES_LIVE_ISSUER` | `http://localhost:<port>`. Use it exactly (see below). |
| `PROTELES_LIVE_CLIENT_ID` | `proteles-live` |
| `PROTELES_LIVE_REDIRECT_URI` | `https://live.proteles.test/callback` |
| `PROTELES_LIVE_USERNAME` / `PROTELES_LIVE_PASSWORD` | a person in the default tenant with no second factor |
| `PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI` | `https://live.proteles.test/logout`, registered for end-session |
| `PROTELES_LIVE_MANAGEMENT_TOKEN` | the platform management token. Only `curl-check.sh` uses it. |

The client is seeded with `admin-cli seed-client --type public`. It is public
(`token_endpoint_auth_method` `none`, no secret), uses the
`authorization_code` and `refresh_token` grants, requires PKCE, and is
first-party, so no consent screen comes between the login and the redirect.
The client gets a refresh token because it registered the `refresh_token`
grant. No `offline_access` scope is needed (§2.3).

**The issuer is the Host you reached.** The server builds the issuer from the
request's `Host` header. The same server reached at `127.0.0.1:<port>` says
its issuer is `http://127.0.0.1:<port>`, and an SDK configured with the
`localhost` issuer correctly refuses that. Always connect through
`PROTELES_LIVE_ISSUER`:

- **iOS Simulator:** the simulator shares the Mac's loopback, so `localhost`
  works as it is.
- **Android emulator:** run `adb reverse tcp:<port> tcp:<port>` and use
  `localhost`. `10.0.2.2` is a different host: its issuer would not match,
  and it is not one of the server's base hosts, so the server answers 404.

## Against a server you already run

```sh
export PROTELES_LIVE_ISSUER=http://localhost:8080   # exactly what its discovery document says
export PROTELES_LIVE_CLIENT_ID=… PROTELES_LIVE_REDIRECT_URI=… PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI=…
export PROTELES_LIVE_USERNAME=… PROTELES_LIVE_PASSWORD=…
mobile/live/run-live.sh -- mobile/live/curl-check.sh
```

All six must be set (`PROTELES_LIVE_MANAGEMENT_TOKEN` is optional: only
`curl-check.sh` uses it). Nothing is seeded, so the server must already hold
what `run-live.sh` would have seeded: a public client (no secret,
`token_endpoint_auth_method` `none`) with that redirect URI and post-logout
redirect URI registered, the `authorization_code` and `refresh_token` grants,
PKCE required, and first-party, so no consent screen comes between the login
and the redirect; and that user in the issuer's tenant, with no second factor.
The SDK suites do sign-ins, refreshes and revocations against it, so use a
server whose data you can throw away.

## Driving the browser hop in a test

A test that stands in for the browser (instead of `ASWebAuthenticationSession`
or a Custom Tab) repeats what `curl-check.sh` steps 2–4 do:

1. `GET` the authorization URL. The server answers `303` to
   `/login?redirect=…`.
2. `GET` that login page. It sets the `__Host-login_csrf` cookie, and its
   form has hidden `redirect` and `csrf` fields.
3. `POST /login` with `username`, `password`, `redirect` and `csrf` as a form.
   The server answers `303` back to the authorization request and sets
   `__Host-oauth_session`.
4. `GET` that URL. The server answers `303` to
   `https://live.proteles.test/callback?iss=…&code=…&state=…`. Do not follow this
   redirect. Hand its URL to the SDK as the callback.

The cookies are `__Host-` and `Secure` even over plain http, and curl's cookie
jar will not send them back, so keep them yourself, as both scripts do. A real
Chromium browser treats `http://localhost` as secure. Whether WebKit in the
iOS Simulator keeps `Secure` cookies from `http://localhost` has not been
tested here.

Rate limits are per network. The login allows 30 per minute (raised from 10,
as in Proteles' integration tests) and the token endpoint allows 60 per
minute. A suite that signs in more often than that will get `429` responses.

## curl-check.sh

`curl-check.sh` runs these steps in order: discovery (the issuer must match
byte for byte, and `authorization_response_iss_parameter_supported` must be
set), a PKCE authorization request, the login form, the callback (`code`,
`state`, `iss`), the code exchange (with ID-token checks: RS256 signature,
`iss`, `aud`, `nonce`, `at_hash`), a refresh with rotation, and revocation.
After those it checks the §2 claims these requests can observe.

Each line of output is one of these:

- `ok`: the check passed.
- `FAIL`: the harness is broken. The script exits 1.
- `DIFF`: the server disagrees with `docs/mobile-SDKs.md`. The script prints
  it but does not fail.

`CURL_CHECK_SLOW=1` adds §2.3's 60-second case, which takes about a minute.
