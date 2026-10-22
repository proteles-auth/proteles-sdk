#!/usr/bin/env bash
# A real Proteles server for the native SDKs' live tests (docs/mobile-SDKs.md §10.8).
#
#   run-live.sh [start]        (re)create the database, start the server, seed it,
#                              print `export PROTELES_LIVE_…` lines on stdout, and
#                              leave the server running
#   run-live.sh env            print the exports again for the running server
#   run-live.sh stop           stop the server this script started
#   run-live.sh -- CMD [ARG…]  start, run CMD with the exports set, stop; exits
#                              with CMD's status
#
# Only the exports go to stdout, so `eval "$(run-live.sh)"` works; progress and
# errors go to stderr.
#
# **The server is not in this repository.** Two ways to give it one:
#
# 1. Binaries: PROTELES_LIVE_BIN_DIR names a directory holding `oauth-server`
#    and `admin-cli` built from the Proteles server repository (private), and
#    this script starts, seeds and stops them against a local Postgres. Nothing
#    is built. Configuration and seeding follow Proteles' integration tests,
#    which is where they are proven against the server.
# 2. A server already running and seeded (a dev image, say): set
#    PROTELES_LIVE_ISSUER and the other PROTELES_LIVE_* values (README.md, "What
#    a test gets", lists them and what the server must hold), and
#    `run-live.sh -- CMD` starts nothing: it checks that the server's discovery
#    document names that issuer, then runs CMD against it. `start`, `env` and
#    `stop` only ever act on a server this script started.
#
# Knobs (all optional, except that mode 1 needs PROTELES_LIVE_BIN_DIR):
#   PROTELES_LIVE_BIN_DIR   holds oauth-server and admin-cli. No default: this
#                           repository builds no server.
#   PROTELES_LIVE_DIR       logs and the state file (default ${TMPDIR:-/tmp}/proteles-sdk-live)
#   PROTELES_LIVE_PORT      18400–18499 (default: the first free one from 18480)
#   PROTELES_LIVE_PG_HOST / _PG_PORT / _PG_USER / _PG_PASSWORD
#                           an existing Postgres (default localhost 5432 oauth/oauth).
#                           Only databases named `proteles_sdk_live_<port>` are ever
#                           touched: this run's is dropped and recreated on start.
#   PROTELES_LIVE_ACCESS_TOKEN_TTL_SECONDS
#                           default 900, the server's own; shorten it to watch a
#                           half-life refresh without waiting 7m30s
#   PROTELES_LIVE_RUST_LOG  the server's RUST_LOG (default warn)

set -euo pipefail

# One database per port, so two runs at once — the iOS and the Android suites,
# say — cannot drop each other's database mid-test, which a single fixed name
# did. Set for real once the port is known (start) or read (state).
DB_PREFIX="proteles_sdk_live"
DB_NAME=""
PORT_LO=18400
PORT_HI=18499

BIN_DIR="${PROTELES_LIVE_BIN_DIR:-}"
SERVER_BIN="$BIN_DIR/oauth-server"
ADMIN_BIN="$BIN_DIR/admin-cli"
LIVE_DIR="${PROTELES_LIVE_DIR:-${TMPDIR:-/tmp}/proteles-sdk-live}"
LIVE_DIR="${LIVE_DIR%/}"
STATE="$LIVE_DIR/state.env"
SERVER_LOG="$LIVE_DIR/oauth-server.log"

PG_HOST="${PROTELES_LIVE_PG_HOST:-localhost}"
PG_PORT="${PROTELES_LIVE_PG_PORT:-5432}"
PG_USER="${PROTELES_LIVE_PG_USER:-oauth}"
PG_PASSWORD="${PROTELES_LIVE_PG_PASSWORD:-oauth}"

# What the SDK tests are handed. The client is the shape docs/mobile-SDKs.md
# §2 and §10 describe: public (token_endpoint_auth_method none, no secret), an
# https redirect (M7: the server registers no private-use scheme), the
# authorization_code and
# refresh_token grants — the grant, not a scope, is what yields a refresh
# token (§2.3) — and PKCE required. First-party, so no consent screen stands
# between the login form and the redirect; that is what the SDK test's
# stand-in for the browser has to get past.
CLIENT_ID="proteles-live"
REDIRECT_URI="https://live.proteles.test/callback"
POST_LOGOUT_REDIRECT_URI="https://live.proteles.test/logout"
USERNAME="sdklive"
PASSWORD="${PROTELES_LIVE_PASSWORD:-live sdk correct horse battery staple}"
EMAIL="sdklive@example.com"

say() { printf 'run-live: %s\n' "$*" >&2; }
die() { printf 'run-live: error: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; }

psql_admin() { # SQL against the maintenance database, never against another one
  PGPASSWORD="$PG_PASSWORD" PGOPTIONS='-c client_min_messages=warning' psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres \
    -v ON_ERROR_STOP=1 -qtAX -c "$1"
}
psql_live() { # SQL against this run's proteles_sdk_live_<port> only
  PGPASSWORD="$PG_PASSWORD" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$DB_NAME" \
    -v ON_ERROR_STOP=1 -qtAX -c "$1"
}

port_listener() { lsof -nP -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | head -1 || true; }

# The pid is only ever signalled once it is proven to be this server binary:
# a stale state file must not turn `stop` into killing whatever reused the pid.
is_our_server() { # $1 = pid
  [ -n "${1:-}" ] || return 1
  local cmd
  cmd="$(ps -p "$1" -o command= 2>/dev/null || true)"
  case "$cmd" in "$SERVER_BIN"*) return 0 ;; *) return 1 ;; esac
}

read_state() { # sets STATE_PID, STATE_PORT, STATE_BIN; returns 1 without a state file
  STATE_PID=""; STATE_PORT=""; STATE_BIN=""
  [ -f "$STATE" ] || return 1
  STATE_PID="$(sed -n 's/^PID=//p' "$STATE")"
  STATE_PORT="$(sed -n 's/^PORT=//p' "$STATE")"
  STATE_BIN="$(sed -n 's/^SERVER_BIN=//p' "$STATE")"
  [ -n "$STATE_PORT" ] && DB_NAME="${DB_PREFIX}_${STATE_PORT}"
  return 0
}

stop_server() {
  if ! read_state; then
    say "no server recorded in $STATE; nothing to stop"
    return 0
  fi
  local pid="$STATE_PID" port="$STATE_PORT" i
  SERVER_BIN="${STATE_BIN:-$SERVER_BIN}"
  if is_our_server "$pid"; then
    kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 50); do is_our_server "$pid" || break; sleep 0.2; done
    if is_our_server "$pid"; then
      say "pid $pid ignored SIGTERM for 10s; sending SIGKILL"
      kill -KILL "$pid" 2>/dev/null || true
      sleep 0.5
    fi
    # Stopped means the port is free, not that the signal was delivered.
    for i in $(seq 1 50); do [ -z "$(port_listener "$port")" ] && break; sleep 0.2; done
    [ -z "$(port_listener "$port")" ] || die "port $port is still held after stopping pid $pid"
    say "stopped oauth-server (pid $pid, port $port)"
  else
    say "pid ${pid:-?} is not a running oauth-server any more; clearing the stale state"
  fi
  release_port "$port"
  rm -f "$STATE"
}

# **A port is reserved, not just found free.** Between choosing a port and the
# server binding it lie a database drop, a create and the migrations — seconds
# in which a second run saw the same port free, chose it, and so chose the same
# database. Two runs started together did exactly that. `mkdir` is the atomic
# step: the run that creates the port's directory holds it. A reservation whose
# owner has exited and whose port nobody is listening on is stale — a run
# killed before it could clean up — and is taken over.
PORT_LOCKS="${TMPDIR:-/tmp}/proteles-sdk-live-ports"

reserve_port() { # $1: a port; succeeds when this run now holds it
  local lock="$PORT_LOCKS/$1" owner
  mkdir -p "$PORT_LOCKS"
  if mkdir "$lock" 2>/dev/null; then echo "$$" > "$lock/pid"; return 0; fi
  owner="$(cat "$lock/pid" 2>/dev/null || true)"
  if { [ -z "$owner" ] || ! kill -0 "$owner" 2>/dev/null; } && [ -z "$(port_listener "$1")" ]; then
    rm -rf "$lock"
    if mkdir "$lock" 2>/dev/null; then echo "$$" > "$lock/pid"; return 0; fi
  fi
  return 1
}

release_port() { # $1: a port this directory's state recorded
  [ -n "${1:-}" ] && rm -rf "${PORT_LOCKS:?}/$1"
  return 0
}

choose_port() {
  local p
  if [ -n "${PROTELES_LIVE_PORT:-}" ]; then
    p="$PROTELES_LIVE_PORT"
    case "$p" in ''|*[!0-9]*) die "PROTELES_LIVE_PORT must be a number" ;; esac
    { [ "$p" -ge "$PORT_LO" ] && [ "$p" -le "$PORT_HI" ]; } || die "PROTELES_LIVE_PORT must be in $PORT_LO–$PORT_HI"
    [ -z "$(port_listener "$p")" ] || die "port $p is in use"
    reserve_port "$p" || die "port $p is reserved by another run"
    echo "$p"; return 0
  fi
  for p in $(seq 18480 "$PORT_HI") $(seq "$PORT_LO" 18479); do
    [ -z "$(port_listener "$p")" ] && reserve_port "$p" && { echo "$p"; return 0; }
  done
  die "no free port in $PORT_LO–$PORT_HI"
}

print_exports() {
  local k v
  for k in PROTELES_LIVE_ISSUER PROTELES_LIVE_CLIENT_ID PROTELES_LIVE_REDIRECT_URI \
           PROTELES_LIVE_USERNAME PROTELES_LIVE_PASSWORD PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI \
           PROTELES_LIVE_MANAGEMENT_TOKEN; do
    v="$(sed -n "s/^$k=//p" "$STATE")"
    printf 'export %s=%q\n' "$k" "$v"
  done
}

start_server() {
  [ -n "$BIN_DIR" ] || die "PROTELES_LIVE_BIN_DIR is not set: point it at oauth-server and admin-cli built from the server repository, or set PROTELES_LIVE_ISSUER and the other PROTELES_LIVE_* values for a server already running and use '$0 -- CMD' (see the header)"
  command -v psql >/dev/null || die "psql is required"
  command -v curl >/dev/null || die "curl is required"
  command -v openssl >/dev/null || die "openssl is required"
  command -v lsof >/dev/null || die "lsof is required"
  command -v perl >/dev/null || die "perl is required"
  [ -x "$SERVER_BIN" ] || die "no oauth-server at $SERVER_BIN (set PROTELES_LIVE_BIN_DIR)"
  [ -x "$ADMIN_BIN" ] || die "no admin-cli at $ADMIN_BIN (set PROTELES_LIVE_BIN_DIR)"
  mkdir -p "$LIVE_DIR"
  chmod 700 "$LIVE_DIR"

  # A server this directory already started, and that is still running, is
  # somebody's run in progress: refuse rather than stop it underneath them. A
  # stale record (its process gone) is cleared.
  if read_state; then
    if is_our_server "$STATE_PID"; then
      die "a server started from $LIVE_DIR is still running (pid $STATE_PID, port $STATE_PORT): stop it with '$0 stop', or give this run its own PROTELES_LIVE_DIR"
    fi
    stop_server
  fi

  local port issuer kek session_secret mgmt_token ttl
  port="$(choose_port)"
  DB_NAME="${DB_PREFIX}_${port}"
  issuer="http://localhost:$port"
  ttl="${PROTELES_LIVE_ACCESS_TOKEN_TTL_SECONDS:-900}"
  case "$ttl" in ''|*[!0-9]*) die "PROTELES_LIVE_ACCESS_TOKEN_TTL_SECONDS must be a number" ;; esac

  if [ -f "$BIN_DIR/SOURCE_COMMIT" ]; then
    say "binaries: $BIN_DIR (built from $(cut -c1-12 "$BIN_DIR/SOURCE_COMMIT"))"
  else
    say "binaries: $BIN_DIR"
  fi
  say "recreating database $DB_NAME on $PG_HOST:$PG_PORT"
  psql_admin "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE);" >/dev/null
  psql_admin "CREATE DATABASE $DB_NAME;" >/dev/null

  # Throwaway secrets, generated per start — the database they
  # encrypt is recreated with them, so nothing needs to outlive this run.
  kek="$(openssl rand -base64 32)"
  session_secret="$(openssl rand -base64 48)"
  # The platform token for the management API. Nothing
  # here needs it to seed; curl-check.sh uses it to show the seeded client is
  # one a tenant administrator could register through the validating door.
  mgmt_token="live-$(openssl rand -hex 24)"

  # `env -i`: the server reads only what is named here. It calls
  # dotenvy::dotenv(), which walks up from the working directory for a `.env`,
  # so it also runs from LIVE_DIR, where there is none; set variables win over
  # a `.env` anyway, but an unset one would be filled from it.
  SERVER_ENV=(
    PATH=/usr/bin:/bin
    HOME="$LIVE_DIR"
    OAUTH_ISSUER="$issuer"
    # The issuer's host (localhost) is a base host automatically. 127.0.0.1 is
    # the same server under another name, and the integration tests name it
    # for the same reason. The issuer follows the Host a client reached
    # (docs/mobile-SDKs.md §10.1), so a client that reaches 127.0.0.1 is
    # told `http://127.0.0.1:PORT` and an SDK configured with the localhost
    # issuer refuses it: use PROTELES_LIVE_ISSUER exactly.
    TENANT_BASE_HOSTS=127.0.0.1
    BIND_ADDR="127.0.0.1:$port"
    DATABASE_URL="postgres://$PG_USER:$PG_PASSWORD@$PG_HOST:$PG_PORT/$DB_NAME"
    KEY_ENCRYPTION_KEY_B64="$kek"
    KEY_ENCRYPTION_KEY_ID=kek-live
    SESSION_SECRET="$session_secret"
    ACCESS_TOKEN_TTL_SECONDS="$ttl"
    REFRESH_TOKEN_TTL_SECONDS=2592000
    AUTH_CODE_TTL_SECONDS=60
    # The integration tests' value, for the same reason: a test suite signs in
    # many times from one address. The per-account budget is left at its
    # default; a successful sign-in refunds it.
    RATE_LIMIT_LOGIN_PER_MIN=30
    MANAGEMENT_BOOTSTRAP_TOKEN="$mgmt_token"
    RUST_LOG="${PROTELES_LIVE_RUST_LOG:-warn}"
  )

  say "starting oauth-server on $issuer (log: $SERVER_LOG)"
  : > "$SERVER_LOG"
  # setsid, so the server outlives `run-live.sh start` and a terminal's
  # Ctrl-C does not reach it behind this script's back. perl execs, so $! is
  # the server's own pid.
  ( cd "$LIVE_DIR" && exec nohup perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV or die "exec: $!"' \
      env -i "${SERVER_ENV[@]}" "$SERVER_BIN" >>"$SERVER_LOG" 2>&1 ) &
  local pid=$!
  {
    echo "PID=$pid"
    echo "PORT=$port"
    echo "SERVER_BIN=$SERVER_BIN"
    echo "PROTELES_LIVE_ISSUER=$issuer"
    echo "PROTELES_LIVE_CLIENT_ID=$CLIENT_ID"
    echo "PROTELES_LIVE_REDIRECT_URI=$REDIRECT_URI"
    echo "PROTELES_LIVE_USERNAME=$USERNAME"
    echo "PROTELES_LIVE_PASSWORD=$PASSWORD"
    echo "PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI=$POST_LOGOUT_REDIRECT_URI"
    echo "PROTELES_LIVE_MANAGEMENT_TOKEN=$mgmt_token"
  } > "$STATE"
  chmod 600 "$STATE"
  OWN_STATE=1

  # Ready means: the process we started is the one listening, and the tenant
  # path (not only /health) answers — discovery needs migrations applied, the
  # default tenant present and its signing key generated. A cold debug boot on
  # a loaded laptop has taken over a minute.
  local i code owner
  for i in $(seq 1 150); do
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -n 40 "$SERVER_LOG" | sed 's/^/  | /' >&2
      rm -f "$STATE"
      die "oauth-server exited during startup"
    fi
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$issuer/.well-known/openid-configuration" 2>/dev/null || true)"
    [ "$code" = "200" ] && break
    sleep 1
  done
  [ "$code" = "200" ] || { tail -n 40 "$SERVER_LOG" | sed 's/^/  | /' >&2; stop_server; die "oauth-server did not become ready in 150s"; }
  owner="$(port_listener "$port")"
  [ "$owner" = "$pid" ] || { stop_server; die "port $port is answered by pid ${owner:-none}, not the server started here ($pid)"; }
  say "ready after ~${i}s (pid $pid)"

  local applied failed
  applied="$(psql_live "SELECT count(*) FROM _sqlx_migrations WHERE success;")"
  failed="$(psql_live "SELECT count(*) FROM _sqlx_migrations WHERE NOT success;")"
  [ "$failed" = "0" ] || { stop_server; die "$failed migration(s) recorded as failed"; }
  say "migrations applied by the server: $applied"

  seed || { stop_server; die "seeding failed"; }
}

admin() { ( cd "$LIVE_DIR" && env -i "${SERVER_ENV[@]}" "$ADMIN_BIN" "$@" ); }

seed() {
  # The tenant: the default one, which migrations create and the issuer's own
  # host resolves to. No seed-tenant — that would make a second tenant reached
  # only at <slug>.localhost, a different issuer.
  [ "$(psql_live "SELECT count(*) FROM tenants WHERE slug='default' AND id='00000000-0000-0000-0000-000000000001';")" = "1" ] \
    || { say "the default tenant is missing"; return 1; }

  # A person: admin-cli seed-user, default tenant, email
  # verified, no second factor (a fresh database has none to inherit).
  admin seed-user --username "$USERNAME" --password "$PASSWORD" --email "$EMAIL" >/dev/null

  # The client: admin-cli seed-client, with --type public.
  # Note that this door writes the row directly and does not run the
  # registrability check (docs/mobile-SDKs.md §2.1); curl-check.sh shows
  # the same redirect is accepted where it is validated.
  admin seed-client --client-id "$CLIENT_ID" --type public --name "Proteles SDK live tests" \
    --redirect-uri "$REDIRECT_URI" --post-logout-redirect-uri "$POST_LOGOUT_REDIRECT_URI" \
    --grants authorization_code,refresh_token \
    --scopes openid,profile,email,offline_access \
    --require-pkce true --first-party true >/dev/null

  # Read back, rather than trusted: the flags are parsed by position and a
  # typo silently takes a default.
  local row want
  row="$(psql_live "SELECT client_type, token_endpoint_auth_method, client_secret_hash IS NULL,
                           array_to_string(redirect_uris,' '), array_to_string(grant_types,','),
                           require_pkce, first_party
                      FROM oauth_clients WHERE client_id='$CLIENT_ID';")"
  want="public|none|t|$REDIRECT_URI|authorization_code,refresh_token|t|t"
  [ "$row" = "$want" ] || { say "client row is '$row', expected '$want'"; return 1; }
  row="$(psql_live "SELECT count(*) FROM users WHERE username='$USERNAME' AND tenant_id='00000000-0000-0000-0000-000000000001';")"
  [ "$row" = "1" ] || { say "user $USERNAME not in the default tenant"; return 1; }
  say "seeded user $USERNAME and public client $CLIENT_ID ($REDIRECT_URI, first-party, PKCE required)"
}

# Mode 2 (the header): a server this script did not start, named by
# PROTELES_LIVE_ISSUER. It is only checked, never seeded or stopped: what a test
# needs from it is the caller's to have set up (README.md, "What a test gets").
check_given_server() {
  local k missing=() body issuer
  for k in PROTELES_LIVE_ISSUER PROTELES_LIVE_CLIENT_ID PROTELES_LIVE_REDIRECT_URI \
           PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI PROTELES_LIVE_USERNAME PROTELES_LIVE_PASSWORD; do
    [ -n "${!k:-}" ] || missing+=("$k")
  done
  [ "${#missing[@]}" -eq 0 ] ||
    die "PROTELES_LIVE_ISSUER names a running server, so these must be set as well: ${missing[*]}"
  command -v curl >/dev/null || die "curl is required"
  command -v perl >/dev/null || die "perl is required"
  body="$(curl -sS --fail --max-time 10 "${PROTELES_LIVE_ISSUER%/}/.well-known/openid-configuration")" ||
    die "no discovery document at ${PROTELES_LIVE_ISSUER%/}/.well-known/openid-configuration"
  issuer="$(printf '%s' "$body" | perl -MJSON::PP -0777 -ne 'my $d = eval { decode_json($_) }; print ref $d eq "HASH" ? ($d->{issuer} // "") : ""')"
  # Byte for byte, as every SDK compares it: a server reached under another
  # name than its issuer is refused by the SDK, and the run would only say so
  # as a failed sign-in.
  [ "$issuer" = "$PROTELES_LIVE_ISSUER" ] ||
    die "the server at $PROTELES_LIVE_ISSUER says its issuer is '$issuer'; set PROTELES_LIVE_ISSUER to exactly that"
  say "using the server already running at $PROTELES_LIVE_ISSUER: nothing is started, seeded or stopped"
}

# Set once this invocation has written the state file. The exit traps stop a
# server only then: a start that refused because another run's server was still
# recorded here used to find that run's state on the way out and stop it.
OWN_STATE=0

cmd="${1:-start}"
case "$cmd" in
  start)
    # A start that fails part-way stops what it started rather than leaving a
    # half-seeded server holding the port.
    STARTED_OK=0
    trap '[ "$STARTED_OK" = 1 ] || [ "$OWN_STATE" = 0 ] || stop_server' EXIT
    start_server
    STARTED_OK=1
    print_exports
    say "server left running; stop it with: $0 stop"
    ;;
  env)
    read_state || die "no server recorded in $STATE (run: $0 start)"
    SERVER_BIN="${STATE_BIN:-$SERVER_BIN}"
    is_our_server "$STATE_PID" || die "the recorded server (pid $STATE_PID) is not running"
    print_exports
    ;;
  stop)
    stop_server
    ;;
  --)
    shift
    [ $# -gt 0 ] || die "nothing to run after --"
    if [ -n "${PROTELES_LIVE_ISSUER:-}" ]; then
      check_given_server
      exec "$@"
    fi
    trap '[ "$OWN_STATE" = 0 ] || stop_server' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    start_server
    set +e
    (
      set -e
      eval "$(print_exports)"
      exec "$@"
    )
    rc=$?
    set -e
    say "command exited $rc"
    exit "$rc"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
