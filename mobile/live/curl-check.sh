#!/usr/bin/env bash
# Proves run-live.sh with curl: the requests a native SDK makes (docs/mobile-SDKs.md
# §10.2–10.4), in order, against the real server, and the §2 claims those
# requests can observe. No SDK code runs; curl plays both the app and the
# browser, the way Proteles' integration tests play the browser.
#
#   mobile/live/run-live.sh -- mobile/live/curl-check.sh
#
# Needs curl, jq and openssl; python3 (standard library only) for the RS256
# signature check, which is skipped — and counted as skipped — without it.
# CURL_CHECK_SLOW=1 adds the one check that has to wait a minute (§2.3's
# 60-second window).
#
# Two kinds of line. `ok`/`FAIL` are the harness: a FAIL means the server, the
# seed or this script is not what an SDK test can stand on, and the exit status
# is 1. `DIFF` is the server disagreeing with docs/mobile-SDKs.md while the
# flow still works: printed, counted, and not fatal, because it is the document
# or the server that needs a decision, not the harness.

set -uo pipefail

: "${PROTELES_LIVE_ISSUER:?run this under run-live.sh -- (PROTELES_LIVE_ISSUER is unset)}"
: "${PROTELES_LIVE_CLIENT_ID:?}" "${PROTELES_LIVE_REDIRECT_URI:?}"
: "${PROTELES_LIVE_USERNAME:?}" "${PROTELES_LIVE_PASSWORD:?}"
ISSUER="$PROTELES_LIVE_ISSUER"
CLIENT_ID="$PROTELES_LIVE_CLIENT_ID"
REDIRECT_URI="$PROTELES_LIVE_REDIRECT_URI"
POST_LOGOUT="${PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI:-}"
MGMT_TOKEN="${PROTELES_LIVE_MANAGEMENT_TOKEN:-}"

for tool in curl jq openssl; do
  command -v "$tool" >/dev/null || { echo "curl-check: $tool is required" >&2; exit 2; }
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/proteles-curl-check.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
BODY="$TMP/body"; HEADERS="$TMP/headers"; JAR="$TMP/jar"; : > "$JAR"

PASS=0; FAILS=0; DIFFS=0; SKIPS=0
section() { printf '\n== %s ==\n' "$1"; }
ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAILS=$((FAILS + 1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }
diff_() { DIFFS=$((DIFFS + 1)); printf '  DIFF  %s\n        %s\n' "$1" "$2"; }
skip() { SKIPS=$((SKIPS + 1)); printf '  skip  %s — %s\n' "$1" "$2"; }
got()  { printf '        %s\n' "$1"; }
check()    { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "expected '$2', got '$3'"; fi; }
contract() { if [ "$2" = "$3" ]; then ok "$1"; else diff_ "$1" "document says '$2', server gave '$3'"; fi; }
# The harness cannot go on without this step.
require() { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "expected '$2', got '$3'"; summary; exit 1; fi; }

summary() {
  printf '\n%d ok, %d FAIL, %d DIFF, %d skipped\n' "$PASS" "$FAILS" "$DIFFS" "$SKIPS"
}

# --- HTTP, with a hand-kept cookie jar -------------------------------------
# By hand, because the login cookies are `__Host-` and `Secure`
# on plain-http localhost, which curl's own jar will not send back.
cookie_get() { awk -v n="$1" '$1==n{print $2}' "$JAR"; }
cookie_apply() {
  local line kv name value
  while IFS= read -r line; do
    line="${line%$'\r'}"; kv="${line#*: }"; name="${kv%%=*}"; value="${kv#*=}"; value="${value%%;*}"
    grep -v "^$name " "$JAR" > "$JAR.t"; mv "$JAR.t" "$JAR"
    if ! printf '%s' "$line" | grep -qiE 'max-age=0|expires=Thu, 01 Jan 1970'; then
      printf '%s %s\n' "$name" "$value" >> "$JAR"
    fi
  done < <(grep -i '^set-cookie:' "$HEADERS")
}
# req METHOD URL [--cookies] [curl args…] — sets STATUS and LOCATION; body in $BODY.
req() {
  local method="$1" url="$2"; shift 2
  local cookies=0 ch
  if [ "${1:-}" = "--cookies" ]; then cookies=1; shift; fi
  local a=(-s -o "$BODY" -D "$HEADERS" -X "$method" --max-time 30)
  if [ "$cookies" = 1 ]; then
    ch="$(awk '{printf "%s=%s; ", $1, $2}' "$JAR" | sed 's/; $//')"
    [ -n "$ch" ] && a+=(-H "Cookie: $ch")
  fi
  curl "${a[@]}" "$@" "$url"
  STATUS="$(awk 'toupper($1) ~ /^HTTP/ {c=$2} END{print c}' "$HEADERS")"
  LOCATION="$(grep -i '^location:' "$HEADERS" | tail -1 | sed 's/^[Ll]ocation: //; s/\r$//')"
  # The server answers a sign-in or logout form whose chain can end at the app
  # with a 200 page that moves on by meta refresh, not a 303; its target is
  # read into LOCATION.
  if [ "$STATUS" = 200 ] && grep -q '<meta http-equiv="refresh" content="0;url=' "$BODY" 2>/dev/null; then
    LOCATION="$(python3 -c 'import html, re, sys
m = re.search(r"<meta http-equiv=\"refresh\" content=\"0;url=([^\"]*)\"", open(sys.argv[1]).read())
print(html.unescape(m.group(1)) if m else "")' "$BODY")"
  fi
  [ "$cookies" = 1 ] && cookie_apply
  return 0
}
header() { grep -i "^$1:" "$HEADERS" | tail -1 | sed 's/^[^:]*: //; s/\r$//'; }
form_post() { # form_post URL k=v … — the token and revocation endpoints; public client, no secret
  local url="$1"; shift
  local a=() kv
  for kv in "$@"; do a+=(--data-urlencode "$kv"); done
  req POST "$url" -H 'Content-Type: application/x-www-form-urlencoded' "${a[@]}"
}

# --- encodings --------------------------------------------------------------
b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
rand_b64u() { openssl rand 32 | b64u; }
urldecode() { local s="${1//+/ }"; printf '%b' "${s//%/\\x}"; }
qparam() { printf '%s' "$1" | sed -n "s/.*[?&]$2=\([^&#]*\).*/\1/p"; }
jwt_part() { # $1=jwt $2=0|1 → the decoded JSON
  printf '%s' "$1" | cut -d. -f$(( $2 + 1 )) | jq -rR 'gsub("-";"+") | gsub("_";"/") | . + ("=" * ((4 - (length % 4)) % 4)) | @base64d'
}
claim() { jwt_part "$1" 1 | jq -c --arg k "$2" 'if has($k) then .[$k] else "<absent>" end' | sed 's/^"\(.*\)"$/\1/'; }
at_hash_of() { printf '%s' "$1" | openssl dgst -sha256 -binary | head -c 16 | b64u; }

# RS256 over the bytes as they arrived (§5 step 3), with the JWKS key named by
# `kid`: EMSA-PKCS1-v1_5 recomputed and compared, standard library only.
verify_rs256() { # $1=jwt $2=jwks file → prints "valid" or a reason
  python3 - "$1" "$2" <<'PY'
import sys, json, base64, hashlib
tok, jwks = sys.argv[1], json.load(open(sys.argv[2]))
def d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
h, p, s = tok.split(".")
hdr = json.loads(d(h))
if hdr.get("alg") != "RS256": print("alg " + str(hdr.get("alg"))); sys.exit()
keys = [k for k in jwks["keys"] if k.get("kid") == hdr.get("kid")]
if len(keys) != 1: print("kid %r matches %d keys" % (hdr.get("kid"), len(keys))); sys.exit()
n = int.from_bytes(d(keys[0]["n"]), "big"); e = int.from_bytes(d(keys[0]["e"]), "big")
k = (n.bit_length() + 7) // 8
em = pow(int.from_bytes(d(s), "big"), e, n).to_bytes(k, "big")
digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256((h + "." + p).encode()).digest()
want = b"\x00\x01" + b"\xff" * (k - 3 - len(digest_info)) + b"\x00" + digest_info
print("valid" if em == want else "signature does not verify")
PY
}

# ==========================================================================
section "1. Discovery (§10.2 step 1)"
req GET "$ISSUER/.well-known/openid-configuration"
require "GET /.well-known/openid-configuration" 200 "$STATUS"
cp "$BODY" "$TMP/discovery.json"
disc() { jq -r "$1" "$TMP/discovery.json"; }
# Byte for byte: the raw string, not a normalised URL.
jq -j '.issuer' "$TMP/discovery.json" > "$TMP/issuer.got"; printf '%s' "$ISSUER" > "$TMP/issuer.want"
if cmp -s "$TMP/issuer.got" "$TMP/issuer.want"; then ok "issuer is '$ISSUER', byte for byte"
else fail "issuer equals the configured one byte for byte" "got '$(cat "$TMP/issuer.got")'"; summary; exit 1; fi
require "authorization_response_iss_parameter_supported" true "$(disc '.authorization_response_iss_parameter_supported')"
AUTHZ="$(disc .authorization_endpoint)"; TOKEN="$(disc .token_endpoint)"; REVOKE="$(disc .revocation_endpoint)"
JWKS_URI="$(disc .jwks_uri)"; END_SESSION="$(disc '.end_session_endpoint // ""')"; USERINFO="$(disc '.userinfo_endpoint // ""')"
got "authorization_endpoint $AUTHZ"
got "token_endpoint         $TOKEN"
got "revocation_endpoint    $REVOKE"
got "end_session_endpoint   ${END_SESSION:-<absent>}"
bad_ep="$(jq -r --arg i "$ISSUER/" 'to_entries[] | select(.key|endswith("_endpoint") or .=="jwks_uri") | select((.value|startswith($i))|not) | .key' "$TMP/discovery.json")"
contract "every endpoint is built from the issuer (§2.5)" "" "$bad_ep"
contract "code_challenge_methods_supported (§2.2)" '["S256"]' "$(jq -c '.code_challenge_methods_supported' "$TMP/discovery.json")"
contract "token_endpoint_auth_methods_supported includes none (§2.3)" true "$(disc '.token_endpoint_auth_methods_supported | index("none") != null')"
contract "revocation_endpoint_auth_methods_supported includes none (§2.5, §10.4)" true "$(disc '.revocation_endpoint_auth_methods_supported | index("none") != null')"
contract "introspection does not accept none (§2.5)" false "$(disc '(.introspection_endpoint_auth_methods_supported // []) | index("none") != null')"
contract "id_token_signing_alg_values_supported (§2.4)" '["RS256"]' "$(jq -c '.id_token_signing_alg_values_supported' "$TMP/discovery.json")"
# §6 P1.8: both were emitted and neither was listed. Named here because `acr`
# only appears in a multi-factor sign-in's token, which this harness never
# makes, so the per-token check in idtoken_checks cannot see it.
contract "claims_supported lists at_hash and acr (§6 P1.8)" "true/true" \
  "$(disc '(.claims_supported // []) | [(index("at_hash") != null), (index("acr") != null)] | map(tostring) | join("/")')"

# The issuer follows the Host the client reached (docs/mobile-SDKs.md §10.1),
# so the same server reached by another name names another issuer — which an
# SDK configured with $ISSUER must, and does, refuse.
ALT="$(printf '%s' "$ISSUER" | sed 's#//localhost:#//127.0.0.1:#')"
if [ "$ALT" != "$ISSUER" ]; then
  req GET "$ALT/.well-known/openid-configuration"
  got "the same server at $ALT says issuer=$(jq -r '.issuer // empty' "$BODY" 2>/dev/null) (HTTP $STATUS)"
fi
req GET "$ISSUER/.well-known/oauth-authorization-server"
check "RFC 8414 metadata names the same issuer" "$ISSUER" "$(jq -r .issuer "$BODY" 2>/dev/null)"

req GET "$JWKS_URI"
require "GET jwks_uri" 200 "$STATUS"
cp "$BODY" "$TMP/jwks.json"
# §5.2's key filter, as an SDK applies it: a key it would refuse is useless to it.
usable="$(jq '[.keys[] | select(.kty=="RSA" and ((.use // "sig")=="sig") and ((.alg // "RS256")=="RS256"))] | length' "$TMP/jwks.json")"
[ "${usable:-0}" -ge 1 ] && ok "JWKS has $usable key(s) the SDK filter accepts (kty RSA, use sig, alg RS256)" \
  || fail "JWKS has a key the SDK filter accepts" "$(jq -c '[.keys[] | {kty,use,alg,kid}]' "$TMP/jwks.json")"

# ==========================================================================
section "2. Authorization request with PKCE (§10.2 steps 2–3)"
VERIFIER="$(rand_b64u)"; CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | b64u)"
STATE="$(rand_b64u)"; NONCE="$(rand_b64u)"
check "verifier and challenge are 43 characters" "43/43" "${#VERIFIER}/${#CHALLENGE}"
SCOPE="openid profile email"      # the SDK default; no offline_access (§2.3, trap 4)
authz_url() { # $1=redirect_uri $2=challenge $3=method ("" = omit) → a full authorization URL
  local u="$AUTHZ?response_type=code&client_id=$(jq -rn --arg v "$CLIENT_ID" '$v|@uri')"
  u+="&redirect_uri=$(jq -rn --arg v "$1" '$v|@uri')&scope=$(jq -rn --arg v "$SCOPE" '$v|@uri')"
  u+="&state=$STATE&nonce=$NONCE&code_challenge=$2"
  [ -n "$3" ] && u+="&code_challenge_method=$3"
  printf '%s' "$u"
}
AUTH_URL="$(authz_url "$REDIRECT_URI" "$CHALLENGE" S256)"
req GET "$AUTH_URL" --cookies
require "an unauthenticated authorization request is a 303" 303 "$STATUS"
got "Location: ${LOCATION:0:90}…"
case "$LOCATION" in /login\?*|"$ISSUER"/login\?*) ok "it bounces to the login page" ;;
  *) fail "it bounces to the login page" "Location: $LOCATION"; summary; exit 1 ;; esac

# ==========================================================================
section "3. The login form (the browser's part)"
LOGIN_URL="$LOCATION"; case "$LOGIN_URL" in /*) LOGIN_URL="$ISSUER$LOGIN_URL" ;; esac
req GET "$LOGIN_URL" --cookies
require "GET the login page" 200 "$STATUS"
cp "$BODY" "$TMP/login.html"
[ -n "$(cookie_get __Host-login_csrf)" ] && ok "a login CSRF cookie is set" || fail "a login CSRF cookie is set" "$(header set-cookie)"
# The form's own hidden fields, as a browser would submit them.
hidden() { grep -o "<input[^>]*name=\"$1\"[^>]*>" "$TMP/login.html" | head -1 | sed -n 's/.*value="\([^"]*\)".*/\1/p' | sed 's/&amp;/\&/g; s/&#x2F;/\//g; s/&#47;/\//g; s/&quot;/"/g; s/&#39;/'"'"'/g; s/&lt;/</g; s/&gt;/>/g'; }
FORM_ACTION="$(grep -o '<form[^>]*action="[^"]*"' "$TMP/login.html" | head -1 | sed 's/.*action="\([^"]*\)"/\1/')"
FORM_REDIRECT="$(hidden redirect)"; FORM_CSRF="$(hidden csrf)"
check "the form posts to /login" "/login" "$FORM_ACTION"
[ -n "$FORM_REDIRECT" ] && [ -n "$FORM_CSRF" ] && ok "the form carries redirect and csrf" || fail "the form carries redirect and csrf" "redirect='$FORM_REDIRECT' csrf='$FORM_CSRF'"
req POST "$ISSUER$FORM_ACTION" --cookies \
  --data-urlencode "username=$PROTELES_LIVE_USERNAME" --data-urlencode "password=$PROTELES_LIVE_PASSWORD" \
  --data-urlencode "redirect=$FORM_REDIRECT" --data-urlencode "csrf=$FORM_CSRF"
require "the login is accepted, through the page that moves on (200)" 200 "$STATUS"
[ -n "$(cookie_get __Host-oauth_session)" ] && ok "a session cookie is set" || fail "a session cookie is set" "no __Host-oauth_session"
case "$LOCATION" in *mfa*|*otp*|*factor*|*passkey*) fail "no second factor is asked for" "Location: $LOCATION" ;;
  *) ok "no second factor is asked for (→ ${LOCATION:0:40}…)" ;; esac

NEXT="$LOCATION"; case "$NEXT" in /*) NEXT="$ISSUER$NEXT" ;; esac
req GET "$NEXT" --cookies
require "the authorization request, now signed in, is a 303 (no consent page: first-party)" 303 "$STATUS"
CALLBACK="$LOCATION"

# ==========================================================================
section "4. The callback (§10.2 step 4)"
got "Location: $CALLBACK"
case "$CALLBACK" in "$REDIRECT_URI?"*) ok "redirects to $REDIRECT_URI" ;;
  *) fail "redirects to $REDIRECT_URI" "Location: $CALLBACK"; summary; exit 1 ;; esac
CODE="$(urldecode "$(qparam "$CALLBACK" code)")"
CB_STATE="$(urldecode "$(qparam "$CALLBACK" state)")"
CB_ISS="$(urldecode "$(qparam "$CALLBACK" iss)")"
[ -n "$CODE" ] && ok "carries a code (${#CODE} characters)" || { fail "carries a code" "none"; summary; exit 1; }
check "carries the state that was sent" "$STATE" "$CB_STATE"
check "carries iss equal to the issuer, byte for byte (RFC 9207)" "$ISSUER" "$CB_ISS"
check "carries no error" "" "$(qparam "$CALLBACK" error)"

# ==========================================================================
section "5. Code exchange (§10.2 step 5)"
form_post "$TOKEN" grant_type=authorization_code "code=$CODE" "redirect_uri=$REDIRECT_URI" \
  "client_id=$CLIENT_ID" "code_verifier=$VERIFIER"
require "POST token_endpoint (authorization_code, no secret)" 200 "$STATUS"
cp "$BODY" "$TMP/tokens1.json"
AT1="$(jq -r '.access_token // empty' "$BODY")"; RT1="$(jq -r '.refresh_token // empty' "$BODY")"
IDT1="$(jq -r '.id_token // empty' "$BODY")"; EXPIRES="$(jq -r '.expires_in // empty' "$BODY")"
got "fields: $(jq -c 'keys' "$BODY"), token_type=$(jq -r .token_type "$BODY"), expires_in=$EXPIRES, scope=$(jq -r '.scope // "<absent>"' "$BODY")"
[ -n "$AT1" ] && ok "an access token" || fail "an access token" "none"
[ -n "$IDT1" ] && ok "an ID token" || fail "an ID token" "none"
if [ -n "$RT1" ]; then ok "a refresh token, without offline_access in the request (§2.3: the grant decides)"
else fail "a refresh token comes back" "none — body $(head -c 300 "$BODY")"; summary; exit 1; fi
check "Cache-Control: no-store (RFC 6749 §5.1)" "no-store" "$(header cache-control | tr 'A-Z' 'a-z' | tr -d ' ' | grep -o 'no-store' | head -1)"

idtoken_checks() { # $1=id token $2=access token $3=expected nonce ("" = must be absent) $4=label
  local t="$1" h
  h="$(jwt_part "$t" 0)"
  check "$4: alg RS256" RS256 "$(printf '%s' "$h" | jq -r .alg)"
  if command -v python3 >/dev/null; then check "$4: RS256 signature verifies with the JWKS key named by kid" valid "$(verify_rs256 "$t" "$TMP/jwks.json")"
  else skip "$4: signature" "no python3"; fi
  check "$4: iss" "$ISSUER" "$(claim "$t" iss)"
  check "$4: aud is the client_id" "$CLIENT_ID" "$(claim "$t" aud)"
  if [ -n "$3" ]; then check "$4: nonce echoes the request" "$3" "$(claim "$t" nonce)"
  else contract "$4: no nonce (§10.3: verified with the explicit null nonce)" "<absent>" "$(claim "$t" nonce)"; fi
  check "$4: at_hash binds the access token from the same response (§2.4, M3)" "$(at_hash_of "$2")" "$(claim "$t" at_hash)"
  contract "$4: no azp (§2.4)" "<absent>" "$(claim "$t" azp)"
  contract "$4: no sid (§2.4)" "<absent>" "$(claim "$t" sid)"
  # "ok" only from a payload that decoded to claims and none of them missing: an
  # empty token, a payload that does not decode or an unreadable discovery
  # document make jq print nothing or "no claims", and those must not pass.
  contract "$4: every claim it carries is in discovery's claims_supported (§6 P1.8)" ok \
    "$(jwt_part "$t" 1 | jq -r --slurpfile d "$TMP/discovery.json" \
        'if (keys | length) == 0 then "no claims" else
           [keys[] | select(. as $k | ($d[0].claims_supported // []) | index($k) == null)]
           | if length == 0 then "ok" else "not listed: " + join(" ") end
         end')"
  got "$4 claims: $(jwt_part "$t" 1 | jq -c 'keys')"
}
idtoken_checks "$IDT1" "$AT1" "$NONCE" "sign-in ID token"
SUB1="$(claim "$IDT1" sub)"; AUTH_TIME1="$(claim "$IDT1" auth_time)"
[ -n "$SUB1" ] && [ "$SUB1" != "<absent>" ] && ok "sub is present ($SUB1)" || fail "sub is present" "$SUB1"
got "auth_time=$AUTH_TIME1 amr=$(claim "$IDT1" amr) preferred_username=$(claim "$IDT1" preferred_username) email=$(claim "$IDT1" email)"
contract "the ID token lives as long as the access token (trap 7)" "$EXPIRES" "$(( $(claim "$IDT1" exp) - $(claim "$IDT1" iat) ))"

# ==========================================================================
section "6. Refresh and rotation (§10.3, §2.3)"
form_post "$TOKEN" grant_type=refresh_token "refresh_token=$RT1" "client_id=$CLIENT_ID"
require "POST token_endpoint (refresh_token, no secret)" 200 "$STATUS"
AT2="$(jq -r '.access_token // empty' "$BODY")"; RT2="$(jq -r '.refresh_token // empty' "$BODY")"; IDT2="$(jq -r '.id_token // empty' "$BODY")"
got "fields: $(jq -c 'keys' "$BODY"), expires_in=$(jq -r .expires_in "$BODY")"
[ -n "$RT2" ] && [ "$RT2" != "$RT1" ] && ok "a new refresh token replaces the old one (rotation)" || fail "a new refresh token" "got '${RT2:0:12}…'"
[ -n "$AT2" ] && [ "$AT2" != "$AT1" ] && ok "a new access token" || fail "a new access token" "none or unchanged"
if [ -n "$IDT2" ]; then
  idtoken_checks "$IDT2" "$AT2" "" "refresh ID token"
  check "refresh ID token: sub unchanged (OIDC Core §12.2)" "$SUB1" "$(claim "$IDT2" sub)"
  contract "refresh ID token: auth_time inherited, not restamped (§2.4, trap 8)" "$AUTH_TIME1" "$(claim "$IDT2" auth_time)"
else
  diff_ "a refresh mints an ID token (§10.3 verifies one)" "none in the response"
fi

# The spent token again, at once: §2.3 says the request fails and, with no
# spent successor, the family is left alone (refresh_token_retry).
form_post "$TOKEN" grant_type=refresh_token "refresh_token=$RT1" "client_id=$CLIENT_ID"
check "the spent refresh token is refused" 400 "$STATUS"
check "…as invalid_grant (§10.3: terminal)" invalid_grant "$(jq -r '.error // empty' "$BODY")"
got "error_description: $(jq -r '.error_description // "<none>"' "$BODY")"
form_post "$TOKEN" grant_type=refresh_token "refresh_token=$RT2" "client_id=$CLIENT_ID"
contract "the family survives a replay inside 60 s: its live token still refreshes (§2.3)" 200 "$STATUS"
RT3="$(jq -r '.refresh_token // empty' "$BODY")"; AT3="$(jq -r '.access_token // empty' "$BODY")"
[ -n "$RT3" ] || RT3="$RT2"

# ==========================================================================
section "7. Revocation (§10.4)"
AT_LIVE="${AT3:-$AT2}"
if [ -n "$USERINFO" ]; then
  req GET "$USERINFO" -H "Authorization: Bearer $AT_LIVE"
  check "userinfo accepts the family's live access token (the control for the line below)" 200 "$STATUS"
fi
form_post "$REVOKE" "token=$RT3" token_type_hint=refresh_token "client_id=$CLIENT_ID"
check "POST revocation_endpoint as a public client (token_type_hint=refresh_token, no secret)" 200 "$STATUS"
form_post "$TOKEN" grant_type=refresh_token "refresh_token=$RT3" "client_id=$CLIENT_ID"
check "the revoked refresh token no longer refreshes" 400/invalid_grant "$STATUS/$(jq -r '.error // empty' "$BODY")"
if [ -n "$USERINFO" ]; then
  req GET "$USERINFO" -H "Authorization: Bearer $AT_LIVE"
  got "userinfo with that access token after the revocation: HTTP $STATUS (§10.4 names only the refresh token)"
fi

# ==========================================================================
section "8. Other §2 and §10 claims the SDK depends on"
err_of() { printf '%s/%s' "$STATUS" "$(jq -r '.error // empty' "$BODY" 2>/dev/null)"; }
# A new code on the browser session from step 3 — silent, because the client
# is first-party (and a public client is not asked to consent again; M7).
new_code() { # sets NC_CODE and NC_VERIFIER
  local c
  NC_VERIFIER="$(rand_b64u)"; c="$(printf '%s' "$NC_VERIFIER" | openssl dgst -sha256 -binary | b64u)"
  req GET "$(authz_url "$REDIRECT_URI" "$c" S256)" --cookies
  NC_CODE=""
  case "$STATUS $LOCATION" in "303 $REDIRECT_URI?"*code=*) NC_CODE="$(urldecode "$(qparam "$LOCATION" code)")" ;; esac
}
exchange() { # $1=code $2=verifier [$3=redirect_uri]
  form_post "$TOKEN" grant_type=authorization_code "code=$1" "redirect_uri=${3:-$REDIRECT_URI}" "client_id=$CLIENT_ID" "code_verifier=$2"
}
refresh() { form_post "$TOKEN" grant_type=refresh_token "refresh_token=$1" "client_id=$CLIENT_ID"; }
rt_of() { jq -r '.refresh_token // empty' "$BODY"; }

new_code
[ -n "$NC_CODE" ] && ok "a second sign-in on a live browser session is silent (303 straight to the app)" \
  || fail "a second sign-in on a live browser session is silent" "HTTP $STATUS → $LOCATION"
exchange "$NC_CODE" "$NC_VERIFIER" "https://live.proteles.test/other"
contract "the token endpoint refuses a redirect_uri other than the authorization request's (§2.1)" 400/invalid_grant "$(err_of)"
got "error_description: $(jq -r '.error_description // "<none>"' "$BODY")"

new_code
exchange "$NC_CODE" "$(rand_b64u)"
contract "the token endpoint refuses the wrong code_verifier (§2.2: redemption re-checks)" 400/invalid_grant "$(err_of)"
got "error_description: $(jq -r '.error_description // "<none>"' "$BODY")"
exchange "$NC_CODE" "$NC_VERIFIER"
got "the same code with the right verifier afterwards: $(err_of) (a failed redemption $( [ "$STATUS" = 200 ] && echo 'does not spend' || echo 'spends') the code)"

exchange "$CODE" "$VERIFIER"
check "the step-5 code, replayed, is refused" 400/invalid_grant "$(err_of)"

# §2.3's first outcome: presenting a token whose successor is already spent
# burns the whole family (refresh_token_reuse).
new_code; exchange "$NC_CODE" "$NC_VERIFIER"; A1="$(rt_of)"
refresh "$A1"; A2="$(rt_of)"; refresh "$A2"; A3="$(rt_of)"
if [ -n "$A1" ] && [ -n "$A2" ] && [ -n "$A3" ]; then
  refresh "$A1"
  check "a token whose successor is spent is refused" 400/invalid_grant "$(err_of)"
  refresh "$A3"
  contract "…and burns the family: its live token is dead too (§2.3 refresh_token_reuse)" 400/invalid_grant "$(err_of)"
else
  fail "a family three rotations long" "A1=${A1:0:8} A2=${A2:0:8} A3=${A3:0:8}"
fi

# §10.9 item 6 relies on this: revoking a *spent* member ends the family.
new_code; exchange "$NC_CODE" "$NC_VERIFIER"; B1="$(rt_of)"
refresh "$B1"; B2="$(rt_of)"
if [ -n "$B1" ] && [ -n "$B2" ]; then
  form_post "$REVOKE" "token=$B1" token_type_hint=refresh_token "client_id=$CLIENT_ID"
  check "revoking a spent refresh token is accepted" 200 "$STATUS"
  refresh "$B2"
  contract "…and ends its family: the live token no longer refreshes (§10.9 item 6)" 400/invalid_grant "$(err_of)"
else
  fail "a family two rotations long" "B1=${B1:0:8} B2=${B2:0:8}"
fi

# §2.1: an unregistered redirect is a 400 page, never a redirect.
req GET "$(authz_url "https://live.proteles.test/other" "$(rand_b64u)" S256)" --cookies
contract "an unregistered redirect_uri gets a non-redirecting 400 (§2.1)" "400 " "$STATUS $LOCATION"

# §2.2: exactly 43 characters, S256 only, no default method, and a challenge
# required of a public client. §2.5: RFC 9207's iss on every authorization
# response, errors included.
pkce_refusal() { # $1=label $2=challenge ("" = omit, with the method) $3=method ("" = omit)
  local u err iss
  u="$(authz_url "$REDIRECT_URI" "$2" "$3")"
  [ -z "$2" ] && u="$(printf '%s' "$u" | sed 's/&code_challenge=[^&]*//; s/&code_challenge_method=[^&]*//')"
  req GET "$u" --cookies
  err="$(qparam "$LOCATION" error)"; iss="$(urldecode "$(qparam "$LOCATION" iss)")"
  case "$STATUS $LOCATION" in
    "303 $REDIRECT_URI?"*error=*)
      ok "$1 is refused ($err, redirected to the app)"
      got "error_description: $(urldecode "$(qparam "$LOCATION" error_description)")"
      contract "…and that error response carries iss (§2.5)" "$ISSUER" "$iss" ;;
    "400 "*) ok "$1 is refused (non-redirecting 400)" ;;
    *) diff_ "$1 is refused (§2.2)" "HTTP $STATUS → ${LOCATION:-<no Location>}" ;;
  esac
}
C_OK="$(rand_b64u)"
pkce_refusal "a 64-character challenge" "$(openssl rand 48 | b64u)" S256
pkce_refusal "an absent code_challenge_method" "$C_OK" ""
pkce_refusal "code_challenge_method=plain" "$C_OK" plain
pkce_refusal "no code_challenge from a public client" "" ""

# Only when run-live.sh exposed a management token: the seeded client's shape
# through the door that validates it — admin-cli does not run §2.1's rule.
if [ -n "$MGMT_TOKEN" ]; then
  mk_app() { # $1=redirect uri
    jq -nc --arg r "$1" '{tenant_id:"00000000-0000-0000-0000-000000000001",
      client_name:"curl-check probe", token_endpoint_auth_method:"none", redirect_uris:[$r],
      grant_types:["authorization_code","refresh_token"], scopes:["openid","profile","email"], first_party:true}'
  }
  mgmt() { req "$1" "$ISSUER$2" -H "Authorization: Bearer $MGMT_TOKEN" -H 'Content-Type: application/json' "${@:3}"; }
  mgmt POST /api/v1/apps -d "$(mk_app "$REDIRECT_URI")"
  contract "the management API registers a public client with this redirect (§2.1, M4)" 201 "$STATUS"
  PROBE_ID="$(jq -r '.client_id // empty' "$BODY")"
  mgmt GET "/api/v1/apps?tenant_id=00000000-0000-0000-0000-000000000001"
  got "as listed: $(jq -c --arg c "$PROBE_ID" '.apps[] | select(.client_id==$c) | {client_type, first_party, redirect_uris, grant_types}' "$BODY")"
  got "the harness's own client, as listed: $(jq -c --arg c "$CLIENT_ID" '.apps[] | select(.client_id==$c) | {client_type, first_party, redirect_uris, grant_types}' "$BODY")"
  mgmt POST /api/v1/apps -d "$(mk_app "com.proteles.live:/callback")"
  contract "…and refuses a private-use scheme, reverse-DNS included (§2.1, M7)" 400 "$STATUS"
else
  skip "registrability through the management API" "PROTELES_LIVE_MANAGEMENT_TOKEN unset"
fi

# ==========================================================================
# §2.3's third outcome needs the 60-second window to pass, so it is opt-in.
if [ "${CURL_CHECK_SLOW:-0}" = 1 ]; then
  section "9. A spent token presented after 60 s (§2.3; CURL_CHECK_SLOW=1)"
  new_code; exchange "$NC_CODE" "$NC_VERIFIER"; X1="$(rt_of)"; refresh "$X1"; X2="$(rt_of)"
  new_code; exchange "$NC_CODE" "$NC_VERIFIER"; Y1="$(rt_of)"
  form_post "$REVOKE" "token=$Y1" token_type_hint=refresh_token "client_id=$CLIENT_ID"
  got "rotated X1 → X2, revoked Y1 (HTTP $STATUS); waiting 61 s"
  sleep 61
  refresh "$X1"
  check "a rotated token presented after 60 s is refused" 400/invalid_grant "$(err_of)"
  refresh "$X2"
  contract "…and burns its family: the unspent successor is dead too (§2.3, refresh_token_reuse)" 400/invalid_grant "$(err_of)"
  refresh "$Y1"
  check "a token the client itself revoked, presented after 60 s, is refused" 400/invalid_grant "$(err_of)"
  got "(the audit trail's reading of these two is in the database: event_type refresh_token.*)"
fi

section "10. Ending the browser session (§10.4)"
# §10.4's second half, last because it ends the browser session: GET confirms,
# POST acts, then the browser lands on the app.
if [ -n "$END_SESSION" ] && [ -n "$POST_LOGOUT" ]; then
  # A family minted from this browser session, to see what ending it does.
  new_code; exchange "$NC_CODE" "$NC_VERIFIER"; L1="$(rt_of)"
  [ -n "$L1" ] && ok "a refresh family minted from the browser session about to end" || fail "a refresh family from the browser session" "$(err_of)"
  LSTATE="$(rand_b64u)"
  req GET "$END_SESSION?id_token_hint=${IDT2:-$IDT1}&client_id=$CLIENT_ID&post_logout_redirect_uri=$(jq -rn --arg v "$POST_LOGOUT" '$v|@uri')&state=$LSTATE" --cookies
  check "end_session_endpoint (id_token_hint, client_id, post_logout_redirect_uri, state) asks for confirmation" 200 "$STATUS"
  cp "$BODY" "$TMP/end.html"
  fields=()
  while IFS= read -r input; do
    n="$(printf '%s' "$input" | sed -n 's/.*name="\([^"]*\)".*/\1/p')"
    v="$(printf '%s' "$input" | sed -n 's/.*value="\([^"]*\)".*/\1/p' | sed 's/&amp;/\&/g; s/&#x2F;/\//g; s/&#47;/\//g; s/&quot;/"/g; s/&#39;/'"'"'/g; s/&lt;/</g; s/&gt;/>/g')"
    [ -n "$n" ] && fields+=(--data-urlencode "$n=$v")
  done < <(sed -n '/<form[^>]*action="\/oauth\/logout"/,/<\/form>/p' "$TMP/end.html" | grep -o '<input[^>]*type="hidden"[^>]*>')
  got "the confirmation form carries: $(printf '%s ' "${fields[@]}" | grep -o '[a-z_]*=' | tr -d '=' | tr '\n' ' ')"
  req POST "$END_SESSION" --cookies "${fields[@]}"
  check "confirming sends the browser back to the app, through the page that moves on (200)" 200 "$STATUS"
  case "$LOCATION" in "$POST_LOGOUT?"*|"$POST_LOGOUT") ok "…to $POST_LOGOUT" ;; *) fail "…to $POST_LOGOUT" "Location: $LOCATION" ;; esac
  check "…with the state that was sent" "$LSTATE" "$(urldecode "$(qparam "$LOCATION" state)")"
  req GET "$(authz_url "$REDIRECT_URI" "$(rand_b64u)" S256)" --cookies
  case "$STATUS $LOCATION" in "303 /login"*|"303 $ISSUER/login"*) ok "the browser session is over: the next sign-in shows the login page" ;;
    *) fail "the browser session is over" "authorize → HTTP $STATUS $LOCATION" ;; esac
  if [ -n "$L1" ]; then
    refresh "$L1"
    contract "the app's refresh family outlives /oauth/logout (M5, trap 10: it ends the browser cookie only)" 200 "$STATUS"
    [ "$STATUS" = 200 ] || got "error_description: $(jq -r '.error_description // "<none>"' "$BODY")"
    L2="$(rt_of)"
    [ -n "$L2" ] && form_post "$REVOKE" "token=$L2" token_type_hint=refresh_token "client_id=$CLIENT_ID"
  fi
fi

summary
[ "$FAILS" -eq 0 ]
