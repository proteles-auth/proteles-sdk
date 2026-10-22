# @proteles/express

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

Express bindings for the Proteles Backend-for-Frontend. Tokens stay on the
server; the browser holds an encrypted session cookie and nothing else.

```bash
npm install @proteles/express
```

```ts
import express from "express";
import { protelesAuth, requireAuth, userOf } from "@proteles/express";

const app = express();

// Serves /api/auth/login, /signup, /callback, /logout, /me, /revalidate, and
// attaches the session to every other request.
app.use(protelesAuth());

app.get("/dashboard", requireAuth(), (req, res) => {
  res.send(`hello ${userOf(req)?.preferredUsername}`);
});
```

Configuration comes from the environment (`PROTELES_ISSUER`,
`PROTELES_CLIENT_ID`, `PROTELES_SESSION_SECRET`, `PROTELES_APP_URL`) or from an
object passed to either function. See `@proteles/bff` for the full list.

`/api/auth/signup` is `/login` opening on the workspace's hosted sign-up page,
which signs the new person in and brings them back to `returnTo`. Where the
workspace has not opened that page, the person sees the ordinary sign-in page.
See [`@proteles/bff`](https://www.npmjs.com/package/@proteles/bff#sign-up).

## Three things worth knowing

**Mount `protelesAuth()` before any body parser.** None of the auth routes reads
a request body — which is why the bridge does not stream one — but a parser that
has already consumed the stream is a surprise waiting for the day one of them
starts to.

**`requireAuth()` redirects browsers and answers XHR with 401.** A request
asking for JSON that is redirected to a login page receives an HTML document
where it expected data, and reports "the API returned garbage" rather than
"I am signed out".

**A session that only needs a refresh is refreshed, not sent to log in.** A
browser whose access token has expired goes through `/api/auth/revalidate` and
straight back; a JSON caller is refreshed in place. While the authorization
server is busy, the browser gets a `503` "try again" page and the JSON caller
`503 {"error":"temporarily_unavailable"}` with the server's `Retry-After` — the
session is kept either way (see
[`@proteles/bff`](https://www.npmjs.com/package/@proteles/bff#when-the-authorization-server-is-busy)).

## Inviting people into your app

Register `<your app>/api/auth/login` as the app's sign-in start address (its
`initiate_login_uri`). An invitation sent through the Management API with the
app's `client_id` then sends the person who accepts it to that route with `iss`,
and the sign-in it starts finds the account they just made already signed in.
The route checks `iss` against `PROTELES_ISSUER` and always signs in at
`PROTELES_ISSUER`, whatever `iss` names.

## License

MIT
