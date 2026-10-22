// A complete Alpine AJAX app with authentication. There is no client-side auth
// code at all — the server renders the right HTML, which is the point of
// choosing a hypermedia library.
//
// Four things worth reading:
//   * /api/auth/*         handed straight to protelesAuthHandler
//   * the sign-in link     carries NO x-target — see below
//   * /fragments/user      an auth-aware fragment, needs no guard
//   * /fragments/secret    a guarded fragment, answered with a 401 Alpine merges
//
// The rule that makes this work: **signing in is a navigation.** Alpine AJAX
// cannot be told by the server to navigate — `fetch` follows redirects
// transparently and no response header changes that — so the sign-in control
// must not be an AJAX control in the first place. Guarded *content* is
// different: it gets a 401 whose body is addressed to the requested target, and
// Alpine merges that in place because it merges bodies on error statuses too.

import http from "node:http";

import { sendNodeResponse } from "@proteles/bff";
import {
  getUser,
  guardRequest,
  protelesAuthHandler,
  requireUser,
} from "@proteles/alpine-ajax";

const port = Number(process.env.PORT ?? 3700);

const html = (res, body, status = 200) => {
  res.statusCode = status;
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.end(body);
};

const escape = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const layout = (body) => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Proteles Alpine AJAX quickstart</title>
    <script defer src="https://cdn.jsdelivr.net/npm/@imacrayon/alpine-ajax@0.12.2/dist/cdn.min.js"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.8/dist/cdn.min.js"></script>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 640px; margin: 64px auto; padding: 0 16px; color-scheme: light dark; }
      button, .btn { font: inherit; font-weight: 600; padding: 8px 14px; border: 0; border-radius: 8px; background: #4f46e5; color: #fff; cursor: pointer; text-decoration: none; display: inline-block; }
      .muted { opacity: .7; font-size: .9rem; }
      [id] { scroll-margin-top: 1rem; }
    </style>
  </head>
  <body>${body}</body>
</html>`;

/** The auth-aware fragment. Renders either branch, so it needs no guard. */
const userFragment = (user) =>
  user
    ? `<div id="user">
         <p>Hi <strong>${escape(user.email ?? user.preferredUsername ?? user.sub)}</strong> 👋</p>
         <!-- No x-target: signing out ends with a navigation, same as signing in. -->
         <form method="post" action="/api/auth/logout"><button>Sign out</button></form>
         <p class="muted">Tokens live in an encrypted, httpOnly cookie — <code>document.cookie</code> is empty.</p>
       </div>`
    : `<div id="user">
         <p>You are signed out.</p>
         <!-- A plain link. An x-target here would fetch the authorization
              server's sign-in page and merge it into this div. -->
         <a class="btn" href="/api/auth/login">Sign in</a>
       </div>`;

const homePage = `
  <h1>Proteles Alpine AJAX quickstart</h1>
  <p class="muted">No client-side auth code: the server renders auth-aware fragments.</p>

  <!-- Loaded on page load: $ajax fetches the fragment and merges the element
       whose id matches this one's. (Alpine AJAX has no x-load attribute; an
       earlier version of this page used one, and the page never left
       "Loading…".) -->
  <div id="user" x-init="$ajax('/fragments/user')">
    <p class="muted">Loading…</p>
  </div>

  <p><a href="/dashboard">Protected page</a></p>

  <!-- The interesting case. Unauthenticated, this gets a 401 whose body carries
       id="secret" — so the message lands here rather than the login page
       landing here. -->
  <div id="secret">
    <a href="/fragments/secret" x-target="secret">Load a protected fragment</a>
  </div>
`;

// The handler's promise is caught here. `node:http` drops whatever a request
// listener returns, and Node exits on an unhandled rejection — so one request
// that throws anywhere below would otherwise take the whole server down.
const server = http.createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error(err);
    if (res.headersSent) return res.destroy();
    res.statusCode = 500;
    res.end("Internal Server Error");
  });
});

async function route(req, res) {
  const event = { node: { req } };
  const url = new URL(req.url ?? "/", `http://localhost:${port}`);

  // 1. The four auth routes. Their redirects stay redirects: login and callback
  //    are genuine browser navigations to and from the authorization server.
  if (url.pathname.startsWith("/api/auth/")) {
    return sendNodeResponse(res, await protelesAuthHandler(event));
  }

  // 2. A protected page. Reached by navigation, so this is an ordinary redirect.
  if (url.pathname === "/dashboard") {
    const stop = await guardRequest(event, { publicPaths: ["/"] });
    if (stop) return sendNodeResponse(res, stop);
    const user = await getUser(event);
    return html(
      res,
      layout(`<h1>Dashboard</h1>
        <p>Signed in as <strong>${escape(user?.email ?? user?.sub)}</strong>.</p>
        <p>Only reachable when authenticated.</p>
        <form method="post" action="/api/auth/logout"><button>Sign out</button></form>
        <p><a href="/">← Home</a></p>`),
    );
  }

  // 3. An auth-aware fragment: renders either branch, no guard needed.
  if (url.pathname === "/fragments/user") {
    return html(res, userFragment(await getUser(event)));
  }

  // 4. A fragment that requires a user. Without this package, an unauthenticated
  //    request here would be redirected, `fetch` would follow it, and the login
  //    page would be merged into #secret.
  if (url.pathname === "/fragments/secret") {
    const auth = await requireUser(event);
    if (auth.response) return sendNodeResponse(res, auth.response);
    return html(
      res,
      `<div id="secret"><p>🔒 Secret for <strong>${escape(auth.user.email ?? auth.user.sub)}</strong>.</p></div>`,
    );
  }

  if (url.pathname === "/") return html(res, layout(homePage));

  html(res, "not found", 404);
}

server.listen(port, () => {
  console.log(`proteles alpine-ajax quickstart on http://localhost:${port}`);
});
