// A complete htmx app with authentication. There is no client-side auth code at
// all — the server renders the right HTML, which is the htmx way.
//
// Three things worth reading:
//   * /api/auth/*      handed straight to protelesAuthHandler
//   * /fragments/user   an auth-aware fragment, guarded by requireUser
//   * /dashboard        a protected page, guarded by guardRequest
//
// Every guard answers `HX-Redirect` when the caller is htmx, so an
// unauthenticated fragment request navigates the browser to login instead of
// swapping the login page into an hx-target.

import http from "node:http";

import {
  getUser,
  guardRequest,
  protelesAuthHandler,
  requireUser,
  sendNodeResponse,
} from "@proteles/htmx";

const port = Number(process.env.PORT ?? 3600);

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
    <title>Proteles htmx quickstart</title>
    <script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js"></script>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 640px; margin: 64px auto; padding: 0 16px; color-scheme: light dark; }
      button { font: inherit; font-weight: 600; padding: 8px 14px; border: 0; border-radius: 8px; background: #4f46e5; color: #fff; cursor: pointer; }
      .muted { opacity: .7; font-size: .9rem; }
    </style>
  </head>
  <body>${body}</body>
</html>`;

/** The auth-aware fragment. htmx loads it on page load and after auth events. */
const userFragment = (user) =>
  user
    ? `<div id="user">
         <p>Hi <strong>${escape(user.email ?? user.preferredUsername ?? user.sub)}</strong> 👋</p>
         <button hx-post="/api/auth/logout">Sign out</button>
         <p class="muted">Tokens live in an encrypted, httpOnly cookie — <code>document.cookie</code> is empty.</p>
       </div>`
    : `<div id="user">
         <p>You are signed out.</p>
         <button hx-get="/api/auth/login">Sign in</button>
       </div>`;

const homePage = `
  <h1>Proteles htmx quickstart</h1>
  <p class="muted">No client-side auth code: the server renders auth-aware fragments.</p>

  <!-- Loaded on page load, and re-loaded whenever auth changes. -->
  <div id="user" hx-get="/fragments/user" hx-trigger="load, proteles:auth-changed from:body" hx-swap="outerHTML">
    <p class="muted">Loading…</p>
  </div>

  <p><a href="/dashboard">Protected page</a> ·
     <button hx-get="/fragments/secret" hx-target="#secret" hx-swap="innerHTML">Load a protected fragment</button></p>
  <div id="secret"></div>
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

  // 1. The four auth routes. protelesAuthHandler turns its redirects into
  //    HX-Redirect for htmx callers (notably the hx-post logout).
  if (url.pathname.startsWith("/api/auth/")) {
    return sendNodeResponse(res, await protelesAuthHandler(event));
  }

  // 2. Protected pages. The guard is htmx-aware, so a boosted link works too.
  if (url.pathname === "/dashboard") {
    const redirect = await guardRequest(event, { publicPaths: ["/"] });
    if (redirect) return sendNodeResponse(res, redirect);
    const user = await getUser(event);
    return html(
      res,
      layout(`<h1>Dashboard</h1>
        <p>Signed in as <strong>${escape(user?.email ?? user?.sub)}</strong>.</p>
        <p>Only reachable when authenticated.</p>
        <button hx-post="/api/auth/logout">Sign out</button>
        <p><a href="/">← Home</a></p>`),
    );
  }

  // 3. An auth-aware fragment: renders either branch, no guard needed.
  if (url.pathname === "/fragments/user") {
    return html(res, userFragment(await getUser(event)));
  }

  // 4. A fragment that requires a user. Without the HX-Redirect conversion this
  //    is exactly where htmx would inject the login page into #secret.
  if (url.pathname === "/fragments/secret") {
    const auth = await requireUser(event);
    if (auth.response) return sendNodeResponse(res, auth.response);
    return html(res, `<p>🔒 Secret for <strong>${escape(auth.user.email ?? auth.user.sub)}</strong>.</p>`);
  }

  if (url.pathname === "/") return html(res, layout(homePage));

  html(res, "not found", 404);
}

server.listen(port, () => {
  console.log(`proteles htmx quickstart on http://localhost:${port}`);
});
