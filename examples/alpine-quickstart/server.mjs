// The whole backend: serve the page, the SDK bundle, and /api/auth/*.
//
// Alpine has no meta-framework, so there's nothing to plug into — this is a
// plain node:http server. @proteles/bff does the OAuth work, and its
// toWebRequest/sendNodeResponse helpers bridge Node's req/res to the Web
// Request/Response the AuthApp speaks. Any Node backend (Express, Fastify, Koa)
// wires up the same way.

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { AuthApp, sendNodeResponse, toWebRequest } from "@proteles/bff";

const here = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT ?? 3500);

// Reads PROTELES_* from the environment; see .env.example.
const auth = new AuthApp();

const files = {
  "/": { file: path.join(here, "public", "index.html"), type: "text/html; charset=utf-8" },
  "/proteles-alpine.js": {
    // Served from node_modules so the page needs no build step. In production
    // you'd use the CDN URL instead (see index.html).
    file: path.join(here, "node_modules", "@proteles", "alpine", "dist", "proteles-alpine.js"),
    type: "text/javascript; charset=utf-8",
  },
};

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
  const url = new URL(req.url ?? "/", `http://localhost:${port}`);

  if (url.pathname.startsWith("/api/auth/")) {
    const response = await auth.handle(toWebRequest({ node: { req } }));
    await sendNodeResponse(res, response);
    return;
  }

  const asset = files[url.pathname];
  if (asset && fs.existsSync(asset.file)) {
    res.statusCode = 200;
    res.setHeader("content-type", asset.type);
    res.end(fs.readFileSync(asset.file));
    return;
  }

  // Anything else: this demo has one page.
  res.statusCode = 404;
  res.end("not found");
}

server.listen(port, () => {
  console.log(`proteles alpine quickstart on http://localhost:${port}`);
});
