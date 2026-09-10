import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createProvider } from "./provider.mjs";
import { fixtureRead } from "./fixtures.mjs";
const root = path.dirname(fileURLToPath(import.meta.url));
export function createServer(provider, { fixture = false } = {}) {
  return http.createServer(async (req, res) => {
    const port = req.socket.localPort;
    const hosts = [`127.0.0.1:${port}`, `localhost:${port}`];
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
    );
    const json = (status, body) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (
      !hosts.includes(req.headers.host) ||
      (req.headers.origin &&
        !hosts.some((h) => req.headers.origin === `http://${h}`)) ||
      req.headers["sec-fetch-site"] === "cross-site"
    )
      return json(403, { error: "Local same-origin access only" });
    if (req.method !== "GET") return json(405, { error: "Read-only console" });
    let url;
    try {
      url = new URL(req.url, `http://${req.headers.host}`);
    } catch {
      return json(400, { error: "Invalid URL" });
    }
    try {
      if (url.pathname === "/api/health")
        return json(200, {
          mode: fixture ? "SYNTHETIC" : "AWS_READ_ONLY",
          region: "ap-southeast-1",
          environments: ["DEV", "PROD"],
        });
      if (url.pathname.startsWith("/api/")) {
        const environment = url.searchParams.get("environment");
        if (!["DEV", "PROD"].includes(environment))
          return json(400, { error: "Choose DEV or PROD" });
        if (url.pathname === "/api/controls")
          return json(
            200,
            await provider.list(
              environment,
              url.searchParams.get("refresh") === "1",
            ),
          );
        if (url.pathname === "/api/resources") {
          const name = url.searchParams.get("rule"),
            token = url.searchParams.get("token");
          if (!name || name.length > 256 || (token && token.length > 8192))
            return json(400, { error: "Invalid rule or page token" });
          return json(200, await provider.details(environment, name, token));
        }
        return json(404, { error: "Not found" });
      }
      const relative =
        url.pathname === "/" ? "index.html" : url.pathname.slice(1);
      const target = path.resolve(root, "dist", relative);
      if (!target.startsWith(path.join(root, "dist") + path.sep))
        return json(404, { error: "Not found" });
      const data = await readFile(target);
      const mime =
        {
          ".html": "text/html",
          ".js": "text/javascript",
          ".css": "text/css",
          ".svg": "image/svg+xml",
        }[path.extname(target)] || "application/octet-stream";
      res.writeHead(200, { "Content-Type": mime });
      res.end(data);
    } catch (error) {
      // Never send CLI stderr (may contain private identities) to the client/log.
      const status =
        error.code === "ENOENT" && !url.pathname.startsWith("/api/")
          ? 404
          : 502;
      json(status, {
        error:
          status === 404
            ? "Not found"
            : "Provider read failed. Check selected profile authorization locally; no login or fallback was attempted.",
      });
    }
  });
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const port = Number(process.env.PORT || 2231);
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || port === 2222)
    throw Error("Use a free experiment port (default 2231), never SecCop 2222");
  const fixture = process.argv.includes("--fixture");
  const server = createServer(
    createProvider(fixture ? fixtureRead : undefined),
    { fixture },
  );
  server.on("error", () => {
    console.error("Listener unavailable; no existing process was stopped.");
    process.exitCode = 1;
  });
  server.listen(port, "127.0.0.1", () =>
    console.log(
      `Config console http://localhost:${port}/ · ${fixture ? "SYNTHETIC" : "AWS READ ONLY"}`,
    ),
  );
}
