import http from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createProvider } from "./provider.mjs";
import { fixtureRead } from "./fixtures.mjs";
import { createMultiAccountProvider, fourAccountFixtureRead } from "./multi-account.mjs";
import { createOrgAggregatorProvider } from "./org-aggregator.mjs";
import { createHistoryStore, createMemoryHistoryStore } from "./history.mjs";
import { createDemoAdmin, createDemoJobStore, CONTROLS as DEMO_CONTROLS } from "./demo-admin.mjs";
import { createDemoAuditStore } from "./demo-audit.mjs";
const root = path.dirname(fileURLToPath(import.meta.url));
export function createServer(provider, { fixture = false, historyStore = createMemoryHistoryStore(), demoAdmin = null } = {}) {
  const environments = provider.environments || ["DEV", "PROD"];
  const allAccounts = provider.allAccounts === true;
  const confirmations = new Map();
  const readBody = async (req) => {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 8192) throw Error("request body too large");
      chunks.push(chunk);
    }
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    if (!value || typeof value !== "object" || Array.isArray(value)) throw Error("invalid request body");
    return value;
  };
  const previewDemo = async (control) => {
    if (!demoAdmin || !DEMO_CONTROLS.includes(control)) throw Error("demo control unavailable");
    const snapshot = await provider.list("ALL", true);
    if (snapshot.partial || snapshot.availableAccounts !== 4 || snapshot.totalAccounts !== 4)
      throw Error("all four LAB accounts must be readable before demo re-arm");
    const rows = snapshot.rules.filter((rule) => rule.ConfigRuleName === control);
    const aliases = rows.map((rule) => rule.accountAlias).sort();
    const expected = [...environments].sort();
    if (rows.length !== 4 || JSON.stringify(aliases) !== JSON.stringify(expected))
      throw Error("four-account control evidence is incomplete");
    const now = Date.now();
    for (const [key, value] of confirmations)
      if (value.expiresAt < now) confirmations.delete(key);
    while (confirmations.size >= 32) confirmations.delete(confirmations.keys().next().value);
    const token = randomUUID();
    confirmations.set(token, { control, expiresAt: now + 120000 });
    await demoAdmin.audit({
      event: "PREVIEW_CREATED",
      control,
      state: "PENDING_CONFIRMATION",
      messageCode: "FOUR_ACCOUNT_EVIDENCE_VERIFIED",
    });
    return {
      control,
      confirmationToken: token,
      aliases: environments,
      current: rows.map((rule) => ({ alias: rule.accountAlias, status: rule.status })),
      targetState: "NON_COMPLIANT",
      resourceCount: 4,
      note: "Exactly one retained Issue #82 demo resource per registered LAB account.",
    };
  };
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
    let url;
    try {
      url = new URL(req.url, `http://${req.headers.host}`);
    } catch {
      return json(400, { error: "Invalid URL" });
    }
    try {
      if (req.method === "POST" && url.pathname === "/api/demo/preview") {
        if (!demoAdmin || fixture) return json(403, { error: "Demo controls unavailable" });
        const body = await readBody(req);
        return json(200, await previewDemo(body.control));
      }
      if (req.method === "POST" && url.pathname === "/api/demo/rearm") {
        if (!demoAdmin || fixture) return json(403, { error: "Demo controls unavailable" });
        const body = await readBody(req);
        const item = confirmations.get(body.confirmationToken);
        confirmations.delete(body.confirmationToken);
        if (!item || item.control !== body.control || item.expiresAt < Date.now()) {
          await demoAdmin.audit({
            event: "CONFIRMATION_REJECTED",
            control: DEMO_CONTROLS.includes(body.control) ? body.control : null,
            state: "REJECTED",
            messageCode: "CONFIRMATION_INVALID",
          });
          return json(409, { error: "Demo confirmation expired or mismatched" });
        }
        await demoAdmin.audit({
          event: "CONFIRMATION_ACCEPTED",
          control: item.control,
          state: "RUNNING",
          messageCode: "CONFIRMATION_ACCEPTED",
        });
        return json(202, await demoAdmin.start(item.control));
      }
      if (req.method !== "GET") return json(405, { error: "Unsupported method" });
      if (url.pathname.startsWith("/api/demo/jobs/")) {
        if (!demoAdmin || fixture) return json(403, { error: "Demo controls unavailable" });
        const jobId = decodeURIComponent(url.pathname.slice("/api/demo/jobs/".length));
        if (!/^[0-9a-f-]{36}$/i.test(jobId)) return json(400, { error: "Invalid demo job" });
        const job = await demoAdmin.status(jobId);
        return job ? json(200, job) : json(404, { error: "Demo job not found" });
      }
      if (url.pathname === "/api/demo/audit") {
        if (!demoAdmin || fixture) return json(403, { error: "Demo controls unavailable" });
        const limit = Math.max(1, Math.min(200, Number(url.searchParams.get("limit")) || 100));
        return json(200, { events: await demoAdmin.auditList(limit) });
      }
      if (url.pathname === "/api/health")
        return json(200, {
          mode: fixture ? "SYNTHETIC" : "AWS_READ_ONLY",
          region: "ap-southeast-1",
          environments,
          allAccounts,
          demoControls: Boolean(demoAdmin && !fixture),
          demoJobMode: demoAdmin && !fixture ? "async-single-flight" : "disabled",
          demoJobRecovery: demoAdmin && !fixture ? demoAdmin.recovery : "disabled",
        });
      if (url.pathname === "/api/diagnostics") {
        const safe = async (fn, message) => {
          try { return await fn(); }
          catch { return { status: "NOT_READY", message }; }
        };
        const providerCheck = await safe(async () => {
          const selection = allAccounts ? "ALL" : environments[0];
          const snapshot = await provider.list(selection, false);
          const aliases = Array.isArray(snapshot.accounts)
            ? snapshot.accounts.map((account) => account.alias).filter((alias) => environments.includes(alias))
            : [];
          const exactAliases = aliases.length === environments.length &&
            [...aliases].sort().join(",") === [...environments].sort().join(",");
          const ready = snapshot.available !== false && !snapshot.partial &&
            snapshot.availableAccounts === snapshot.totalAccounts &&
            snapshot.totalAccounts === environments.length && exactAliases;
          return {
            status: ready ? "READY" : "DEGRADED",
            availableAccounts: Number(snapshot.availableAccounts) || 0,
            totalAccounts: Number(snapshot.totalAccounts) || environments.length,
            aliases: [...environments],
            fetchedAt: snapshot.fetchedAt || null,
            ...(ready ? {} : { message: "Config evidence is partial or does not cover the full registered account set." }),
          };
        }, "Config provider readiness could not be validated.");

        const historyCheck = await safe(
          async () => historyStore.diagnostics(),
          "Historical snapshot storage is not readable.",
        );

        const demoCheck = demoAdmin && !fixture
          ? await safe(
              async () => demoAdmin.diagnostics(),
              "Demo-job journal or fixed CodeBuild dependency could not be validated.",
            )
          : {
              journal: { status: "READY", enabled: false, jobs: 0, running: 0, succeeded: 0, failed: 0, unknown: 0 },
              codebuild: { status: "READY", enabled: false, fixedProject: false },
            };

        const auditCheck = demoAdmin && !fixture
          ? await safe(
              async () => demoAdmin.auditDiagnostics(),
              "Demo audit storage is not readable.",
            )
          : { status: "READY", enabled: false, events: 0 };

        const journalCheck = demoCheck.journal || {
          status: "NOT_READY",
          message: "Demo-job journal readiness could not be validated.",
        };
        const codebuildCheck = demoCheck.codebuild || {
          status: "NOT_READY",
          fixedProject: true,
          message: "Fixed CodeBuild readiness could not be validated.",
        };

        const components = {
          configProvider: providerCheck,
          historyStore: historyCheck,
          demoJournal: journalCheck,
          demoAudit: auditCheck,
          codebuild: codebuildCheck,
        };
        const statuses = Object.values(components).map((component) => component.status);
        const status = statuses.includes("NOT_READY")
          ? "NOT_READY"
          : statuses.includes("DEGRADED") ? "DEGRADED" : "READY";
        const ready = statuses.every((value) => value === "READY");
        return json(status === "NOT_READY" ? 503 : 200, {
          status,
          ready,
          checkedAt: new Date().toISOString(),
          components,
        });
      }
      if (url.pathname === "/api/history") {
        const limit = Math.max(1, Math.min(365, Number(url.searchParams.get("limit")) || 60));
        return json(200, { snapshots: await historyStore.list(limit) });
      }
      if (url.pathname.startsWith("/api/")) {
        const environment = url.searchParams.get("environment");
        const aggregate = allAccounts && environment === "ALL" && url.pathname === "/api/controls";
        if (!aggregate && !environments.includes(environment))
          return json(400, { error: "Choose one configured account; All Accounts is inventory-only" });
        if (url.pathname === "/api/controls") {
          const snapshot = await provider.list(
            environment,
            url.searchParams.get("refresh") === "1",
          );
          if (environment === "ALL" && snapshot.available !== false && !snapshot.partial)
            await historyStore.record(snapshot);
          return json(200, snapshot);
        }
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
            : "Provider read failed. Check the configured read-only AWS source locally; no login or fallback was attempted.",
      });
    }
  });
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const port = Number(process.env.PORT || 1111);
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || port === 2222)
    throw Error("Use a free experiment port (default 1111), never SecCop 2222");
  if (process.argv.slice(2).some((arg) => !["--fixture", "--four-account-fixture", "--org-aggregator"].includes(arg)))
    throw Error("Unknown Config console mode");
  const fourAccountFixture = process.argv.includes("--four-account-fixture");
  const orgAggregator = process.argv.includes("--org-aggregator");
  const legacyFixture = process.argv.includes("--fixture");
  if ([fourAccountFixture, orgAggregator, legacyFixture].filter(Boolean).length > 1)
    throw Error("Choose exactly one Config console mode");
  const fixture = fourAccountFixture || legacyFixture;
  const provider = orgAggregator ? createOrgAggregatorProvider()
    : fourAccountFixture ? createMultiAccountProvider(fourAccountFixtureRead)
      : createProvider(legacyFixture ? fixtureRead : undefined);
  const historyStore = orgAggregator ? createHistoryStore() : createMemoryHistoryStore();
  const demoAdmin = orgAggregator ? createDemoAdmin({
    store: createDemoJobStore(),
    auditStore: createDemoAuditStore(),
  }) : null;
  const server = createServer(provider, { fixture, historyStore, demoAdmin });
  server.on("error", () => {
    console.error("Listener unavailable; no existing process was stopped.");
    process.exitCode = 1;
  });
  server.listen(port, "127.0.0.1", () =>
    console.log(
      `Config console http://localhost:${port}/ \u00b7 ${fixture ? "SYNTHETIC" : "AWS READ ONLY"}`,
    ),
  );
}
