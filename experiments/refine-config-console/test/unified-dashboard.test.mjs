import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createServer } from "../server.mjs";
import { createHistoryStore, createMemoryHistoryStore, summarizeSnapshot } from "../history.mjs";
import { createDemoAdmin, createDemoJobStore, PROJECT } from "../demo-admin.mjs";
import { createDemoAuditStore, createMemoryDemoAuditStore } from "../demo-audit.mjs";

const aliases = ["lab-dev", "lab-poc", "lab-qa", "lab-sec"];
function snapshot() {
  const rules = aliases.flatMap((alias) => [
    { id: alias+"-s3", accountAlias: alias, ConfigRuleName: "s3-bucket-level-public-access-prohibited", status: "COMPLIANT", count: 0, warning: false },
    { id: alias+"-ssh", accountAlias: alias, ConfigRuleName: "restricted-ssh", status: "NON_COMPLIANT", count: 1, warning: false },
  ]);
  return {
    environment: "ALL", available: true, partial: false, availableAccounts: 4, totalAccounts: 4,
    fetchedAt: "2026-09-19T06:20:00.000Z",
    accounts: aliases.map((alias) => ({ alias, available: true, fetchedAt: "2026-09-19T06:20:00.000Z", ruleCount: 2 })),
    rules, recorders: [],
  };
}

test("history stores only sanitized aggregate metrics", async () => {
  const value = summarizeSnapshot(snapshot());
  assert.equal(value.totalChecks, 8);
  assert.equal(value.compliant, 4);
  assert.equal(value.noncompliant, 4);
  assert.equal(value.affectedResources, 4);
  assert.deepEqual(value.accounts.map((x) => x.alias), aliases);
  assert.equal(JSON.stringify(value).includes("AccountId"), false);
  assert.equal(JSON.stringify(value).includes("sg-"), false);
});

test("history diagnostics expose sanitized persistence readiness", async () => {
  const store = createMemoryHistoryStore();
  await store.record(snapshot());
  const value = await store.diagnostics();
  assert.equal(value.status, "READY");
  assert.equal(value.snapshots, 1);
  assert.equal(value.latestAt, snapshot().fetchedAt);
  assert.equal(JSON.stringify(value).includes("AccountId"), false);
});

test("demo diagnostics use retained private build evidence without leaking it", async () => {
  const privateId = PROJECT+":diagnostic-build";
  const admin = createDemoAdmin({
    run: async (args) => {
      if (args.includes("start-build")) return { build: { id: privateId } };
      return { builds: [{ id: privateId, buildStatus: "IN_PROGRESS", exportedEnvironmentVariables: [] }] };
    },
  });
  await admin.start("restricted-ssh");
  const value = await admin.diagnostics();
  assert.equal(value.journal.status, "READY");
  assert.equal(value.journal.jobs, 1);
  assert.equal(value.journal.running, 1);
  assert.equal(value.codebuild.status, "READY");
  assert.equal(value.codebuild.fixedProject, true);
  assert.equal(JSON.stringify(value).includes(privateId), false);
});

test("demo diagnostics degrade without a retained build reference", async () => {
  const admin = createDemoAdmin({
    run: async () => { throw Error("AWS read should not run without retained evidence"); },
  });
  const value = await admin.diagnostics();
  assert.equal(value.journal.status, "READY");
  assert.equal(value.journal.jobs, 0);
  assert.equal(value.codebuild.status, "DEGRADED");
  assert.equal(value.codebuild.fixedProject, true);
});

test("demo audit store is bounded sanitized and mode 0600", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "seccop-audit-"));
  try {
    const file = path.join(dir, "demo-audit.json");
    let clock = Date.parse("2026-09-20T04:00:00.000Z");
    const store = createDemoAuditStore({
      file, max: 3, maxAgeMs: 24 * 60 * 60 * 1000, now: () => clock,
    });
    for (const control of [
      "restricted-ssh",
      "s3-bucket-level-public-access-prohibited",
      "restricted-ssh",
      "s3-bucket-level-public-access-prohibited",
    ]) {
      await store.record({
        event: "PREVIEW_CREATED",
        control,
        state: "PENDING_CONFIRMATION",
        messageCode: "FOUR_ACCOUNT_EVIDENCE_VERIFIED",
      });
      clock += 1000;
    }
    const rows = await store.list(200);
    assert.equal(rows.length, 3);
    assert.equal(rows[0].event, "PREVIEW_CREATED");
    assert.equal(JSON.stringify(rows).includes("confirmationToken"), false);
    assert.equal(JSON.stringify(rows).includes("AccountId"), false);
    assert.equal(JSON.stringify(rows).includes(PROJECT+":"), false);
    const mode = (await stat(file)).mode & 0o777;
    assert.equal(mode, 0o600);
    const diagnostics = await store.diagnostics();
    assert.equal(diagnostics.status, "READY");
    assert.equal(diagnostics.events, 3);
    assert.equal(diagnostics.retentionDays, 30);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("demo admin audits start completion reuse and transient status failures", async () => {
  const auditStore = createMemoryDemoAuditStore();
  const result = {
    control: "restricted-ssh", decision: "PREPARE", provider_verified: true, mutation_count: 1,
    aliases, account_ids: "hidden-by-default", resource_identifiers: "hidden-by-default",
    changed_aliases: ["lab-dev"],
  };
  const encoded = Buffer.from(JSON.stringify(result)).toString("base64");
  let statusMode = "in-progress";
  let starts = 0;
  const admin = createDemoAdmin({
    auditStore,
    run: async (args) => {
      if (args.includes("start-build")) {
        starts++;
        return { build: { id: PROJECT+":private-audit-build" } };
      }
      if (statusMode === "fail") throw Error("private transient detail");
      if (statusMode === "in-progress")
        return { builds: [{ buildStatus: "IN_PROGRESS", exportedEnvironmentVariables: [] }] };
      return { builds: [{ buildStatus: "SUCCEEDED", exportedEnvironmentVariables: [{ name: "SECOPS_RESULT_B64", value: encoded }] }] };
    },
  });
  const first = await admin.start("restricted-ssh");
  const reused = await admin.start("restricted-ssh");
  assert.equal(starts, 1);
  assert.equal(reused.reused, true);
  statusMode = "fail";
  await assert.rejects(() => admin.status(first.jobId), /private transient detail/);
  statusMode = "success";
  const completed = await admin.status(first.jobId);
  assert.equal(completed.state, "SUCCEEDED");
  const events = await admin.auditList(20);
  assert.ok(events.some((row) => row.event === "JOB_STARTED"));
  assert.ok(events.some((row) => row.event === "JOB_REUSED"));
  assert.ok(events.some((row) => row.event === "JOB_STATUS_READ_FAILED"));
  assert.ok(events.some((row) => row.event === "JOB_COMPLETED" && row.mutationCount === 1));
  const raw = JSON.stringify(events);
  assert.equal(raw.includes("private-audit-build"), false);
  assert.equal(raw.includes("private transient detail"), false);
});

test("bounded CodeBuild prepare uses sanitized async jobs", async () => {
  const result = {
    control: "restricted-ssh", decision: "PREPARE", provider_verified: true, mutation_count: 3,
    aliases, account_ids: "hidden-by-default", resource_identifiers: "hidden-by-default",
    changed_aliases: aliases.slice(0,3),
  };
  const encoded = Buffer.from(JSON.stringify(result)).toString("base64");
  const calls = [];
  const admin = createDemoAdmin({
    run: async (args) => {
      calls.push(args);
      if (args.includes("start-build")) return { build: { id: PROJECT+":private-build-id" } };
      return { builds: [{ buildStatus: "SUCCEEDED", exportedEnvironmentVariables: [{ name: "SECOPS_RESULT_B64", value: encoded }] }] };
    },
  });
  const started = await admin.start("restricted-ssh");
  assert.equal(started.state, "RUNNING");
  assert.equal(started.control, "restricted-ssh");
  assert.equal(JSON.stringify(started).includes("private-build-id"), false);
  const value = await admin.status(started.jobId);
  assert.equal(value.state, "SUCCEEDED");
  assert.equal(value.mutationCount, 3);
  assert.equal(value.providerVerified, true);
  assert.equal(JSON.stringify(value).includes("private-build-id"), false);
  const start = calls[0];
  const overrides = JSON.parse(start[start.indexOf("--environment-variables-override") + 1]);
  assert.ok(overrides.some((row) => row.name === "SECOPS_MODE" && row.value === "prepare"));
  assert.equal(JSON.stringify(start).match(/source-version|buildspec/gi), null);
});

test("same-control active demo jobs are single-flight", async () => {
  let starts = 0;
  const admin = createDemoAdmin({
    run: async (args) => {
      if (args.includes("start-build")) {
        starts++;
        return { build: { id: PROJECT+":only-one" } };
      }
      return { builds: [{ buildStatus: "IN_PROGRESS", exportedEnvironmentVariables: [] }] };
    },
  });
  const first = await admin.start("restricted-ssh");
  const second = await admin.start("restricted-ssh");
  assert.equal(starts, 1);
  assert.equal(second.jobId, first.jobId);
  assert.equal(second.reused, true);
  const status = await admin.status(first.jobId);
  assert.equal(status.state, "RUNNING");
});

test("active demo job recovers across process restart and remains single-flight", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "seccop-demo-job-"));
  try {
    const file = path.join(dir, "demo-jobs.json");
    let starts = 0;
    const result = {
      control: "restricted-ssh", decision: "PREPARE", provider_verified: true, mutation_count: 0,
      aliases, account_ids: "hidden-by-default", resource_identifiers: "hidden-by-default",
      changed_aliases: [],
    };
    const encoded = Buffer.from(JSON.stringify(result)).toString("base64");
    let statusChecks = 0;
    const run = async (args) => {
      if (args.includes("start-build")) {
        starts++;
        return { build: { id: PROJECT+":recovered-build" } };
      }
      statusChecks++;
      if (statusChecks === 1) return { builds: [{ buildStatus: "IN_PROGRESS", exportedEnvironmentVariables: [] }] };
      return { builds: [{ buildStatus: "SUCCEEDED", exportedEnvironmentVariables: [{ name: "SECOPS_RESULT_B64", value: encoded }] }] };
    };

    const firstProcess = createDemoAdmin({ run, store: createDemoJobStore({ file }) });
    const started = await firstProcess.start("restricted-ssh");
    assert.equal(starts, 1);

    const secondProcess = createDemoAdmin({ run, store: createDemoJobStore({ file }) });
    const reused = await secondProcess.start("restricted-ssh");
    assert.equal(starts, 1);
    assert.equal(reused.jobId, started.jobId);
    assert.equal(reused.reused, true);
    assert.equal(JSON.stringify(reused).includes("recovered-build"), false);

    const completed = await secondProcess.status(started.jobId);
    assert.equal(completed.state, "SUCCEEDED");
    assert.equal(completed.mutationCount, 0);
    assert.equal(completed.providerVerified, true);
    assert.equal(JSON.stringify(completed).includes("recovered-build"), false);

    const thirdProcess = createDemoAdmin({ run, store: createDemoJobStore({ file }) });
    const recoveredTerminal = await thirdProcess.status(started.jobId);
    assert.equal(recoveredTerminal.state, "SUCCEEDED");
    assert.equal(recoveredTerminal.mutationCount, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("missing recovered CodeBuild job becomes UNKNOWN and releases single-flight", async () => {
  let starts = 0;
  const buildIds = [];
  const admin = createDemoAdmin({
    run: async (args) => {
      if (args.includes("start-build")) {
        starts++;
        const id = PROJECT+":build-"+starts;
        buildIds.push(id);
        return { build: { id } };
      }
      return { builds: [], buildsNotFound: [buildIds.at(-1)] };
    },
  });
  const first = await admin.start("restricted-ssh");
  const reconciled = await admin.start("restricted-ssh");
  assert.equal(starts, 1);
  assert.equal(reconciled.jobId, first.jobId);
  assert.equal(reconciled.reused, true);
  assert.equal(reconciled.state, "UNKNOWN");
  assert.match(reconciled.error, /no longer available.*not verified/i);
  assert.equal(JSON.stringify(reconciled).includes(buildIds[0]), false);

  const fresh = await admin.start("restricted-ssh");
  assert.equal(starts, 2);
  assert.notEqual(fresh.jobId, first.jobId);
  assert.equal(fresh.state, "RUNNING");
});

test("non-success CodeBuild terminal state becomes UNKNOWN", async () => {
  const privateId = PROJECT+":stopped-build";
  const admin = createDemoAdmin({
    run: async (args) => args.includes("start-build")
      ? { build: { id: privateId } }
      : { builds: [{ buildStatus: "STOPPED", exportedEnvironmentVariables: [] }] },
  });
  const started = await admin.start("restricted-ssh");
  const value = await admin.status(started.jobId);
  assert.equal(value.state, "UNKNOWN");
  assert.match(value.error, /without verified provider evidence/i);
  assert.equal(JSON.stringify(value).includes(privateId), false);
});

test("invalid successful CodeBuild result becomes UNKNOWN", async () => {
  const privateId = PROJECT+":invalid-result";
  const admin = createDemoAdmin({
    run: async (args) => args.includes("start-build")
      ? { build: { id: privateId } }
      : { builds: [{ buildStatus: "SUCCEEDED", exportedEnvironmentVariables: [] }] },
  });
  const started = await admin.start("s3-bucket-level-public-access-prohibited");
  const value = await admin.status(started.jobId);
  assert.equal(value.state, "UNKNOWN");
  assert.match(value.error, /could not be verified/i);
  assert.equal(JSON.stringify(value).includes(privateId), false);
});

test("transient CodeBuild lookup failure preserves RUNNING state", async () => {
  let lookupFails = true;
  let starts = 0;
  const privateId = PROJECT+":transient-build";
  const admin = createDemoAdmin({
    run: async (args) => {
      if (args.includes("start-build")) {
        starts++;
        return { build: { id: privateId } };
      }
      if (lookupFails) throw Error("temporary CodeBuild read failure");
      return { builds: [{ buildStatus: "IN_PROGRESS", exportedEnvironmentVariables: [] }] };
    },
  });
  const started = await admin.start("restricted-ssh");
  await assert.rejects(() => admin.status(started.jobId), /temporary CodeBuild read failure/);
  lookupFails = false;
  const reused = await admin.start("restricted-ssh");
  assert.equal(starts, 1);
  assert.equal(reused.jobId, started.jobId);
  assert.equal(reused.reused, true);
  assert.equal(reused.state, "RUNNING");
});

test("malformed persisted demo job journal fails closed", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "seccop-demo-job-bad-"));
  try {
    const file = path.join(dir, "demo-jobs.json");
    await writeFile(file, JSON.stringify({ version: 1, jobs: [{ jobId: "bad" }] }));
    const admin = createDemoAdmin({
      run: async () => { throw Error("AWS should not be called"); },
      store: createDemoJobStore({ file }),
    });
    await assert.rejects(() => admin.start("restricted-ssh"), /demo job journal invalid/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("serialized file history retains concurrent refresh snapshots", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "seccop-history-"));
  try {
    const store = createHistoryStore({ file: path.join(dir, "history.json"), max: 10 });
    const first = snapshot();
    const second = { ...snapshot(), fetchedAt: "2026-09-19T06:21:00.000Z" };
    await Promise.all([store.record(first), store.record(second)]);
    const rows = await store.list(10);
    assert.equal(rows.length, 2);
    assert.deepEqual(rows.map((row) => row.fetchedAt), [first.fetchedAt, second.fetchedAt]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("unified server records history and gates four-account demo confirmation", async () => {
  const historyStore = createMemoryHistoryStore();
  const provider = {
    environments: aliases, allAccounts: true,
    async list(selection) { return { ...snapshot(), environment: selection }; },
    async details() { return { resources: [] }; },
  };
  const prepared = [];
  const auditEvents = [];
  const jobId = "11111111-1111-4111-8111-111111111111";
  const demoAdmin = {
    controls: ["s3-bucket-level-public-access-prohibited", "restricted-ssh"],
    recovery: "persistent-journal",
    async start(control) {
      prepared.push(control);
      return { jobId, control, state: "RUNNING", reused: false, startedAt: "2026-09-19T06:20:00.000Z" };
    },
    async status(id) {
      if (id !== jobId) return null;
      return { jobId, control: prepared[0], state: "SUCCEEDED", mutationCount: 2,
        providerVerified: true, startingState: "NON_COMPLIANT", changedAliases: aliases.slice(0,2) };
    },
    async diagnostics() {
      return {
        journal: { status: "READY", jobs: 1, running: 0, succeeded: 1, failed: 0, unknown: 0 },
        codebuild: { status: "READY", fixedProject: true, message: "Fixed dependency is queryable." },
      };
    },
    async audit(entry) {
      auditEvents.push({ eventId: "22222222-2222-4222-8222-222222222222", at: "2026-09-20T04:00:00.000Z",
        control: null, jobId: null, state: null, reused: null, mutationCount: null,
        providerVerified: null, ...entry });
    },
    async auditList(limit = 100) { return auditEvents.slice(-limit).reverse(); },
    async auditDiagnostics() {
      return { status: "READY", events: auditEvents.length, latestAt: auditEvents.at(-1)?.at || null,
        retentionDays: 30, maxEvents: 500 };
    },
  };
  const server = createServer(provider, { historyStore, demoAdmin });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:"+server.address().port;
  try {
    const health = await (await fetch(base+"/api/health")).json();
    assert.equal(health.demoJobRecovery, "persistent-journal");
    const inventory = await fetch(base+"/api/controls?environment=ALL&refresh=1");
    assert.equal(inventory.status, 200);
    const history = await (await fetch(base+"/api/history?limit=10")).json();
    assert.equal(history.snapshots.length, 1);
    const diagnosticsResponse = await fetch(base+"/api/diagnostics");
    assert.equal(diagnosticsResponse.status, 200);
    const diagnostics = await diagnosticsResponse.json();
    assert.equal(diagnostics.status, "READY");
    assert.equal(diagnostics.ready, true);
    assert.equal(diagnostics.components.configProvider.availableAccounts, 4);
    assert.equal(diagnostics.components.historyStore.snapshots, 1);
    assert.equal(diagnostics.components.demoJournal.status, "READY");
    assert.equal(diagnostics.components.demoAudit.status, "READY");
    assert.equal(diagnostics.components.codebuild.status, "READY");
    assert.equal(JSON.stringify(diagnostics).includes("AccountId"), false);
    assert.equal(JSON.stringify(diagnostics).includes(PROJECT+":"), false);
    const previewResponse = await fetch(base+"/api/demo/preview", {
      method:"POST", headers:{"Content-Type":"application/json","Origin":base},
      body:JSON.stringify({control:"s3-bucket-level-public-access-prohibited"}),
    });
    assert.equal(previewResponse.status, 200);
    const preview = await previewResponse.json();
    assert.equal(preview.resourceCount, 4);
    assert.deepEqual(preview.aliases, aliases);
    const runResponse = await fetch(base+"/api/demo/rearm", {
      method:"POST", headers:{"Content-Type":"application/json","Origin":base},
      body:JSON.stringify({control:preview.control,confirmationToken:preview.confirmationToken}),
    });
    assert.equal(runResponse.status, 202);
    const started = await runResponse.json();
    assert.equal(started.state, "RUNNING");
    assert.equal(started.jobId, jobId);
    assert.deepEqual(prepared, ["s3-bucket-level-public-access-prohibited"]);
    const statusResponse = await fetch(base+"/api/demo/jobs/"+jobId);
    assert.equal(statusResponse.status, 200);
    const run = await statusResponse.json();
    assert.equal(run.state, "SUCCEEDED");
    assert.equal(run.mutationCount, 2);
    const replay = await fetch(base+"/api/demo/rearm", {
      method:"POST", headers:{"Content-Type":"application/json","Origin":base},
      body:JSON.stringify({control:preview.control,confirmationToken:preview.confirmationToken}),
    });
    assert.equal(replay.status, 409);
    const auditResponse = await fetch(base+"/api/demo/audit?limit=20");
    assert.equal(auditResponse.status, 200);
    const audit = await auditResponse.json();
    assert.ok(audit.events.some((row) => row.event === "PREVIEW_CREATED"));
    assert.ok(audit.events.some((row) => row.event === "CONFIRMATION_ACCEPTED"));
    assert.ok(audit.events.some((row) => row.event === "CONFIRMATION_REJECTED"));
    assert.equal(JSON.stringify(audit).includes(preview.confirmationToken), false);
    assert.equal(JSON.stringify(audit).includes("AccountId"), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
