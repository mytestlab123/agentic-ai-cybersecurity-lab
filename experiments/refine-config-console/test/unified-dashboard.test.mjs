import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "../server.mjs";
import { createMemoryHistoryStore, summarizeSnapshot } from "../history.mjs";
import { createDemoAdmin, PROJECT } from "../demo-admin.mjs";

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

test("bounded CodeBuild prepare validates fixed four-account public result", async () => {
  const result = {
    control: "restricted-ssh", decision: "PREPARE", provider_verified: true, mutation_count: 3,
    aliases, account_ids: "hidden-by-default", resource_identifiers: "hidden-by-default",
    changed_aliases: aliases.slice(0,3),
  };
  const encoded = Buffer.from(JSON.stringify(result)).toString("base64");
  const calls = [];
  const admin = createDemoAdmin({
    sleep: async () => {},
    run: async (args) => {
      calls.push(args);
      if (args.includes("start-build")) return { build: { id: PROJECT+":1" } };
      return { builds: [{ buildStatus: "SUCCEEDED", exportedEnvironmentVariables: [{ name: "SECOPS_RESULT_B64", value: encoded }] }] };
    },
  });
  const value = await admin.prepare("restricted-ssh");
  assert.equal(value.mutationCount, 3);
  assert.equal(value.providerVerified, true);
  assert.deepEqual(value.aliases, aliases);
  const start = JSON.stringify(calls[0]);
  assert.match(start, /"SECOPS_MODE","value":"prepare"/);
  assert.doesNotMatch(start, /source-version|buildspec/i);
});

test("unified server records history and gates four-account demo confirmation", async () => {
  const historyStore = createMemoryHistoryStore();
  const provider = {
    environments: aliases, allAccounts: true,
    async list(selection) { return { ...snapshot(), environment: selection }; },
    async details() { return { resources: [] }; },
  };
  const prepared = [];
  const demoAdmin = {
    controls: ["s3-bucket-level-public-access-prohibited", "restricted-ssh"],
    async prepare(control) {
      prepared.push(control);
      return { control, aliases, mutationCount: 2, providerVerified: true, startingState: "NON_COMPLIANT", changedAliases: aliases.slice(0,2) };
    },
  };
  const server = createServer(provider, { historyStore, demoAdmin });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:"+server.address().port;
  try {
    const inventory = await fetch(base+"/api/controls?environment=ALL&refresh=1");
    assert.equal(inventory.status, 200);
    const history = await (await fetch(base+"/api/history?limit=10")).json();
    assert.equal(history.snapshots.length, 1);
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
    assert.equal(runResponse.status, 200);
    const run = await runResponse.json();
    assert.equal(run.mutationCount, 2);
    assert.deepEqual(prepared, ["s3-bucket-level-public-access-prohibited"]);
    const replay = await fetch(base+"/api/demo/rearm", {
      method:"POST", headers:{"Content-Type":"application/json","Origin":base},
      body:JSON.stringify({control:preview.control,confirmationToken:preview.confirmationToken}),
    });
    assert.equal(replay.status, 409);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
