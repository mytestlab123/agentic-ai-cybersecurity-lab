import { test } from "node:test";
import assert from "node:assert/strict";
import { ACCOUNT_ALIASES, createMultiAccountProvider, fourAccountFixtureRead } from "../multi-account.mjs";
import { operations, awsRead, createProvider } from "../provider.mjs";
import { fixtureRead } from "../fixtures.mjs";
import { createServer } from "../server.mjs";

function tracked(reader = fourAccountFixtureRead, now) {
  const calls = [];
  const provider = createMultiAccountProvider(async (...args) => {
    calls.push(args);
    return reader(...args);
  }, now);
  return { provider, calls };
}
function ruleFor(snapshot, alias, name = "ec2-metadata-check") {
  return snapshot.rules.find((row) => row.accountAlias === alias && row.ConfigRuleName === name);
}

test("four accounts aggregate distinct account/control checks and truthful states", async () => {
  const { provider, calls } = tracked();
  const result = await provider.list("ALL");
  assert.deepEqual(result.accounts.map((x) => x.alias), ACCOUNT_ALIASES);
  assert.equal(result.rules.length, 22);
  assert.equal(new Set(result.rules.map((x) => x.id)).size, 22);
  assert.equal(result.rules.filter((x) => x.ConfigRuleName === "ec2-metadata-check").length, 4);
  assert.equal(result.rules.filter((x) => x.status === "COMPLIANT").length, 9);
  assert.equal(result.rules.filter((x) => x.status === "NON_COMPLIANT").length, 5);
  assert.equal(result.rules.filter((x) => x.status === "NOT_REPORTED").length, 6);
  assert.equal(result.partial, false);
  assert.equal(result.availableAccounts, 4);
  assert.equal(calls.length, 16);
  assert.ok(calls.every(([, op]) => Object.hasOwn(operations, op) && !op.startsWith("get-")));
  assert.equal(ruleFor(result, "ACCOUNT_A").capped, true);
});

test("single selection reads only that account and concurrent inventory coalesces", async () => {
  const { provider, calls } = tracked();
  const [a, b] = await Promise.all([provider.list("ACCOUNT_B"), provider.list("ACCOUNT_B")]);
  assert.equal(a.rules.length, 4);
  assert.deepEqual(a.rules, b.rules);
  assert.equal(calls.length, 4);
  assert.ok(calls.every(([alias]) => alias === "ACCOUNT_B"));
  await provider.list("ACCOUNT_B");
  assert.equal(calls.length, 4);
});

test("partial failures exclude unavailable accounts without claiming full totals", async () => {
  const { provider } = tracked((alias, ...args) => {
    if (alias === "ACCOUNT_C") throw Error("private-profile credential failure");
    return fourAccountFixtureRead(alias, ...args);
  });
  const value = await provider.list("ALL");
  assert.equal(value.partial, true);
  assert.equal(value.available, true);
  assert.equal(value.availableAccounts, 3);
  assert.equal(value.totalAccounts, 4);
  assert.equal(value.rules.length, 16);
  assert.equal(value.accounts[2].ruleCount, null);
  assert.equal(value.accounts[2].available, false);
  assert.ok(!JSON.stringify(value).includes("private-profile"));
});

test("all failures and valid empty inventory are distinguishable", async () => {
  const failed = await tracked(() => { throw Error("unavailable"); }).provider.list("ALL");
  assert.equal(failed.available, false);
  assert.equal(failed.partial, true);
  assert.equal(failed.fetchedAt, null);
  assert.ok(failed.accounts.every((account) => account.ruleCount === null));
  const empty = await tracked((alias, op) => ({ [operations[op]]: [] })).provider.list("ALL");
  assert.equal(empty.available, true);
  assert.equal(empty.partial, false);
  assert.equal(empty.rules.length, 0);
  assert.ok(empty.accounts.every((account) => account.ruleCount === 0));
});

test("failed refresh invalidates saved detail bindings; recovery stays account-bound", async () => {
  let clock = 0, fail = false;
  const { provider } = tracked((alias, ...args) => {
    if (fail && alias === "ACCOUNT_A") throw Error("failure");
    return fourAccountFixtureRead(alias, ...args);
  }, () => clock);
  const first = await provider.list("ACCOUNT_A");
  const id = ruleFor(first, "ACCOUNT_A").id;
  clock = 3000; fail = true;
  const failed = await provider.list("ACCOUNT_A", true);
  assert.equal(failed.available, false);
  assert.deepEqual(failed.rules, []);
  await assert.rejects(provider.details("ACCOUNT_A", id), /inventory/);
  clock = 6000; fail = false;
  const recovered = await provider.list("ACCOUNT_A", true);
  assert.equal(ruleFor(recovered, "ACCOUNT_A").id, id);
  assert.equal(recovered.available, true);
});

test("combined timestamp is oldest included snapshot, not latest attempted refresh", async () => {
  let clock = 1000;
  const { provider } = tracked(fourAccountFixtureRead, () => clock);
  await provider.list("ACCOUNT_A");
  clock = 2000;
  const all = await provider.list("ALL");
  assert.equal(all.fetchedAt, new Date(1000).toISOString());
});

test("all inventory pages are included; malformed or looping pages fail closed", async () => {
  const { provider } = tracked((alias, op, params) => {
    const value = fourAccountFixtureRead(alias, op, params), key = operations[op];
    return params.NextToken ? { [key]: value[key].slice(1) }
      : { [key]: value[key].slice(0, 1), NextToken: "second" };
  });
  assert.equal((await provider.list("ALL")).rules.length, 22);
  const malformed = await tracked(() => ({})).provider.list("ALL");
  assert.equal(malformed.available, false);
  const looping = await tracked((alias, op) => ({ [operations[op]]: [], NextToken: "same" })).provider.list("ALL");
  assert.equal(looping.available, false);
});

test("lazy details and page handles cannot cross accounts or controls", async () => {
  const { provider, calls } = tracked();
  const all = await provider.list("ALL");
  const a = ruleFor(all, "ACCOUNT_A"), b = ruleFor(all, "ACCOUNT_B");
  const page = await provider.details("ACCOUNT_A", a.id);
  assert.equal(calls.length, 17);
  assert.match(page.resources[0].ResourceId, /^RESOURCE_[a-f0-9]{24}$/);
  assert.ok(page.nextToken && page.nextToken !== "synthetic-page-2");
  assert.ok(!JSON.stringify(page).includes("MUST_NOT_LEAK"));
  await assert.rejects(provider.details("ACCOUNT_B", a.id), /inventory/);
  await assert.rejects(provider.details("ACCOUNT_B", b.id, page.nextToken), /token/);
  await assert.rejects(provider.details("ALL", a.id), /one account/);
  assert.equal(calls.length, 17);
  const second = await provider.details("ACCOUNT_A", a.id, page.nextToken);
  assert.equal(second.nextToken, undefined);
  assert.notEqual(second.resources[0].ResourceId, page.resources[0].ResourceId);
  assert.equal(calls.at(-1)[0], "ACCOUNT_A");
  assert.equal(calls.at(-1)[2].ConfigRuleName, "ec2-metadata-check");
  assert.equal(calls.at(-1)[2].NextToken, "synthetic-page-2");
});

test("unknown selections and absent reader never fall back to legacy AWS profiles", async () => {
  const { provider, calls } = tracked();
  assert.throws(() => createMultiAccountProvider(), /not configured/);
  for (const selection of ["DEV", "PROD", "default", "ACCOUNT_E", "__proto__"])
    await assert.rejects(provider.list(selection), /Unknown/);
  assert.equal(calls.length, 0);
  await assert.rejects(awsRead("ACCOUNT_A", "describe-config-rules"), /boundary/);
  await assert.rejects(awsRead("DEV", "start-config-rules-evaluation"), /boundary/);
});

test("public projection omits raw identity fields and does not fabricate input parameters", async () => {
  const account = "1".repeat(12), arn = `arn:aws:lambda:ap-southeast-1:${account}:function:example`;
  const { provider } = tracked((alias, op, params) => {
    const value = fourAccountFixtureRead(alias, op, params);
    if (op === "describe-config-rules") {
      value.ConfigRules[0].ConfigRuleArn = arn;
      value.ConfigRules[0].CreatedBy = arn;
      value.ConfigRules[0].Description = `${arn} ${account}`;
      value.ConfigRules[0].InputParameters = '{"private":"DO_NOT_PUBLISH"}';
      value.ConfigRules[0].Scope.ComplianceResourceId = "PRIVATE_RESOURCE";
    }
    return value;
  });
  const view = await provider.list("ACCOUNT_A");
  const serialized = JSON.stringify(view);
  for (const secret of [account, arn, "DO_NOT_PUBLISH", "PRIVATE_RESOURCE", "ConfigRuleArn"])
    assert.ok(!serialized.includes(secret));
  assert.equal(JSON.parse(view.rules[0].InputParameters), "Hidden in alias-only view");
});

test("HTTP supports All Accounts inventory but rejects aggregate detail and mutations", async (t) => {
  const { provider, calls } = tracked();
  const server = createServer(provider, { fixture: true });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(health.mode, "SYNTHETIC");
  assert.deepEqual(health.environments, ACCOUNT_ALIASES);
  assert.equal(health.allAccounts, true);
  assert.equal(calls.length, 0);
  assert.equal((await fetch(`${base}/api/controls?environment=ALL`, { method: "POST" })).status, 405);
  assert.equal((await fetch(`${base}/api/controls?environment=ALL`, { headers: { Origin: "https://example.com" } })).status, 403);
  assert.equal((await fetch(`${base}/api/controls?environment=DEV`)).status, 400);
  assert.equal((await fetch(`${base}/api/resources?environment=ALL&rule=x`)).status, 400);
  assert.equal(calls.length, 0);
  const all = await (await fetch(`${base}/api/controls?environment=ALL`)).json();
  assert.equal(all.rules.length, 22);
  const row = ruleFor(all, "ACCOUNT_B");
  const detail = await fetch(`${base}/api/resources?environment=ACCOUNT_B&rule=${row.id}`);
  assert.equal(detail.status, 200);
  assert.equal((await detail.json()).accountAlias, "ACCOUNT_B");
});

test("legacy provider remains DEV/PROD and five Config reads only", async () => {
  const provider = createProvider(fixtureRead);
  assert.deepEqual(provider.environments, ["DEV", "PROD"]);
  assert.equal((await provider.list("DEV")).rules.length, 6);
  assert.equal((await provider.list("PROD")).rules.length, 4);
  await assert.rejects(provider.list("ACCOUNT_A"), /Unknown/);
  assert.equal(Object.keys(operations).length, 5);
});
