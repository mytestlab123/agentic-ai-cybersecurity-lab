import { test } from "node:test";
import assert from "node:assert/strict";
import { category, trigger, frequency, warning, inventory } from "../model.mjs";
import { createProvider, operations, awsRead } from "../provider.mjs";
import { fixtureRead, rules } from "../fixtures.mjs";
import { createServer } from "../server.mjs";
import http from "node:http";

test("category precedence, SG before EC2, explicit IAM, custom/unknown not guessed", () => {
  assert.deepEqual(
    rules.map((r) => category(r)),
    ["EC2", "S3", "Security Groups", "Lambda", "IAM", "Other"],
  );
  assert.equal(
    category({
      ...rules[0],
      Scope: {
        ComplianceResourceTypes: [
          "AWS::EC2::Instance",
          "AWS::EC2::SecurityGroup",
        ],
      },
    }),
    "Security Groups",
  );
  assert.equal(
    category(
      {
        ...rules[0],
        Scope: { ComplianceResourceTypes: ["AWS::Unknown::Thing"] },
      },
      ["AWS::S3::Bucket"],
    ),
    "Other",
  );
  assert.equal(
    category({ ...rules[0], Scope: {} }, ["AWS::Lambda::Function"]),
    "Lambda",
  );
  assert.equal(
    category({
      Description: "S3 IAM security EC2",
      Source: { Owner: "CUSTOM_LAMBDA", SourceIdentifier: "S3_FAKE" },
    }),
    "Other",
  );
  assert.equal(
    category({
      Source: { Owner: "AWS", SourceIdentifier: "ACCESS_KEYS_ROTATED" },
    }),
    "IAM",
  );
});
test("trigger and recent failure truth; old errors are not current warnings", () => {
  assert.equal(
    trigger({
      Source: {
        SourceDetails: [
          { MessageType: "ScheduledNotification" },
          { MessageType: "ConfigurationItemChangeNotification" },
        ],
      },
    }),
    "Hybrid",
  );
  assert.equal(trigger({}), "Not reported");
  assert.equal(
    frequency({
      Source: { SourceDetails: [{ MessageType: "ScheduledNotification" }] },
    }),
    "Not reported",
  );
  assert.equal(
    frequency({ MaximumExecutionFrequency: "TwentyFour_Hours" }),
    "TwentyFour_Hours",
  );
  assert.equal(
    warning({
      LastFailedEvaluationTime: "2026-01-01",
      LastSuccessfulEvaluationTime: "2026-01-02",
    }),
    false,
  );
  assert.equal(
    warning({
      LastFailedInvocationTime: "2026-01-02",
      LastSuccessfulInvocationTime: "2026-01-01",
    }),
    true,
  );
  assert.equal(warning({ LastErrorCode: "OLD_ERROR" }), false);
});
test("counts never reinterpret compliant contributors as noncompliant; missing stays unknown", () => {
  const result = inventory(
    rules,
    [
      {
        ConfigRuleName: rules[0].ConfigRuleName,
        Compliance: {
          ComplianceType: "COMPLIANT",
          ComplianceContributorCount: { CappedCount: 25, CapExceeded: true },
        },
      },
      {
        ConfigRuleName: rules[1].ConfigRuleName,
        Compliance: {
          ComplianceType: "NON_COMPLIANT",
          ComplianceContributorCount: { CappedCount: 25, CapExceeded: true },
        },
      },
    ],
    [],
  );
  assert.equal(result[0].count, 0);
  assert.equal(result[0].capped, false);
  assert.equal(result[1].count, 25);
  assert.equal(result[1].capped, true);
  assert.equal(result[2].status, "NOT_REPORTED");
  assert.equal(result[2].count, null);
});
test("all inventory APIs paginate, coalesce and cache; no details fanout", async () => {
  const calls = [];
  let clock = 0;
  const provider = createProvider(
    async (env, op, p) => {
      calls.push([env, op, p]);
      const original = fixtureRead(env, op, p);
      const key = operations[op];
      return p.NextToken
        ? { [key]: original[key].slice(1) }
        : { [key]: original[key].slice(0, 1), NextToken: "second" };
    },
    () => clock,
  );
  const [a, b] = await Promise.all([
    provider.list("DEV"),
    provider.list("DEV"),
  ]);
  assert.equal(a, b);
  assert.equal(a.rules.length, 6);
  assert.equal(calls.length, 8);
  assert.ok(
    calls.every((c) => c[1] !== "get-compliance-details-by-config-rule"),
  );
  await provider.list("DEV");
  assert.equal(calls.length, 8);
  clock = 3000;
  await provider.list("DEV", true);
  assert.equal(calls.length, 16);
  await provider.list("PROD");
  assert.equal(calls.length, 24);
});
test("empty pages with next token continue, repeated token fails closed", async () => {
  const provider = createProvider(async (env, op, p) =>
    p.NextToken
      ? fixtureRead(env, op, p)
      : { [operations[op]]: [], NextToken: "second" },
  );
  assert.equal((await provider.list("DEV")).rules.length, 6);
  const bad = createProvider(async () => ({ NextToken: "loop" }));
  await assert.rejects(bad.list("DEV"), /Repeated/);
});
test("details bind inventory name, paginate lazily, exclude ResultToken", async () => {
  const calls = [];
  const provider = createProvider(async (...args) => {
    calls.push(args);
    return fixtureRead(...args);
  });
  await provider.list("DEV");
  assert.equal(calls.length, 4);
  await assert.rejects(provider.details("DEV", "unbound"), /Unknown rule/);
  assert.equal(calls.length, 4);
  const page = await provider.details("DEV", rules[0].ConfigRuleName);
  assert.equal(page.resources[0].ResourceId, "RESOURCE_ALIAS_01");
  assert.ok(!JSON.stringify(page).includes("MUST_NOT_LEAK"));
  const next = await provider.details(
    "DEV",
    rules[0].ConfigRuleName,
    page.nextToken,
  );
  assert.equal(next.resources[0].ResourceId, "RESOURCE_ALIAS_02");
  assert.equal(next.nextToken, undefined);
  assert.deepEqual(calls[4][2].ComplianceTypes, ["NON_COMPLIANT"]);
});
test("AWS invocation rejects other profiles and every write API before exec", async () => {
  assert.equal(Object.keys(operations).length, 5);
  for (const op of [
    "start-config-rules-evaluation",
    "start-remediation-execution",
    "put-config-rule",
    "delete-config-rule",
  ])
    await assert.rejects(awsRead("DEV", op), /boundary/);
  await assert.rejects(awsRead("amit", "describe-config-rules"), /boundary/);
});
test("HTTP is GET-only, same-origin, environment-bound, with sanitized errors", async (t) => {
  const provider = createProvider(fixtureRead);
  const server = createServer(provider, { fixture: true });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${base}/api/health`)).status, 200);
  assert.equal(
    (await fetch(`${base}/api/controls?environment=DEV`, { method: "POST" }))
      .status,
    405,
  );
  assert.equal(
    (
      await fetch(`${base}/api/controls?environment=DEV`, {
        headers: { Origin: "https://example.com" },
      })
    ).status,
    403,
  );
  const badHostStatus = await new Promise((resolve, reject) => {
    http
      .get(
        `${base}/api/health`,
        { headers: { Host: "attacker.invalid" } },
        (res) => {
          res.resume();
          resolve(res.statusCode);
        },
      )
      .on("error", reject);
  });
  assert.equal(badHostStatus, 403);
  assert.equal(
    (await fetch(`${base}/api/controls?environment=amit`)).status,
    400,
  );
  const good = await fetch(`${base}/api/controls?environment=PROD`);
  assert.equal((await good.json()).rules.length, 4);
  const invalid = await fetch(
    `${base}/api/resources?environment=DEV&rule=unknown`,
  );
  assert.equal(invalid.status, 502);
  assert.ok(!(await invalid.text()).includes("unknown"));
});
