import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ACCOUNT_ALIASES,
  AGGREGATOR,
  createOrgAggregatorProvider,
  parseTargets,
} from "../org-aggregator.mjs";

const ids = ["111111111111","222222222222","333333333333","444444444444"];
const targets = new Map(ACCOUNT_ALIASES.map((alias, i) => [alias, ids[i]]));

function fakeRun(calls) {
  return async (args) => {
    calls.push(args);
    const op = args[1];
    if (op === "describe-organization-config-rules")
      return {
        OrganizationConfigRules: [
          { OrganizationConfigRuleName: "s3-bucket-level-public-access-prohibited",
            OrganizationManagedRuleMetadata: { RuleIdentifier: "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
              ResourceTypesScope: ["AWS::S3::Bucket"] } },
          { OrganizationConfigRuleName: "restricted-ssh",
            OrganizationManagedRuleMetadata: { RuleIdentifier: "INCOMING_SSH_DISABLED",
              ResourceTypesScope: ["AWS::EC2::SecurityGroup"] } },
        ],
      };
    if (op === "describe-aggregate-compliance-by-config-rules") {
      const rows = [];
      for (const accountId of ids)
        for (const name of ["s3-bucket-level-public-access-prohibited","restricted-ssh"])
          rows.push({
            AccountId: accountId,
            AwsRegion: "ap-southeast-1",
            ConfigRuleName: `OrgConfigRule-${name}-synthetic`,
            Compliance: {
              ComplianceType: name.startsWith("s3-") ? "COMPLIANT" : "NON_COMPLIANT",
              ComplianceContributorCount: { CappedCount: name.startsWith("s3-") ? 0 : 1, CapExceeded: false },
            },
          });
      rows.push({ AccountId: "999999999999", AwsRegion: "ap-southeast-1",
        ConfigRuleName: "OrgConfigRule-restricted-ssh-other", Compliance: { ComplianceType: "NON_COMPLIANT" } });
      return { AggregateComplianceByConfigRules: rows };
    }
    if (op === "get-aggregate-compliance-details-by-config-rule")
      return {
        AggregateEvaluationResults: [{
          ComplianceType: "NON_COMPLIANT",
          EvaluationResultIdentifier: {
            EvaluationResultQualifier: {
              ResourceType: "AWS::EC2::SecurityGroup",
              ResourceId: "sg-private-real-id",
              EvaluationMode: "DETECTIVE",
            },
            OrderingTimestamp: "2026-09-19T00:00:00Z",
          },
          ResultRecordedTime: "2026-09-19T00:01:00Z",
          Annotation: "private annotation sg-private-real-id",
        }],
        NextToken: args.includes("--next-token") ? undefined : "provider-secret-page",
      };
    throw Error("unexpected operation");
  };
}

test("runtime mapping requires fixed four aliases and distinct account ids", () => {
  const raw = JSON.stringify(ACCOUNT_ALIASES.map((alias, i) => ({ alias, account_id: ids[i] })));
  assert.deepEqual([...parseTargets(raw)], [...targets]);
  assert.throws(() => parseTargets("[]"), /four/);
  assert.throws(() => parseTargets(JSON.stringify([...ACCOUNT_ALIASES].reverse().map((alias, i) => ({alias,account_id:ids[i]}))), /mapping/);
});

test("live aggregator projects exactly four aliases and hides raw account ids", async () => {
  const calls = [];
  const provider = createOrgAggregatorProvider({ run: fakeRun(calls), targets, now: () => 1000 });
  const all = await provider.list("ALL");
  assert.equal(all.availableAccounts, 4);
  assert.equal(all.partial, false);
  assert.equal(all.rules.length, 8);
  assert.deepEqual(all.accounts.map((x) => x.alias), ACCOUNT_ALIASES);
  assert.equal(all.rules.filter((x) => x.status === "COMPLIANT").length, 4);
  assert.equal(all.rules.filter((x) => x.status === "NON_COMPLIANT").length, 4);
  const serialized = JSON.stringify(all);
  ids.forEach((id) => assert.ok(!serialized.includes(id)));
  assert.ok(!serialized.includes("999999999999"));
  assert.ok(calls.some((x) => x.includes(AGGREGATOR)));
});

test("detail lookup is account-bound and aliases resource identifiers", async () => {
  const calls = [];
  const provider = createOrgAggregatorProvider({ run: fakeRun(calls), targets });
  const all = await provider.list("ALL");
  const row = all.rules.find((x) => x.accountAlias === "lab-dev" && x.ConfigRuleName === "restricted-ssh");
  const first = await provider.details("lab-dev", row.id);
  assert.equal(first.accountAlias, "lab-dev");
  assert.match(first.resources[0].ResourceId, /^RESOURCE_[a-f0-9]{24}$/);
  assert.ok(!JSON.stringify(first).includes("sg-private-real-id"));
  assert.ok(!JSON.stringify(first).includes("private annotation"));
  assert.ok(first.nextToken);
  await assert.rejects(provider.details("lab-poc", row.id), /inventory/);
  const second = await provider.details("lab-dev", row.id, first.nextToken);
  assert.equal(second.nextToken, undefined);
  const detailCalls = calls.filter((x) => x[1] === "get-aggregate-compliance-details-by-config-rule");
  assert.equal(detailCalls.length, 2);
  assert.ok(detailCalls[0].includes(ids[0]));
  assert.ok(detailCalls[1].includes("provider-secret-page"));
});
