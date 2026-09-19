import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
export const ACCOUNT_ALIASES = Object.freeze(["lab-dev", "lab-poc", "lab-qa", "lab-sec"]);
export const REGION = "ap-southeast-1";
export const AGGREGATOR = "aws-secops-issue88-org";
const STATES = new Set(["COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_DATA", "NOT_APPLICABLE"]);
const keyFor = (...parts) => createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 24);

export function parseTargets(raw = process.env.SECOPS_MULTI_ACCOUNT_TARGETS_JSON || "") {
  let rows;
  try { rows = JSON.parse(raw); } catch { throw Error("four-account runtime mapping unavailable"); }
  if (!Array.isArray(rows) || rows.length !== ACCOUNT_ALIASES.length)
    throw Error("exactly four runtime targets are required");
  const result = new Map();
  rows.forEach((row, index) => {
    if (!row || Object.keys(row).sort().join(",") !== "account_id,alias" ||
        row.alias !== ACCOUNT_ALIASES[index] || !/^\d{12}$/.test(row.account_id) ||
        result.has(row.alias))
      throw Error("invalid four-account runtime mapping");
    result.set(row.alias, row.account_id);
  });
  if (new Set(result.values()).size !== ACCOUNT_ALIASES.length)
    throw Error("four-account targets must be distinct");
  return result;
}

export async function awsJson(args) {
  const env = { ...process.env };
  for (const name of Object.keys(env))
    if (name.startsWith("AWS_ENDPOINT_URL") ||
        ["AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
         "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"].includes(name))
      delete env[name];
  Object.assign(env, {
    AWS_REGION: REGION,
    AWS_DEFAULT_REGION: REGION,
    AWS_PAGER: "",
    AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true",
    AWS_MAX_ATTEMPTS: "2",
  });
  const { stdout } = await exec("aws", [
    ...args, "--region", REGION, "--output", "json", "--no-cli-pager",
    "--cli-connect-timeout", "5", "--cli-read-timeout", "30",
  ], { env, timeout: 45000, maxBuffer: 16 * 1024 * 1024 });
  const value = JSON.parse(stdout || "{}");
  if (!value || typeof value !== "object") throw Error("invalid AWS Config response");
  return value;
}

const CONTROL_METADATA = new Map([
  ["s3-bucket-level-public-access-prohibited", {
    sourceIdentifier: "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
    resourceTypes: ["AWS::S3::Bucket"],
  }],
  ["restricted-ssh", {
    sourceIdentifier: "INCOMING_SSH_DISABLED",
    resourceTypes: ["AWS::EC2::SecurityGroup"],
  }],
]);

function baseRuleName(rawName) {
  if (CONTROL_METADATA.has(rawName)) return rawName;
  for (const name of CONTROL_METADATA.keys())
    if (rawName.startsWith(`OrgConfigRule-${name}-`)) return name;
  return null;
}

export function createOrgAggregatorProvider({
  run = awsJson,
  targets = parseTargets(),
  now = Date.now,
} = {}) {
  if (!(targets instanceof Map) || targets.size !== ACCOUNT_ALIASES.length)
    throw Error("four-account runtime mapping unavailable");
  const reverse = new Map([...targets].map(([alias, accountId]) => [accountId, alias]));
  let cache = null;
  const bindings = new Map();

  async function load(refresh = false) {
    if (cache && now() - cache.at < (refresh ? 2000 : 30000)) return cache.value;
    const compliance = await run([
      "configservice", "describe-aggregate-compliance-by-config-rules",
      "--configuration-aggregator-name", AGGREGATOR,
    ]);
    const rows = compliance.AggregateComplianceByConfigRules;
    if (!Array.isArray(rows) || rows.length > 500) throw Error("unexpected aggregate compliance response");
    const accounts = new Map(ACCOUNT_ALIASES.map((alias) => [alias, []]));
    bindings.clear();

    for (const row of rows) {
      const alias = reverse.get(row?.AccountId);
      const rawName = row?.ConfigRuleName;
      if (!alias || row?.AwsRegion !== REGION || typeof rawName !== "string") continue;
      const name = baseRuleName(rawName);
      if (!name) continue;
      const status = row?.Compliance?.ComplianceType;
      if (!STATES.has(status)) throw Error("unexpected aggregate compliance state");
      const meta = CONTROL_METADATA.get(name);
      const id = keyFor(alias, REGION, rawName);
      const contributor = row?.Compliance?.ComplianceContributorCount || {};
      bindings.set(`${alias}:${id}`, { alias, accountId: targets.get(alias), rawName, tokens: new Map() });
      accounts.get(alias).push({
        id,
        accountAlias: alias,
        ConfigRuleName: name,
        ConfigRuleId: id,
        Description: "Organization AWS Config rule observed through the read-only aggregator.",
        ConfigRuleState: "ACTIVE",
        Source: { Owner: "AWS", SourceIdentifier: meta.sourceIdentifier, SourceDetails: [] },
        Scope: { ComplianceResourceTypes: meta.resourceTypes },
        EvaluationModes: [{ Mode: "DETECTIVE" }],
        InputParameters: JSON.stringify("Hidden in alias-only view"),
        trigger: "Organization rule",
        status,
        count: status === "COMPLIANT" ? 0 :
          status === "NON_COMPLIANT" && Number.isInteger(contributor.CappedCount) ? contributor.CappedCount : null,
        capped: status === "NON_COMPLIANT" && contributor.CapExceeded === true,
        health: {},
        warning: false,
      });
    }

    const fetchedAt = new Date(now()).toISOString();
    const value = { accounts, fetchedAt };
    cache = { at: now(), value };
    return value;
  }

  return {
    environments: ACCOUNT_ALIASES,
    allAccounts: true,
    async list(selection = "ALL", refresh = false) {
      if (selection !== "ALL" && !ACCOUNT_ALIASES.includes(selection))
        throw Error("Unknown account selection");
      const source = await load(refresh);
      const aliases = selection === "ALL" ? ACCOUNT_ALIASES : [selection];
      const accountRows = aliases.map((alias) => {
        const rules = source.accounts.get(alias) || [];
        return {
          alias,
          available: rules.length > 0,
          fetchedAt: rules.length ? source.fetchedAt : null,
          ruleCount: rules.length || null,
          rules,
        };
      });
      const available = accountRows.filter((x) => x.available);
      return {
        environment: selection,
        region: REGION,
        available: available.length > 0,
        partial: available.length !== aliases.length,
        availableAccounts: available.length,
        totalAccounts: aliases.length,
        fetchedAt: available.length ? source.fetchedAt : null,
        accounts: accountRows.map(({ alias, available, fetchedAt, ruleCount }) => ({
          alias, available, fetchedAt, ruleCount,
          ...(available ? {} : { message: "No current aggregate Config evidence for this account." }),
        })),
        rules: available.flatMap((x) => x.rules),
        recorders: [],
      };
    },
    async details(alias, id, token) {
      if (!ACCOUNT_ALIASES.includes(alias)) throw Error("Choose one account for details");
      await load(false);
      const binding = bindings.get(`${alias}:${id}`);
      if (!binding) throw Error("Load this account inventory first");
      if (token && !binding.tokens.has(token)) throw Error("Page token does not match this account/control");
      const rawToken = token ? binding.tokens.get(token) : undefined;
      const args = [
        "configservice", "get-aggregate-compliance-details-by-config-rule",
        "--configuration-aggregator-name", AGGREGATOR,
        "--config-rule-name", binding.rawName,
        "--account-id", binding.accountId,
        "--aws-region", REGION,
        "--compliance-type", "NON_COMPLIANT",
        "--limit", "100",
      ];
      if (rawToken) args.push("--next-token", rawToken);
      let page;
      try {
        page = await run(args);
      } catch (error) {
        const message = String(error?.stderr || error?.message || "");
        if (message.includes("AccessDenied"))
          return {
            accountAlias: alias,
            controlId: id,
            nextToken: undefined,
            resources: [],
            unavailable: true,
            message: "Affected resource detail is unavailable under the current read-only host role.",
          };
        throw error;
      }
      if (!Array.isArray(page.AggregateEvaluationResults))
        throw Error("unexpected aggregate detail response");
      let nextToken;
      if (page.NextToken) {
        nextToken = randomUUID();
        binding.tokens.set(nextToken, page.NextToken);
      }
      return {
        accountAlias: alias,
        controlId: id,
        nextToken,
        resources: page.AggregateEvaluationResults.map((item) => {
          const qualifier = item?.EvaluationResultIdentifier?.EvaluationResultQualifier || {};
          const resourceAlias = "RESOURCE_" + keyFor(alias, qualifier.ResourceType, qualifier.ResourceId);
          return {
            ComplianceType: item.ComplianceType,
            ResourceType: qualifier.ResourceType,
            ResourceId: resourceAlias,
            EvaluationMode: qualifier.EvaluationMode,
            OrderingTimestamp: item?.EvaluationResultIdentifier?.OrderingTimestamp,
            ConfigRuleInvokedTime: item.ConfigRuleInvokedTime,
            ResultRecordedTime: item.ResultRecordedTime,
            Annotation: item.Annotation ? "Provider annotation available; identifier content hidden." : undefined,
          };
        }),
      };
    },
  };
}
