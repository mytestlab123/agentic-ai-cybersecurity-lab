import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { inventory } from "./model.mjs";
const exec = promisify(execFile);
export const profiles = Object.freeze({ DEV: "ihis_dev", PROD: "ihis_pro" });
export const operations = Object.freeze({
  "describe-config-rules": "ConfigRules",
  "describe-compliance-by-config-rule": "ComplianceByConfigRules",
  "describe-config-rule-evaluation-status": "ConfigRulesEvaluationStatus",
  "describe-configuration-recorder-status": "ConfigurationRecordersStatus",
  "get-compliance-details-by-config-rule": "EvaluationResults",
});
export async function awsRead(environment, operation, parameters = {}) {
  if (
    !Object.hasOwn(profiles, environment) ||
    !Object.hasOwn(operations, operation)
  )
    throw Error("Read boundary rejected");
  // Fixed profile + region, no shell, no inherited key or endpoint overrides.
  const env = { ...process.env };
  for (const name of Object.keys(env))
    if (name.startsWith("AWS_")) delete env[name];
  Object.assign(env, {
    AWS_PROFILE: profiles[environment],
    AWS_DEFAULT_PROFILE: profiles[environment],
    AWS_REGION: "ap-southeast-1",
    AWS_DEFAULT_REGION: "ap-southeast-1",
    AWS_PAGER: "",
    AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true",
  });
  const { stdout } = await exec(
    "aws",
    [
      "--profile",
      profiles[environment],
      "--region",
      "ap-southeast-1",
      "configservice",
      operation,
      "--cli-input-json",
      JSON.stringify(parameters),
      "--no-paginate",
      "--output",
      "json",
      "--no-cli-pager",
      "--cli-connect-timeout",
      "10",
      "--cli-read-timeout",
      "30",
    ],
    { env, timeout: 45000, maxBuffer: 16 * 1024 * 1024 },
  );
  return JSON.parse(stdout);
}
export function createProvider(read = awsRead, now = Date.now) {
  const cache = new Map(),
    pending = new Map();
  async function pages(environment, operation) {
    const rows = [],
      seen = new Set();
    let token;
    do {
      const result = await read(
        environment,
        operation,
        token ? { NextToken: token } : {},
      );
      rows.push(...(result[operations[operation]] || []));
      token = result.NextToken;
      if (token && seen.has(token))
        throw Error("Repeated provider pagination token");
      seen.add(token);
    } while (token);
    return rows;
  }
  return {
    async list(environment, refresh = false) {
      if (!Object.hasOwn(profiles, environment))
        throw Error("Unknown environment");
      const prior = cache.get(environment);
      // Coalesce refresh bursts; otherwise explicit refresh bypasses the 30s cache.
      if (prior && now() - prior.at < (refresh ? 2000 : 30000))
        return prior.value;
      if (pending.has(environment)) return pending.get(environment);
      const request = (async () => {
        const [rules, compliance, health, recorders] = await Promise.all(
          Object.keys(operations)
            .slice(0, 4)
            .map((op) => pages(environment, op)),
        );
        const value = {
          environment,
          region: "ap-southeast-1",
          fetchedAt: new Date(now()).toISOString(),
          rules: inventory(rules, compliance, health),
          recorders,
        };
        cache.set(environment, { at: now(), value });
        return value;
      })();
      pending.set(environment, request);
      try {
        return await request;
      } finally {
        pending.delete(environment);
      }
    },
    async details(environment, name, token) {
      // Details must bind to a rule from the complete server-owned inventory.
      const current = cache.get(environment)?.value;
      if (!current) throw Error("Load inventory first");
      if (!current.rules.some((r) => r.id === name))
        throw Error("Unknown rule");
      const response = await read(
        environment,
        "get-compliance-details-by-config-rule",
        {
          ConfigRuleName: name,
          ComplianceTypes: ["NON_COMPLIANT"],
          Limit: 100,
          ...(token ? { NextToken: token } : {}),
        },
      );
      return {
        nextToken: response.NextToken,
        resources: (response.EvaluationResults || []).map((r) => ({
          ComplianceType: r.ComplianceType,
          ResourceType:
            r.EvaluationResultIdentifier?.EvaluationResultQualifier
              ?.ResourceType,
          ResourceId:
            r.EvaluationResultIdentifier?.EvaluationResultQualifier?.ResourceId,
          EvaluationMode:
            r.EvaluationResultIdentifier?.EvaluationResultQualifier
              ?.EvaluationMode,
          OrderingTimestamp: r.EvaluationResultIdentifier?.OrderingTimestamp,
          ConfigRuleInvokedTime: r.ConfigRuleInvokedTime,
          ResultRecordedTime: r.ResultRecordedTime,
          Annotation: r.Annotation,
        })),
      };
    },
  };
}
