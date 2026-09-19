import { createHash, randomUUID } from "node:crypto";
import { createProvider, operations } from "./provider.mjs";
import { fixtureRead } from "./fixtures.mjs";

export const ACCOUNT_ALIASES = Object.freeze([
  "ACCOUNT_A", "ACCOUNT_B", "ACCOUNT_C", "ACCOUNT_D",
]);
const REGION = "ap-southeast-1";
const STATES = ["COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_DATA", "NOT_APPLICABLE"];
const keyFor = (...parts) => createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 24);
// Provider descriptions and annotations are text, never identity transport.
function publicValue(value) {
  if (typeof value === "string") return value
    .replace(/arn:[^\s,"<>]+/g, "[identifier hidden]")
    .replace(/\b\d{12}\b/g, "[account hidden]");
  if (Array.isArray(value)) return value.map(publicValue);
  if (value && typeof value === "object") return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, publicValue(item)]),
  );
  return value;
}
function publicRule(rule, alias, id) {
  const health = Object.fromEntries([
    "FirstActivatedTime", "LastSuccessfulInvocationTime", "LastFailedInvocationTime",
    "LastSuccessfulEvaluationTime", "LastFailedEvaluationTime", "LastErrorCode", "LastErrorMessage",
  ].map((key) => [key, rule.health?.[key]]));
  const status = STATES.includes(rule.status) ? rule.status : "NOT_REPORTED";
  return publicValue({
    id, accountAlias: alias, ConfigRuleName: rule.ConfigRuleName, ConfigRuleId: id,
    Description: rule.Description, ConfigRuleState: rule.ConfigRuleState,
    Source: { Owner: rule.Source?.Owner, SourceIdentifier: rule.Source?.SourceIdentifier,
      SourceDetails: (rule.Source?.SourceDetails || []).map((item) => ({
        MessageType: item.MessageType, MaximumExecutionFrequency: item.MaximumExecutionFrequency,
      })) },
    Scope: { ComplianceResourceTypes: rule.Scope?.ComplianceResourceTypes || [] },
    EvaluationModes: rule.EvaluationModes, MaximumExecutionFrequency: rule.MaximumExecutionFrequency,
    // Raw scope, input parameters, creator ARN and ConfigRuleArn stay server-side.
    InputParameters: JSON.stringify("Hidden in alias-only view"), category: rule.category, trigger: rule.trigger, status,
    count: status === "COMPLIANT" ? 0 : status === "NON_COMPLIANT" &&
      Number.isInteger(rule.count) && rule.count >= 0 ? rule.count : null,
    capped: status === "NON_COMPLIANT" && rule.capped === true,
    health, warning: rule.warning === true,
  });
}

// No default live reader: this must never inherit the legacy DEV/PROD profiles.
export function createMultiAccountProvider(read, now = Date.now) {
  if (typeof read !== "function") throw Error("Four-account reader not configured");
  const provider = createProvider(async (alias, operation, params) => {
    if (!ACCOUNT_ALIASES.includes(alias) || !Object.hasOwn(operations, operation))
      throw Error("Read boundary rejected");
    const result = await read(alias, operation, params);
    if (!result || !Array.isArray(result[operations[operation]]))
      throw Error("Incomplete provider response");
    return result;
  }, now, ACCOUNT_ALIASES);
  const snapshots = new Map();
  async function readAccount(alias, refresh) {
    try {
      const source = await provider.list(alias, refresh);
      let saved = snapshots.get(alias);
      if (saved?.source !== source) {
        const bindings = new Map();
        const rules = source.rules.map((rule) => {
          const id = keyFor(alias, REGION, rule.id);
          bindings.set(id, { name: rule.id, tokens: new Map() });
          return publicRule(rule, alias, id);
        });
        const recorders = source.recorders.map((recorder) => publicValue({
          accountAlias: alias, recording: recorder.recording, lastStatus: recorder.lastStatus,
          lastStatusChangeTime: recorder.lastStatusChangeTime,
          lastErrorCode: recorder.lastErrorCode,
        }));
        saved = { source, rules, recorders, bindings };
        snapshots.set(alias, saved);
      }
      return { alias, available: true, fetchedAt: source.fetchedAt,
        ruleCount: saved.rules.length, rules: saved.rules, recorders: saved.recorders };
    } catch {
      snapshots.delete(alias);
      return { alias, available: false, fetchedAt: null, ruleCount: null,
        rules: [], recorders: [], message: "Inventory unavailable; no fallback attempted." };
    }
  }
  return {
    environments: ACCOUNT_ALIASES,
    allAccounts: true,
    async list(selection = "ALL", refresh = false) {
      if (selection !== "ALL" && !ACCOUNT_ALIASES.includes(selection))
        throw Error("Unknown account selection");
      const aliases = selection === "ALL" ? ACCOUNT_ALIASES : [selection];
      const results = await Promise.all(aliases.map((alias) => readAccount(alias, refresh)));
      const available = results.filter((account) => account.available);
      return {
        environment: selection, region: REGION, available: available.length > 0,
        partial: available.length !== aliases.length,
        availableAccounts: available.length, totalAccounts: aliases.length,
        // The oldest successful fetch is truthful for a combined cached view.
        fetchedAt: available.length ? available.map((x) => x.fetchedAt).sort()[0] : null,
        accounts: results.map((account) => ({
          alias: account.alias, available: account.available, fetchedAt: account.fetchedAt,
          ruleCount: account.ruleCount, message: account.message,
        })),
        rules: available.flatMap((account) => account.rules),
        recorders: available.flatMap((account) => account.recorders),
      };
    },
    async details(alias, id, token) {
      if (!ACCOUNT_ALIASES.includes(alias)) throw Error("Choose one account for details");
      const saved = snapshots.get(alias), binding = saved?.bindings.get(id);
      if (!binding) throw Error("Load this account's inventory first");
      if (token && !binding.tokens.has(token)) throw Error("Page token does not match this account/control");
      const rawToken = token ? binding.tokens.get(token) : undefined;
      const page = await provider.details(alias, binding.name, rawToken);
      if (snapshots.get(alias) !== saved) throw Error("Inventory changed; reopen the control");
      if (rawToken && page.nextToken === rawToken) throw Error("Repeated provider page token");
      let nextToken;
      if (page.nextToken) {
        nextToken = [...binding.tokens].find(([, value]) => value === page.nextToken)?.[0];
        if (!nextToken) {
          if (binding.tokens.size >= 100) throw Error("Page limit reached; refresh inventory");
          nextToken = randomUUID();
          binding.tokens.set(nextToken, page.nextToken);
        }
      }
      return {
        accountAlias: alias, controlId: id, nextToken,
        resources: page.resources.map((resource) => {
          const resourceAlias = "RESOURCE_" + keyFor(alias, resource.ResourceType, resource.ResourceId);
          return publicValue({
            ...resource, ResourceId: resourceAlias,
            Annotation: typeof resource.Annotation === "string" && resource.ResourceId
              ? resource.Annotation.split(resource.ResourceId).join(resourceAlias) : resource.Annotation,
          });
        }),
      };
    },
  };
}

// Invented fixtures only; these labels are not mappings to real AWS accounts.
export function fourAccountFixtureRead(alias, operation, params = {}) {
  if (!ACCOUNT_ALIASES.includes(alias)) throw Error("Unknown fixture account");
  const result = structuredClone(fixtureRead(alias === "ACCOUNT_B" ? "PROD" : "DEV", operation, params));
  if (operation === "describe-compliance-by-config-rule") {
    if (alias === "ACCOUNT_C") for (const item of result.ComplianceByConfigRules)
      item.Compliance = { ComplianceType: "COMPLIANT" };
    if (alias === "ACCOUNT_D") result.ComplianceByConfigRules = [];
  }
  if (["ACCOUNT_C", "ACCOUNT_D"].includes(alias) && operation === "describe-config-rule-evaluation-status")
    result.ConfigRulesEvaluationStatus = [];
  if (["ACCOUNT_C", "ACCOUNT_D"].includes(alias) && operation === "get-compliance-details-by-config-rule")
    return { EvaluationResults: [] };
  return result;
}
