export const categories = [
  "EC2",
  "S3",
  "Security Groups",
  "Lambda",
  "IAM",
  "Other",
];
function fromTypes(types = []) {
  if (types.includes("AWS::EC2::SecurityGroup")) return "Security Groups";
  for (const [prefix, category] of [
    ["EC2", "EC2"],
    ["S3", "S3"],
    ["Lambda", "Lambda"],
    ["IAM", "IAM"],
  ]) {
    if (types.some((t) => t.startsWith(`AWS::${prefix}::`))) return category;
  }
}
export function category(rule, observed = []) {
  const scoped = rule.Scope?.ComplianceResourceTypes || [];
  if (scoped.length) return fromTypes(scoped) || "Other";
  if (observed.length) return fromTypes(observed) || "Other";
  if (rule.Source?.Owner !== "AWS") return "Other";
  const id = rule.Source?.SourceIdentifier || "";
  if (
    [
      "INCOMING_SSH_DISABLED",
      "RESTRICTED_INCOMING_TRAFFIC",
      "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS",
    ].includes(id) ||
    id.startsWith("EC2_SECURITY_GROUP")
  )
    return "Security Groups";
  for (const [prefix, group] of [
    ["EC2_", "EC2"],
    ["S3_", "S3"],
    ["LAMBDA_", "Lambda"],
    ["IAM_", "IAM"],
  ])
    if (id.startsWith(prefix)) return group;
  if (
    [
      "ROOT_ACCOUNT_MFA_ENABLED",
      "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED",
      "ACCESS_KEYS_ROTATED",
      "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
    ].includes(id)
  )
    return "IAM";
  return "Other";
}
export function trigger(rule) {
  const messages = (rule.Source?.SourceDetails || []).map((x) => x.MessageType);
  const periodic =
    messages.includes("ScheduledNotification") ||
    Boolean(rule.MaximumExecutionFrequency);
  const change = messages.some((x) =>
    [
      "ConfigurationItemChangeNotification",
      "OversizedConfigurationItemChangeNotification",
    ].includes(x),
  );
  return periodic && change
    ? "Hybrid"
    : periodic
      ? "Periodic"
      : change
        ? "Change"
        : "Not reported";
}
export function frequency(rule) {
  const values = [
    rule.MaximumExecutionFrequency,
    ...(rule.Source?.SourceDetails || []).map(
      (x) => x.MaximumExecutionFrequency,
    ),
  ].filter(Boolean);
  return [...new Set(values)].join(", ") || "Not reported";
}
export function warning(h = {}) {
  return ["Invocation", "Evaluation"].some((kind) => {
    const failed = Date.parse(h[`LastFailed${kind}Time`] || "");
    const success = Date.parse(h[`LastSuccessful${kind}Time`] || "");
    return (
      Number.isFinite(failed) && (!Number.isFinite(success) || failed > success)
    );
  });
}
export function inventory(rules, compliance, health) {
  const byName = (xs) => new Map(xs.map((x) => [x.ConfigRuleName, x]));
  const c = byName(compliance),
    h = byName(health);
  return rules.map((rule) => {
    const state = c.get(rule.ConfigRuleName)?.Compliance || {};
    const status = state.ComplianceType || "NOT_REPORTED";
    return {
      ...rule,
      id: rule.ConfigRuleName,
      category: category(rule),
      trigger: trigger(rule),
      status,
      count:
        status === "NON_COMPLIANT"
          ? (state.ComplianceContributorCount?.CappedCount ?? null)
          : status === "COMPLIANT"
            ? 0
            : null,
      capped:
        status === "NON_COMPLIANT" &&
        state.ComplianceContributorCount?.CapExceeded === true,
      health: h.get(rule.ConfigRuleName) || {},
      warning: warning(h.get(rule.ConfigRuleName)),
    };
  });
}
