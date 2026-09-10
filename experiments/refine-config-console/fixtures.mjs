// Public-safe invented controls only. Never replace these with provider dumps.
export const rules = [
  ["ec2-metadata-check", "EC2_IMDSV2_CHECK", "AWS::EC2::Instance"],
  ["s3-access-check", "S3_BUCKET_PUBLIC_READ_PROHIBITED", "AWS::S3::Bucket"],
  ["security-group-check", "INCOMING_SSH_DISABLED", "AWS::EC2::SecurityGroup"],
  [
    "lambda-runtime-check",
    "LAMBDA_FUNCTION_SETTINGS_CHECK",
    "AWS::Lambda::Function",
  ],
  ["iam-root-check", "ROOT_ACCOUNT_MFA_ENABLED", null],
  ["custom-review-check", "CUSTOM_CONTROL_01", null],
].map(([name, id, type], i) => ({
  ConfigRuleName: name,
  ConfigRuleId: `CONTROL_0${i + 1}`,
  Description: `Synthetic ${name} control for local UI validation.`,
  ConfigRuleState: "ACTIVE",
  Source: {
    Owner: i === 5 ? "CUSTOM_LAMBDA" : "AWS",
    SourceIdentifier: id,
    SourceDetails: [
      {
        MessageType:
          i === 4
            ? "ScheduledNotification"
            : "ConfigurationItemChangeNotification",
      },
    ],
  },
  Scope: type ? { ComplianceResourceTypes: [type] } : {},
  EvaluationModes: [{ Mode: "DETECTIVE" }],
  InputParameters: "{}",
}));
export function fixtureRead(environment, operation, params = {}) {
  const selected = environment === "PROD" ? rules.slice(0, 4) : rules;
  switch (operation) {
    case "describe-config-rules":
      return { ConfigRules: selected };
    case "describe-compliance-by-config-rule":
      return {
        ComplianceByConfigRules: selected.map((r, i) => ({
          ConfigRuleName: r.ConfigRuleName,
          Compliance: {
            ComplianceType:
              i === 3
                ? "INSUFFICIENT_DATA"
                : i % 2
                  ? "COMPLIANT"
                  : "NON_COMPLIANT",
            ComplianceContributorCount: {
              CappedCount: i === 0 ? 25 : 1,
              CapExceeded: i === 0,
            },
          },
        })),
      };
    case "describe-config-rule-evaluation-status":
      return {
        ConfigRulesEvaluationStatus: selected.map((r, i) => ({
          ConfigRuleName: r.ConfigRuleName,
          LastSuccessfulEvaluationTime: "2026-01-01T10:00:00Z",
          ...(i === 3
            ? {
                LastFailedEvaluationTime: "2026-01-01T11:00:00Z",
                LastErrorCode: "SYNTHETIC_ERROR",
                LastErrorMessage: "Synthetic evaluation failure",
              }
            : {}),
        })),
      };
    case "describe-configuration-recorder-status":
      return {
        ConfigurationRecordersStatus: [
          {
            name: "RECORDER_ALIAS",
            recording: true,
            lastStatus: "SUCCESS",
            lastStatusChangeTime: "2026-01-01T10:00:00Z",
          },
        ],
      };
    case "get-compliance-details-by-config-rule": {
      const index = rules.findIndex(
        (r) => r.ConfigRuleName === params.ConfigRuleName,
      );
      if (index % 2) return { EvaluationResults: [] };
      return {
        EvaluationResults: [
          {
            ComplianceType: "NON_COMPLIANT",
            EvaluationResultIdentifier: {
              EvaluationResultQualifier: {
                ResourceType:
                  rules[index].Scope.ComplianceResourceTypes?.[0] ||
                  "AWS::IAM::User",
                ResourceId: params.NextToken
                  ? "RESOURCE_ALIAS_02"
                  : "RESOURCE_ALIAS_01",
                EvaluationMode: "DETECTIVE",
              },
              OrderingTimestamp: "2026-01-01T10:00:00Z",
            },
            ConfigRuleInvokedTime: "2026-01-01T10:00:00Z",
            ResultRecordedTime: "2026-01-01T10:01:00Z",
            Annotation:
              "Synthetic affected resource. No AWS action is available.",
            ResultToken: "MUST_NOT_LEAK",
          },
        ],
        ...(!params.NextToken ? { NextToken: "synthetic-page-2" } : {}),
      };
    }
    default:
      throw Error("Unexpected fixture API");
  }
}
