// Explicit read-only proof; emits booleans/API counts, never provider identities.
import { createProvider, awsRead } from "../provider.mjs";
const environment = process.argv[2];
if (!["DEV", "PROD"].includes(environment))
  throw Error("Pass DEV or PROD explicitly");
const calls = {};
try {
  const provider = createProvider(async (...args) => {
    calls[args[1]] = (calls[args[1]] || 0) + 1;
    return awsRead(...args);
  });
  const data = await provider.list(environment);
  const rulesPresent = data.rules.length > 0;
  const compliancePresent = data.rules.some((r) => r.status !== "NOT_REPORTED");
  const result = {
    environment,
    region: "ap-southeast-1",
    rulesPresent,
    compliancePresent,
    recorderStatusPresent: data.recorders.length > 0,
    apiCalls: calls,
    awsWrites: 0,
  };
  console.log(
    JSON.stringify(
      {
        ...result,
        result: rulesPresent && compliancePresent ? "PASS" : "NOT_PROVEN",
        timestamp: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
  if (!rulesPresent || !compliancePresent) process.exitCode = 1;
} catch {
  console.error(
    JSON.stringify({
      result: "BLOCKED",
      environment,
      apiCalls: calls,
      error: "Read-only provider access failed; no login/fallback attempted",
      awsWrites: 0,
    }),
  );
  process.exitCode = 1;
}
