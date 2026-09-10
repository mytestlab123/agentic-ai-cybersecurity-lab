// Explicit optional live HTTP + lazy-detail proof; sanitized output only.
import { createProvider, awsRead } from "../provider.mjs";
import { createServer } from "../server.mjs";
const environment = process.argv[2];
if (!["DEV", "PROD"].includes(environment))
  throw Error("Pass DEV or PROD explicitly");
const calls = {};
const provider = createProvider(async (...args) => {
  calls[args[1]] = (calls[args[1]] || 0) + 1;
  return awsRead(...args);
});
const server = createServer(provider);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
try {
  const inventory = await fetch(
    `${base}/api/controls?environment=${environment}`,
  );
  if (!inventory.ok) throw Error("Inventory failed");
  const data = await inventory.json();
  const rule = data.rules.find((r) => r.status === "NON_COMPLIANT");
  if (!rule) throw Error("No non-compliant rule to prove details");
  const lazyBefore = !calls["get-compliance-details-by-config-rule"];
  const detail = await fetch(
    `${base}/api/resources?environment=${environment}&rule=${encodeURIComponent(rule.id)}`,
  );
  if (!detail.ok) throw Error("Details failed");
  const body = await detail.json();
  const tokenOmitted = !JSON.stringify(body).includes("ResultToken");
  const pass = lazyBefore && tokenOmitted && body.resources.length > 0;
  console.log(
    JSON.stringify(
      {
        result: pass ? "PASS" : "NOT_PROVEN",
        environment,
        inventoryHttp: inventory.status,
        detailHttp: detail.status,
        detailsLazy: lazyBefore,
        resourceEvaluationsPresent: body.resources.length > 0,
        resultTokenOmitted: tokenOmitted,
        apiCalls: calls,
        awsWrites: 0,
        timestamp: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
  if (!pass) process.exitCode = 1;
} catch {
  console.error(
    JSON.stringify({
      result: "NOT_PROVEN",
      environment,
      error:
        "Live HTTP/detail proof did not complete; no private provider payload retained",
      apiCalls: calls,
      awsWrites: 0,
    }),
  );
  process.exitCode = 1;
} finally {
  await new Promise((resolve) => server.close(resolve));
}
