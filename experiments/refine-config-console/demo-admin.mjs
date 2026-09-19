import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
export const PROJECT = "aws-secops-four-account-executor";
export const CONTROLS = Object.freeze([
  "s3-bucket-level-public-access-prohibited",
  "restricted-ssh",
]);
const ALIASES = Object.freeze(["lab-dev", "lab-poc", "lab-qa", "lab-sec"]);
const TERMINAL = new Set(["SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"]);

function cleanEnv() {
  const env = { ...process.env };
  for (const name of Object.keys(env))
    if (name.startsWith("AWS_ENDPOINT_URL") ||
        ["AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
         "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"].includes(name))
      delete env[name];
  return { ...env, AWS_REGION: "ap-southeast-1", AWS_DEFAULT_REGION: "ap-southeast-1",
    AWS_PAGER: "", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true", AWS_MAX_ATTEMPTS: "2" };
}

async function defaultRun(args) {
  const { stdout } = await exec("aws", [...args, "--region", "ap-southeast-1", "--output", "json", "--no-cli-pager"], {
    env: cleanEnv(), timeout: 45000, maxBuffer: 4 * 1024 * 1024,
  });
  const value = JSON.parse(stdout || "{}");
  if (!value || typeof value !== "object") throw Error("invalid CodeBuild response");
  return value;
}

export function createDemoAdmin({ run = defaultRun, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  return {
    controls: CONTROLS,
    async prepare(control) {
      if (!CONTROLS.includes(control)) throw Error("unsupported demo control");
      const started = await run([
        "codebuild", "start-build",
        "--project-name", PROJECT,
        "--environment-variables-override", JSON.stringify([
          { name: "SECOPS_MODE", value: "prepare", type: "PLAINTEXT" },
          { name: "SECOPS_CONTROL", value: control, type: "PLAINTEXT" },
        ]),
      ]);
      const id = started?.build?.id;
      if (typeof id !== "string" || !id.startsWith(PROJECT + ":"))
        throw Error("unexpected CodeBuild start response");
      for (let attempt = 0; attempt < 90; attempt++) {
        const status = await run(["codebuild", "batch-get-builds", "--ids", id]);
        const build = status?.builds?.[0];
        if (!build || status.builds.length !== 1) throw Error("CodeBuild status unavailable");
        if (!TERMINAL.has(build.buildStatus)) { await sleep(2000); continue; }
        if (build.buildStatus !== "SUCCEEDED") throw Error("bounded four-account prepare failed");
        const encoded = Object.fromEntries((build.exportedEnvironmentVariables || [])
          .map((row) => [row?.name, row?.value])).SECOPS_RESULT_B64;
        if (typeof encoded !== "string" || !encoded) throw Error("prepare result unavailable");
        const result = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
        if (result?.control !== control || result?.decision !== "PREPARE" ||
            result?.provider_verified !== true || result?.account_ids !== "hidden-by-default" ||
            result?.resource_identifiers !== "hidden-by-default" ||
            JSON.stringify(result?.aliases) !== JSON.stringify(ALIASES) ||
            !Number.isInteger(result?.mutation_count) || result.mutation_count < 0 || result.mutation_count > 4)
          throw Error("prepare result failed scope validation");
        return {
          control,
          aliases: [...ALIASES],
          mutationCount: result.mutation_count,
          providerVerified: true,
          startingState: "NON_COMPLIANT",
          changedAliases: Array.isArray(result.changed_aliases) ? result.changed_aliases.filter((x) => ALIASES.includes(x)) : [],
        };
      }
      throw Error("bounded four-account prepare timed out");
    },
  };
}
