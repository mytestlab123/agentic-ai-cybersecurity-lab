import { randomUUID } from "node:crypto";
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
const JOB_RETENTION_MS = 15 * 60 * 1000;
const MAX_JOBS = 32;

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

function validatedResult(control, build) {
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
    mutationCount: result.mutation_count,
    providerVerified: true,
    startingState: "NON_COMPLIANT",
    changedAliases: Array.isArray(result.changed_aliases)
      ? result.changed_aliases.filter((x) => ALIASES.includes(x)) : [],
  };
}

export function createDemoAdmin({ run = defaultRun, now = Date.now } = {}) {
  const jobs = new Map();
  const activeByControl = new Map();

  const publicJob = (job, reused = false) => ({
    jobId: job.jobId,
    control: job.control,
    state: job.state,
    reused,
    startedAt: new Date(job.startedAt).toISOString(),
    ...(job.finishedAt ? { finishedAt: new Date(job.finishedAt).toISOString() } : {}),
    ...(job.result || {}),
    ...(job.error ? { error: job.error } : {}),
  });

  const cleanup = () => {
    const cutoff = now() - JOB_RETENTION_MS;
    for (const [jobId, job] of jobs) {
      if (job.state !== "RUNNING" && job.finishedAt < cutoff) jobs.delete(jobId);
    }
    const terminal = [...jobs.values()]
      .filter((job) => job.state !== "RUNNING")
      .sort((a, b) => a.finishedAt - b.finishedAt);
    while (jobs.size > MAX_JOBS && terminal.length) jobs.delete(terminal.shift().jobId);
  };

  const finish = (job, state, values = {}) => {
    job.state = state;
    job.finishedAt = now();
    Object.assign(job, values);
    if (activeByControl.get(job.control) === job.jobId) activeByControl.delete(job.control);
    cleanup();
  };

  return {
    controls: CONTROLS,

    async start(control) {
      if (!CONTROLS.includes(control)) throw Error("unsupported demo control");
      cleanup();
      const existingId = activeByControl.get(control);
      if (existingId) {
        const existing = jobs.get(existingId);
        if (existing?.state === "RUNNING") return publicJob(existing, true);
        activeByControl.delete(control);
      }

      const started = await run([
        "codebuild", "start-build",
        "--project-name", PROJECT,
        "--environment-variables-override", JSON.stringify([
          { name: "SECOPS_MODE", value: "prepare", type: "PLAINTEXT" },
          { name: "SECOPS_CONTROL", value: control, type: "PLAINTEXT" },
        ]),
      ]);
      const buildId = started?.build?.id;
      if (typeof buildId !== "string" || !buildId.startsWith(PROJECT + ":"))
        throw Error("unexpected CodeBuild start response");

      const job = {
        jobId: randomUUID(),
        buildId,
        control,
        state: "RUNNING",
        startedAt: now(),
        finishedAt: 0,
        result: null,
        error: "",
      };
      jobs.set(job.jobId, job);
      activeByControl.set(control, job.jobId);
      cleanup();
      return publicJob(job);
    },

    async status(jobId) {
      cleanup();
      const job = jobs.get(jobId);
      if (!job) return null;
      if (job.state !== "RUNNING") return publicJob(job);

      const status = await run(["codebuild", "batch-get-builds", "--ids", job.buildId]);
      const build = status?.builds?.[0];
      if (!build || status.builds.length !== 1) throw Error("CodeBuild status unavailable");
      if (!TERMINAL.has(build.buildStatus)) return publicJob(job);

      if (build.buildStatus !== "SUCCEEDED") {
        finish(job, "FAILED", { error: "bounded four-account prepare failed" });
        return publicJob(job);
      }
      try {
        finish(job, "SUCCEEDED", { result: validatedResult(job.control, build) });
      } catch {
        finish(job, "FAILED", { error: "prepare result failed scope validation" });
      }
      return publicJob(job);
    },
  };
}
