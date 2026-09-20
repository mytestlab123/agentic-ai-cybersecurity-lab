import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
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
const JOURNAL_VERSION = 1;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

function validatePersistedJob(job) {
  if (!job || typeof job !== "object" || Array.isArray(job)) throw Error("demo job journal invalid");
  const keys = Object.keys(job).sort().join(",");
  if (keys !== "buildId,control,error,finishedAt,jobId,result,startedAt,state")
    throw Error("demo job journal invalid");
  if (!UUID_RE.test(job.jobId) || !CONTROLS.includes(job.control) ||
      typeof job.buildId !== "string" || !job.buildId.startsWith(PROJECT + ":") ||
      !["RUNNING", "SUCCEEDED", "FAILED", "UNKNOWN"].includes(job.state) ||
      !Number.isInteger(job.startedAt) || job.startedAt <= 0 ||
      !Number.isInteger(job.finishedAt) || job.finishedAt < 0 ||
      (job.state === "RUNNING" && job.finishedAt !== 0) ||
      (job.state !== "RUNNING" && job.finishedAt <= 0) ||
      typeof job.error !== "string" ||
      (job.result !== null && (typeof job.result !== "object" || Array.isArray(job.result))))
    throw Error("demo job journal invalid");
  if (job.result) {
    const { mutationCount, providerVerified, startingState, changedAliases } = job.result;
    if (!Number.isInteger(mutationCount) || mutationCount < 0 || mutationCount > 4 ||
        providerVerified !== true || startingState !== "NON_COMPLIANT" ||
        !Array.isArray(changedAliases) || changedAliases.some((x) => !ALIASES.includes(x)))
      throw Error("demo job journal invalid");
  }
  return {
    jobId: job.jobId,
    buildId: job.buildId,
    control: job.control,
    state: job.state,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    result: job.result,
    error: job.error,
  };
}

export function createDemoJobStore({
  file = process.env.CONFIG_DEMO_JOB_FILE || "/var/lib/aws-config-console/demo-jobs.json",
} = {}) {
  let queue = Promise.resolve();

  const serialize = (task) => {
    const next = queue.catch(() => undefined).then(task);
    queue = next.then(() => undefined, () => undefined);
    return next;
  };

  const readRows = async () => {
    try {
      const value = JSON.parse(await readFile(file, "utf8"));
      if (!value || value.version !== JOURNAL_VERSION || !Array.isArray(value.jobs))
        throw Error("demo job journal invalid");
      return value.jobs.map(validatePersistedJob);
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      if (String(error?.message) === "demo job journal invalid") throw error;
      throw Error("demo job journal invalid");
    }
  };

  return {
    async load() {
      await queue;
      return readRows();
    },
    async save(rows) {
      const copy = rows.map(validatePersistedJob);
      return serialize(async () => {
        await mkdir(path.dirname(file), { recursive: true });
        const temp = file + ".tmp";
        await writeFile(temp, JSON.stringify({ version: JOURNAL_VERSION, jobs: copy }), { mode: 0o600 });
        await rename(temp, file);
      });
    },
  };
}

export function createMemoryDemoJobStore(initial = []) {
  let rows = initial.map(validatePersistedJob);
  return {
    async load() { return rows.map((row) => ({ ...row, result: row.result ? { ...row.result } : null })); },
    async save(next) { rows = next.map(validatePersistedJob); },
  };
}

export function createDemoAdmin({
  run = defaultRun,
  now = Date.now,
  store = createMemoryDemoJobStore(),
} = {}) {
  const jobs = new Map();
  const activeByControl = new Map();
  let loaded = false;
  let loading = null;

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

  const persistedRows = () => [...jobs.values()].map((job) => ({
    jobId: job.jobId,
    buildId: job.buildId,
    control: job.control,
    state: job.state,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    result: job.result,
    error: job.error,
  }));

  const cleanup = () => {
    let changed = false;
    const cutoff = now() - JOB_RETENTION_MS;
    for (const [jobId, job] of jobs) {
      if (job.state !== "RUNNING" && job.finishedAt < cutoff) {
        jobs.delete(jobId);
        changed = true;
      }
    }
    const terminal = [...jobs.values()]
      .filter((job) => job.state !== "RUNNING")
      .sort((a, b) => a.finishedAt - b.finishedAt);
    while (jobs.size > MAX_JOBS && terminal.length) {
      jobs.delete(terminal.shift().jobId);
      changed = true;
    }
    return changed;
  };

  const ensureLoaded = async () => {
    if (loaded) return;
    if (!loading) {
      loading = (async () => {
        const rows = await store.load();
        const runningControls = new Set();
        for (const row of rows) {
          const job = validatePersistedJob(row);
          if (jobs.has(job.jobId)) throw Error("demo job journal invalid");
          if (job.state === "RUNNING") {
            if (runningControls.has(job.control)) throw Error("demo job journal has duplicate active control");
            runningControls.add(job.control);
            activeByControl.set(job.control, job.jobId);
          }
          jobs.set(job.jobId, job);
        }
        const changed = cleanup();
        if (changed) await store.save(persistedRows());
        loaded = true;
      })();
    }
    try { await loading; } finally { if (!loaded) loading = null; }
  };

  const persist = async () => store.save(persistedRows());

  const finish = async (job, state, values = {}) => {
    job.state = state;
    job.finishedAt = now();
    Object.assign(job, values);
    if (activeByControl.get(job.control) === job.jobId) activeByControl.delete(job.control);
    cleanup();
    await persist();
  };

  const reconcile = async (job) => {
    if (job.state !== "RUNNING") return publicJob(job);

    const status = await run(["codebuild", "batch-get-builds", "--ids", job.buildId]);
    const notFound = Array.isArray(status?.buildsNotFound) && status.buildsNotFound.includes(job.buildId);
    if (notFound) {
      await finish(job, "UNKNOWN", {
        error: "Previous demo job is no longer available in CodeBuild; provider outcome is not verified. Refresh Config evidence before retrying.",
      });
      return publicJob(job);
    }

    const builds = Array.isArray(status?.builds) ? status.builds : [];
    if (builds.length !== 1) throw Error("CodeBuild status unavailable");
    const build = builds[0];
    if (!TERMINAL.has(build.buildStatus)) return publicJob(job);

    if (build.buildStatus !== "SUCCEEDED") {
      await finish(job, "UNKNOWN", {
        error: "Previous demo job ended without verified provider evidence. Refresh Config evidence before retrying.",
      });
      return publicJob(job);
    }

    try {
      await finish(job, "SUCCEEDED", { result: validatedResult(job.control, build) });
    } catch {
      await finish(job, "UNKNOWN", {
        error: "Previous demo job completed but its provider result could not be verified. Refresh Config evidence before retrying.",
      });
    }
    return publicJob(job);
  };

  return {
    controls: CONTROLS,
    recovery: "persistent-journal",

    async start(control) {
      if (!CONTROLS.includes(control)) throw Error("unsupported demo control");
      await ensureLoaded();
      if (cleanup()) await persist();
      const existingId = activeByControl.get(control);
      if (existingId) {
        const existing = jobs.get(existingId);
        if (existing?.state === "RUNNING") {
          await reconcile(existing);
          return publicJob(existing, true);
        }
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
      await persist();
      return publicJob(job);
    },

    async status(jobId) {
      await ensureLoaded();
      if (cleanup()) await persist();
      const job = jobs.get(jobId);
      if (!job) return null;
      if (job.state !== "RUNNING") return publicJob(job);

      return reconcile(job);
    },
  };
}
