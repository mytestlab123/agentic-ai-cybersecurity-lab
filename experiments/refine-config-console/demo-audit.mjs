import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const VERSION = 1;
const MAX_EVENTS = 500;
const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EVENTS = new Set([
  "PREVIEW_CREATED",
  "CONFIRMATION_ACCEPTED",
  "CONFIRMATION_REJECTED",
  "JOB_STARTED",
  "JOB_REUSED",
  "JOB_START_FAILED",
  "JOB_STATUS_READ_FAILED",
  "JOB_COMPLETED",
  "JOB_RECONCILED",
]);
const CONTROLS = new Set([
  "s3-bucket-level-public-access-prohibited",
  "restricted-ssh",
]);
const STATES = new Set([null, "PENDING_CONFIRMATION", "RUNNING", "SUCCEEDED", "UNKNOWN", "REJECTED"]);
const MESSAGE_CODES = new Set([
  "FOUR_ACCOUNT_EVIDENCE_VERIFIED",
  "CONFIRMATION_ACCEPTED",
  "CONFIRMATION_INVALID",
  "JOB_STARTED",
  "ACTIVE_JOB_REUSED",
  "JOB_START_FAILED",
  "CODEBUILD_STATUS_READ_FAILED",
  "PROVIDER_VERIFIED",
  "BUILD_NOT_FOUND",
  "BUILD_TERMINAL_UNVERIFIED",
  "RESULT_UNVERIFIED",
]);

function validateEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) throw Error("demo audit journal invalid");
  const keys = Object.keys(event).sort().join(",");
  if (keys !== "at,control,event,eventId,jobId,messageCode,mutationCount,providerVerified,reused,state")
    throw Error("demo audit journal invalid");
  if (!UUID_RE.test(event.eventId) || !EVENTS.has(event.event) ||
      typeof event.at !== "string" || Number.isNaN(Date.parse(event.at)) ||
      !(event.control === null || CONTROLS.has(event.control)) ||
      !(event.jobId === null || UUID_RE.test(event.jobId)) ||
      !STATES.has(event.state) ||
      !(event.reused === null || typeof event.reused === "boolean") ||
      !(event.mutationCount === null || (Number.isInteger(event.mutationCount) && event.mutationCount >= 0 && event.mutationCount <= 4)) ||
      !(event.providerVerified === null || typeof event.providerVerified === "boolean") ||
      !MESSAGE_CODES.has(event.messageCode))
    throw Error("demo audit journal invalid");
  return { ...event };
}

function normalizeInput(input, at) {
  const allowed = new Set([
    "event", "control", "jobId", "state", "reused",
    "mutationCount", "providerVerified", "messageCode",
  ]);
  for (const key of Object.keys(input || {}))
    if (!allowed.has(key)) throw Error("demo audit event invalid");
  return validateEvent({
    eventId: randomUUID(),
    at: new Date(at).toISOString(),
    event: input.event,
    control: input.control ?? null,
    jobId: input.jobId ?? null,
    state: input.state ?? null,
    reused: input.reused ?? null,
    mutationCount: input.mutationCount ?? null,
    providerVerified: input.providerVerified ?? null,
    messageCode: input.messageCode,
  });
}

export function createDemoAuditStore({
  file = process.env.CONFIG_DEMO_AUDIT_FILE || "/var/lib/aws-config-console/demo-audit.json",
  max = MAX_EVENTS,
  maxAgeMs = MAX_AGE_MS,
  now = Date.now,
} = {}) {
  let queue = Promise.resolve();

  const serialize = (task) => {
    const next = queue.catch(() => undefined).then(task);
    queue = next.then(() => undefined, () => undefined);
    return next;
  };

  const readEvents = async () => {
    try {
      const value = JSON.parse(await readFile(file, "utf8"));
      if (!value || value.version !== VERSION || !Array.isArray(value.events))
        throw Error("demo audit journal invalid");
      return value.events.map(validateEvent);
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      if (String(error?.message) === "demo audit journal invalid") throw error;
      throw Error("demo audit journal invalid");
    }
  };

  const bounded = (events) => {
    const cutoff = now() - maxAgeMs;
    return events
      .filter((event) => Date.parse(event.at) >= cutoff)
      .slice(-max);
  };

  return {
    async record(input) {
      const event = normalizeInput(input, now());
      return serialize(async () => {
        const events = bounded([...(await readEvents()), event]);
        await mkdir(path.dirname(file), { recursive: true });
        const temp = file + ".tmp";
        await writeFile(temp, JSON.stringify({ version: VERSION, events }), { mode: 0o600 });
        await rename(temp, file);
        return event;
      });
    },
    async list(limit = 100) {
      await queue;
      const size = Math.max(1, Math.min(200, Number(limit) || 100));
      return bounded(await readEvents()).slice(-size).reverse();
    },
    async diagnostics() {
      await queue;
      const events = bounded(await readEvents());
      return {
        status: "READY",
        events: events.length,
        latestAt: events.at(-1)?.at || null,
        retentionDays: 30,
        maxEvents: max,
      };
    },
  };
}

export function createMemoryDemoAuditStore({ now = Date.now } = {}) {
  const events = [];
  return {
    async record(input) {
      const event = normalizeInput(input, now());
      events.push(event);
      return event;
    },
    async list(limit = 100) {
      const size = Math.max(1, Math.min(200, Number(limit) || 100));
      return events.slice(-size).reverse().map((event) => ({ ...event }));
    },
    async diagnostics() {
      return {
        status: "READY",
        events: events.length,
        latestAt: events.at(-1)?.at || null,
        retentionDays: 30,
        maxEvents: 500,
      };
    },
  };
}
