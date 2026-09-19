import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const MAX_HISTORY = 720;
const safeInt = (value) => Number.isInteger(value) && value >= 0 ? value : 0;

export function summarizeSnapshot(snapshot) {
  if (!snapshot || snapshot.environment !== "ALL" || snapshot.partial || snapshot.available === false)
    return null;
  const rules = Array.isArray(snapshot.rules) ? snapshot.rules : [];
  const accounts = Array.isArray(snapshot.accounts) ? snapshot.accounts : [];
  const compliant = rules.filter((r) => r.status === "COMPLIANT").length;
  const noncompliant = rules.filter((r) => r.status === "NON_COMPLIANT").length;
  const attention = rules.filter((r) => ["INSUFFICIENT_DATA", "NOT_REPORTED"].includes(r.status) || r.warning).length;
  const affected = rules.filter((r) => r.status === "NON_COMPLIANT")
    .reduce((sum, r) => sum + safeInt(r.count), 0);
  const controls = new Map();
  for (const rule of rules) {
    const name = String(rule.ConfigRuleName || "");
    if (!name) continue;
    const row = controls.get(name) || { name, compliant: 0, noncompliant: 0, affected: 0 };
    if (rule.status === "COMPLIANT") row.compliant++;
    if (rule.status === "NON_COMPLIANT") {
      row.noncompliant++;
      row.affected += safeInt(rule.count);
    }
    controls.set(name, row);
  }
  return {
    fetchedAt: snapshot.fetchedAt,
    availableAccounts: safeInt(snapshot.availableAccounts),
    totalAccounts: safeInt(snapshot.totalAccounts),
    totalChecks: rules.length,
    compliant,
    noncompliant,
    attention,
    affectedResources: affected,
    accounts: accounts.map((account) => {
      const scoped = rules.filter((r) => r.accountAlias === account.alias);
      return {
        alias: String(account.alias || ""),
        available: account.available === true,
        compliant: scoped.filter((r) => r.status === "COMPLIANT").length,
        noncompliant: scoped.filter((r) => r.status === "NON_COMPLIANT").length,
      };
    }),
    controls: [...controls.values()].sort((a, b) => a.name.localeCompare(b.name)),
  };
}

export function createHistoryStore({
  file = process.env.CONFIG_HISTORY_FILE || "/var/lib/aws-config-console/history.json",
  max = MAX_HISTORY,
} = {}) {
  let writeQueue = Promise.resolve();

  async function readRows() {
    try {
      const value = JSON.parse(await readFile(file, "utf8"));
      return Array.isArray(value) ? value : [];
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      throw error;
    }
  }

  function serialize(task) {
    const next = writeQueue.catch(() => undefined).then(task);
    writeQueue = next.then(() => undefined, () => undefined);
    return next;
  }

  async function record(snapshot) {
    const entry = summarizeSnapshot(snapshot);
    if (!entry?.fetchedAt) return null;
    return serialize(async () => {
      const rows = await readRows();
      if (rows.at(-1)?.fetchedAt === entry.fetchedAt) return rows.at(-1);
      rows.push(entry);
      const bounded = rows.slice(-max);
      await mkdir(path.dirname(file), { recursive: true });
      const temp = file + ".tmp";
      await writeFile(temp, JSON.stringify(bounded), { mode: 0o600 });
      await rename(temp, file);
      return entry;
    });
  }

  async function list(limit = 60) {
    await writeQueue;
    const bounded = Math.max(1, Math.min(365, Number(limit) || 60));
    return (await readRows()).slice(-bounded);
  }

  return { record, list };
}

export function createMemoryHistoryStore() {
  const rows = [];
  return {
    async record(snapshot) {
      const entry = summarizeSnapshot(snapshot);
      if (!entry?.fetchedAt) return null;
      if (rows.at(-1)?.fetchedAt !== entry.fetchedAt) rows.push(entry);
      return entry;
    },
    async list(limit = 60) { return rows.slice(-Math.max(1, Math.min(365, Number(limit) || 60))); },
  };
}
