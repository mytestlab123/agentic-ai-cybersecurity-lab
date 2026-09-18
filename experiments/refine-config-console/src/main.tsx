import React, { useEffect, useState, useRef } from "react";
import { createRoot } from "react-dom/client";
import { Refine, useOne, type DataProvider } from "@refinedev/core";
import { Button, Sheet } from "./ui";
import { categories, category as classify, frequency } from "../model.mjs";
import "./style.css";

type Rule = Record<string, any> & {
  id: string; accountAlias?: string; category: string; status: string;
  count: number | null; capped: boolean; warning: boolean;
};
type AccountStatus = { alias: string; available: boolean; fetchedAt: string | null; ruleCount: number | null };
type Snapshot = {
  id?: string; environment: string; rules: Rule[]; recorders: Record<string, any>[];
  fetchedAt: string | null; available?: boolean; partial?: boolean;
  availableAccounts?: number; totalAccounts?: number; accounts?: AccountStatus[];
};
type Resource = Record<string, string>;
const FOUR_ACCOUNTS = ["ACCOUNT_A", "ACCOUNT_B", "ACCOUNT_C", "ACCOUNT_D"];
async function request(url: string) {
  const response = await fetch(url, { cache: "no-store" });
  const body = await response.json();
  if (!response.ok) throw Error(body.error || "Read failed");
  return body;
}
const blocked = async (): Promise<never> => { throw Error("Read-only data provider"); };
const dataProvider: DataProvider = {
  getApiUrl: () => "/api", getList: blocked, create: blocked, update: blocked, deleteOne: blocked,
  getOne: async ({ id, meta }) => ({ data: await request(
    `/api/controls?environment=${encodeURIComponent(String(id))}&refresh=${meta?.refresh ? 1 : 0}`,
  ) }),
};
const date = (value?: string | null) => value && Number.isFinite(Date.parse(value))
  ? new Date(value).toLocaleString() : "Not reported";
function Status({ value }: { value: string }) {
  return <span className={`inline-block rounded px-2 py-1 text-[10px] font-semibold whitespace-nowrap ${value === "NON_COMPLIANT" ? "bg-red-50 text-red-800" : value === "COMPLIANT" ? "bg-emerald-50 text-emerald-800" : "bg-amber-50 text-amber-900"}`}>{value.replaceAll("_", " ")}</span>;
}
function Fields({ value }: { value: Record<string, any> }) {
  return <dl>{Object.entries(value).map(([key, val]) => <React.Fragment key={key}>
    <dt>{key}</dt><dd>{val == null ? "Not reported" : typeof val === "object" ? JSON.stringify(val) : String(val)}</dd>
  </React.Fragment>)}</dl>;
}
function App() {
  const [environment, setEnvironment] = useState(""), [environments, setEnvironments] = useState<string[]>([]),
    [allAccounts, setAllAccounts] = useState(false), [category, setCategory] = useState("All Controls"),
    [search, setSearch] = useState(""), [status, setStatus] = useState("ALL"), [sort, setSort] = useState("status"),
    [descending, setDescending] = useState(false), [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState<Rule | null>(null), [resources, setResources] = useState<Resource[]>([]),
    [token, setToken] = useState<string | undefined>(), [detailError, setDetailError] = useState(""),
    [loading, setLoading] = useState(false), [observed, setObserved] = useState<Record<string, string[]>>({});
  const [mode, setMode] = useState("Checking mode");
  const detailGeneration = useRef(0);
  const { query } = useOne<Snapshot>({ resource: "controls", id: environment || "UNSELECTED", meta: { refresh },
    queryOptions: { enabled: Boolean(environment), retry: false, refetchOnWindowFocus: false,
      refetchOnReconnect: false, staleTime: Infinity } });
  // Never label a failed refresh or another selection's cached rows as current.
  const snapshot = !query.isError && query.data?.data.environment === environment ? query.data.data : undefined;
  const hasEvidence = Boolean(snapshot && snapshot.available !== false);
  useEffect(() => {
    let cancelled = false;
    request("/api/health").then((health) => {
      const aliases = health.allAccounts === true ? FOUR_ACCOUNTS : ["DEV", "PROD"];
      if (health.region !== "ap-southeast-1" || !["SYNTHETIC", "AWS_READ_ONLY"].includes(health.mode) ||
          !Array.isArray(health.environments) || health.environments.length !== aliases.length ||
          !aliases.every((alias) => health.environments.filter((x: string) => x === alias).length === 1))
        throw Error("Unsupported account configuration");
      if (cancelled) return;
      setMode(health.mode); setEnvironments(aliases); setAllAccounts(health.allAccounts === true);
      setEnvironment(health.allAccounts === true ? "ALL" : aliases[0]);
    }).catch(() => { if (!cancelled) setMode("Unavailable"); });
    return () => { cancelled = true; };
  }, []);
  const closeDetail = () => {
    detailGeneration.current++; setSelected(null); setResources([]); setToken(undefined); setDetailError("");
  };
  const changeEnvironment = (value: string) => { closeDetail(); setObserved({}); setEnvironment(value); };
  const openRule = (rule: Rule) => {
    detailGeneration.current++; setResources([]); setToken(undefined); setDetailError(""); setSelected(rule);
  };
  // Each drawer binds the selected row's account, never the All Accounts selector.
  useEffect(() => {
    const generation = ++detailGeneration.current;
    if (!selected) return;
    const controller = new AbortController();
    setLoading(true);
    fetch(`/api/resources?environment=${encodeURIComponent(selected.accountAlias || environment)}&rule=${encodeURIComponent(selected.id)}`,
      { signal: controller.signal, cache: "no-store" })
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok || !Array.isArray(body.resources)) throw Error(body.error || "Resource read failed");
        return body;
      }).then((body) => {
        if (controller.signal.aborted || generation !== detailGeneration.current) return;
        setResources(body.resources); setToken(body.nextToken);
        setObserved((old) => ({ ...old, [selected.id]: body.resources.map((x: Resource) => x.ResourceType) }));
      }).catch((error) => {
        if (!controller.signal.aborted && generation === detailGeneration.current) setDetailError(error.message);
      }).finally(() => {
        if (!controller.signal.aborted && generation === detailGeneration.current) setLoading(false);
      });
    return () => controller.abort();
  }, [environment, selected]);
  const rules: Rule[] = (hasEvidence ? snapshot?.rules || [] : []).map((r) => ({ ...r, category: classify(r, observed[r.id] || []) }));
  const filtered = rules.filter((r) => (category === "All Controls" || r.category === category) &&
    (status === "ALL" || r.status === status) &&
    `${r.accountAlias || ""} ${r.ConfigRuleName} ${r.Source?.SourceIdentifier} ${r.Description || ""}`.toLowerCase().includes(search.toLowerCase()));
  const ranks: Record<string, number> = { NON_COMPLIANT: 0, INSUFFICIENT_DATA: 1, NOT_REPORTED: 2, COMPLIANT: 3, NOT_APPLICABLE: 4 };
  filtered.sort((a, b) => {
    let comparison = 0;
    if (sort === "name") comparison = a.ConfigRuleName.localeCompare(b.ConfigRuleName);
    else if (sort === "count") comparison = (b.count ?? -1) - (a.count ?? -1);
    else if (sort === "time") comparison = (Date.parse(b.health.LastSuccessfulEvaluationTime) || 0) - (Date.parse(a.health.LastSuccessfulEvaluationTime) || 0);
    else comparison = (ranks[a.status] ?? 5) - (ranks[b.status] ?? 5);
    return (comparison || a.ConfigRuleName.localeCompare(b.ConfigRuleName) || a.id.localeCompare(b.id)) * (descending ? -1 : 1);
  });
  const loadMore = async () => {
    if (!selected || !token) return;
    setLoading(true); setDetailError(""); const generation = detailGeneration.current;
    try {
      const body = await request(`/api/resources?environment=${encodeURIComponent(selected.accountAlias || environment)}&rule=${encodeURIComponent(selected.id)}&token=${encodeURIComponent(token)}`);
      if (generation !== detailGeneration.current) return;
      if (!Array.isArray(body.resources)) throw Error("Resource read failed");
      setResources((old) => [...old, ...body.resources]); setToken(body.nextToken);
      setObserved((old) => ({ ...old, [selected.id]: [...(old[selected.id] || []), ...body.resources.map((x: Resource) => x.ResourceType)] }));
    } catch (error) { if (generation === detailGeneration.current) setDetailError((error as Error).message); }
    finally { if (generation === detailGeneration.current) setLoading(false); }
  };
  return <div className="min-h-screen flex">
    <aside className="w-52 shrink-0 border-r bg-white p-4">
      <div className="text-lg font-bold mb-1">SecCop</div><div className="text-xs text-slate-500 mb-9">Config control explorer</div>
      <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-3">Controls</div>
      <nav aria-label="Control categories">{["All Controls", ...categories].map((c) => {
        const group = rules.filter((r) => c === "All Controls" || r.category === c);
        return <button key={c} onClick={() => setCategory(c)} aria-pressed={category === c}
          className={`flex w-full justify-between items-center rounded px-3 py-3 text-sm mb-1 ${category === c ? "bg-slate-900 text-white" : "hover:bg-slate-100"}`}>
          <span>{c}</span><span title={`${group.filter((r) => r.status === "NON_COMPLIANT").length} non-compliant`} className="text-xs opacity-70">
            {hasEvidence ? `${group.length} / ${group.filter((r) => r.status === "NON_COMPLIANT").length}` : "--"}
          </span></button>;
      })}</nav>
      <p className="text-xs text-slate-400 mt-6">Counts: total / non-compliant</p>
      <p className="text-xs text-slate-500 mt-12">Read-only exploration<br />No remediation actions</p>
    </aside>
    <main className="min-w-0 flex-1 p-7">
      <header className="flex flex-wrap justify-between items-start gap-4 mb-6">
        <div><p className="text-xs text-slate-500 mb-1">AWS CONFIG - SINGAPORE</p><h1 className="text-2xl font-semibold">Config controls</h1>
          <p className="text-sm text-slate-500 mt-1">{allAccounts ? "One account and control per row. The same rule in four accounts counts as four checks." : "One control per row. Open a control to inspect its affected resources."}</p></div>
        <div className="flex flex-wrap items-center gap-3"><label className="text-xs">{allAccounts ? "Account" : "Environment"}{" "}
          <select aria-label={allAccounts ? "Account" : "Environment"} value={environment} disabled={!environments.length} onChange={(e) => changeEnvironment(e.target.value)}>
            {!environments.length && <option value="">Loading accounts</option>}
            {allAccounts && <option value="ALL">All Accounts</option>}
            {environments.map((alias) => <option key={alias} value={alias}>{alias}</option>)}
          </select></label>
          <Button disabled={!environment || query.isFetching} onClick={() => { closeDetail(); setObserved({}); setRefresh((x) => x + 1); }}>Refresh</Button>
        </div>
      </header>
      <div className="flex flex-wrap justify-between text-xs text-slate-500 mb-5"><span>{mode} - ap-southeast-1 - provider reads only</span>
        <span>{allAccounts ? "Oldest included fetch" : "Fetched"}: {date(snapshot?.fetchedAt)}</span></div>
      {mode === "Unavailable" && <p role="alert" className="text-red-700 mb-4">Account configuration unavailable. No provider read has been started.</p>}
      {allAccounts && <section aria-label="Account availability" className="flex flex-wrap gap-2 mb-4">{environments.map((alias) => {
        const account = snapshot?.accounts?.find((item) => item.alias === alias);
        return <Button key={alias} variant="outline" onClick={() => changeEnvironment(alias)} aria-pressed={environment === alias}>
          {alias}: {query.isFetching ? "Loading" : account ? account.available ? "Read available" : "Unavailable" : "Not in current view"}
        </Button>;
      })}</section>}
      {snapshot?.partial && <p role="alert" className="border border-amber-200 bg-amber-50 p-4 rounded mb-5">
        Partial evidence: {snapshot.availableAccounts} of {snapshot.totalAccounts} accounts available. Counts exclude unavailable accounts; they are not compliant.</p>}
      {query.isError && <div role="alert" className="border border-red-200 bg-red-50 p-4 rounded mb-5">{query.error?.message}. No successful inventory is asserted.</div>}
      {query.isFetching && <p role="status" className="mb-3 text-sm">Reading inventory...</p>}
      <section aria-label="Control summary" className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-5">{[
        [allAccounts ? "Total account/control checks" : "Total controls", rules.length],
        ["Non-compliant", rules.filter((r) => r.status === "NON_COMPLIANT").length],
        ["Compliant", rules.filter((r) => r.status === "COMPLIANT").length],
        ["Insufficient data / evaluation attention", rules.filter((r) => ["INSUFFICIENT_DATA", "NOT_REPORTED"].includes(r.status) || r.warning).length],
      ].map(([label, count]) => <div key={label} className="rounded-lg border border-slate-200 bg-white p-4">
        <div className="text-xs text-slate-500 min-h-8">{label}</div><div className="text-2xl font-semibold">{hasEvidence ? count : "--"}</div>
        {snapshot?.partial && <div className="text-xs text-amber-800">Available accounts only</div>}
      </div>)}</section>
      <div className="text-xs text-slate-500 mb-5">Recorder: {hasEvidence && snapshot
        ? snapshot.recorders.length ? snapshot.recorders.map((r) => `${r.accountAlias ? r.accountAlias + ": " : ""}${r.recording === true ? "Recording" : r.recording === false ? "Not recording" : "Not reported"} - ${r.lastStatus || "Not reported"} - ${date(r.lastStatusChangeTime)}${r.lastErrorCode ? ` - ${r.lastErrorCode}: ${r.lastErrorMessage || ""}` : ""}`).join("; ")
          : "No recorder status returned" : "Not loaded"}</div>
      <section className="rounded-lg border border-slate-200 bg-white overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 p-4 border-b border-slate-200">
          <input aria-label="Search controls" placeholder={allAccounts ? "Search account, name, AWS rule, description" : "Search name, AWS rule, description"} value={search} onChange={(e) => setSearch(e.target.value)} className="min-w-64 flex-1" />
          <select aria-label="Compliance filter" value={status} onChange={(e) => setStatus(e.target.value)}>{["ALL", "NON_COMPLIANT", "COMPLIANT", "INSUFFICIENT_DATA", "NOT_APPLICABLE", "NOT_REPORTED"].map((x) => <option key={x} value={x}>{x.replaceAll("_", " ")}</option>)}</select>
          <select aria-label="Sort controls" value={sort} onChange={(e) => setSort(e.target.value)}><option value="status">Compliance</option><option value="name">Control name</option><option value="count">Non-compliant count</option><option value="time">Last evaluated</option></select>
          <Button variant="outline" onClick={() => setDescending((x) => !x)} aria-label="Reverse sort order">{descending ? "Ascending" : "Descending"}</Button>
        </div>
        <div className="overflow-x-auto"><table className="w-full"><thead><tr>{[
          "Status", ...(allAccounts ? ["Account"] : []), "Control", "Category", "AWS rule", "Scope", "Trigger", "Mode", "Non-compliant", "Last evaluated", "Health",
        ].map((x) => <th key={x}>{x}</th>)}</tr></thead><tbody>{filtered.map((r) => <tr key={r.id} className="hover:bg-slate-50">
          <td><Status value={r.status} /></td>{allAccounts && <td>{r.accountAlias}</td>}
          <td><button className="text-blue-700 text-left font-medium hover:underline" title={r.Description} onClick={() => openRule(r)}>{r.ConfigRuleName}</button></td>
          <td>{r.category}</td><td className="max-w-48 break-words">{r.Source?.SourceIdentifier}<div className="text-slate-400 text-[10px]">{r.Source?.Owner}</div></td>
          <td>{r.Scope?.ComplianceResourceTypes?.join(", ") || "Not scoped by type"}</td><td>{r.trigger}</td>
          <td>{r.EvaluationModes?.map((m: any) => m.Mode).join(", ") || "Not reported"}</td>
          <td>{r.count == null ? "--" : `${r.count}${r.capped ? "+" : ""}`}</td><td className="whitespace-nowrap">{date(r.health.LastSuccessfulEvaluationTime)}</td>
          <td>{r.warning ? <span className="text-amber-800" title={r.health.LastErrorMessage}>Recent failure</span> : "--"}</td>
        </tr>)}</tbody></table>
        {!filtered.length && !query.isFetching && <p className="p-8 text-center text-slate-500">{!hasEvidence ? "Inventory unavailable" : "No matching controls"}</p>}</div>
        <footer className="p-3 border-t text-xs text-slate-500">{hasEvidence ? `${filtered.length} of ${rules.length}` : "No current"} {allAccounts ? "account/control checks" : "controls"} - "+" is a capped provider count, not an exact total.{snapshot?.partial ? " Partial scope." : ""}</footer>
      </section>
    </main>
    <Sheet open={Boolean(selected)} onOpenChange={(open) => { if (!open) closeDetail(); }} title={selected ? `${selected.accountAlias ? selected.accountAlias + " / " : ""}${selected.ConfigRuleName}` : "Control"}>
      {selected && <div className="detail"><h3>Overview</h3><p className="text-sm mb-4">{selected.Description || "No description reported"}</p>
        <Fields value={{ ...(selected.accountAlias ? {Account: selected.accountAlias} : {}), Compliance: selected.status,
          [selected.accountAlias ? "Console key" : "Rule ID"]: selected.ConfigRuleId,
          Owner: selected.Source?.Owner, "AWS rule": selected.Source?.SourceIdentifier, State: selected.ConfigRuleState,
          Scope: selected.Scope, Category: classify(selected, observed[selected.id] || []), Trigger: selected.trigger,
          Frequency: frequency(selected), Mode: selected.EvaluationModes, Visibility: selected.RuleEvaluationVisibility, Creator: selected.CreatedBy }} />
        <h3>Input parameters</h3><pre>{(() => { try { return JSON.stringify(JSON.parse(selected.InputParameters || "{}"), null, 2); } catch { return selected.InputParameters; } })()}</pre>
        <h3>Affected resources - NON_COMPLIANT</h3><p className="text-xs text-slate-500 mb-3">Fetched only on opening this control. Empty results do not override the inventory compliance state.{allAccounts ? " Resource identifiers are shown as account-scoped aliases." : ""}</p>
        {loading && <p role="status">Reading resource page...</p>}{detailError && <p role="alert" className="text-red-700">{detailError}</p>}
        {resources.map((r, i) => <div className="border rounded p-3 mb-3" key={`${r.ResourceId}-${i}`}><Fields value={r} /></div>)}
        {!loading && !detailError && !resources.length && <p>No non-compliant resource evaluations returned.</p>}
        {token && <Button onClick={loadMore} disabled={loading}>Load more resources</Button>}
        <h3>Evaluation health</h3><Fields value={Object.fromEntries(["FirstActivatedTime", "LastSuccessfulInvocationTime", "LastFailedInvocationTime", "LastSuccessfulEvaluationTime", "LastFailedEvaluationTime", "LastErrorCode", "LastErrorMessage"].map((key) => [key, selected.health[key]]))} />
        <p className="mt-4 text-xs text-slate-500">Latest provider timestamps only; this is not historical timeline data.</p>
      </div>}
    </Sheet>
  </div>;
}
createRoot(document.getElementById("root")!).render(<Refine dataProvider={dataProvider} options={{ disableTelemetry: true }}><App /></Refine>);
