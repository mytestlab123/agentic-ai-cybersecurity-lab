import React, { useEffect, useState, useRef } from "react";
import { createRoot } from "react-dom/client";
import { Refine, useOne, type DataProvider } from "@refinedev/core";
import { Button, Sheet, ThemeToggle } from "./ui";
import { Icon, categoryIcon } from "./icons";
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
type HistorySnapshot = {
  fetchedAt: string; compliant: number; noncompliant: number; attention: number;
  affectedResources: number; totalChecks: number; availableAccounts: number; totalAccounts: number;
};
type DemoPreview = {
  control: string; confirmationToken: string; aliases: string[];
  current: { alias: string; status: string }[]; targetState: string; resourceCount: number; note: string;
};
const SYNTHETIC_ACCOUNTS = ["ACCOUNT_A", "ACCOUNT_B", "ACCOUNT_C", "ACCOUNT_D"];
const LAB_ACCOUNTS = ["lab-dev", "lab-poc", "lab-qa", "lab-sec"];
async function jsonBody(response: Response, fallback: string) {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    const label = response.status ? `HTTP ${response.status}` : "Gateway error";
    throw Error(`${label}: ${response.statusText || fallback}`);
  }
  let body: any;
  try { body = await response.json(); }
  catch { throw Error(`HTTP ${response.status || "?"}: invalid JSON response`); }
  if (!response.ok) throw Error(body?.error || `HTTP ${response.status}: ${fallback}`);
  return body;
}
async function request(url: string) {
  const response = await fetch(url, { cache: "no-store" });
  return jsonBody(response, "Read failed");
}
async function post(url: string, value: Record<string, any>) {
  const response = await fetch(url, {
    method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(value),
  });
  return jsonBody(response, "Request failed");
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
  const kind = value === "COMPLIANT" ? "good" : value === "NON_COMPLIANT" ? "danger" : "warning";
  return <span className={`status-chip ${kind}`}><Icon name={kind === "good" ? "check" : kind === "danger" ? "alert" : "clock"} size={14} />{value.replaceAll("_", " ")}</span>;
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
  const [history, setHistory] = useState<HistorySnapshot[]>([]);
  const [demoControlsAvailable, setDemoControlsAvailable] = useState(false);
  const [demoOpen, setDemoOpen] = useState(false);
  const [demoPreview, setDemoPreview] = useState<DemoPreview | null>(null);
  const [demoResult, setDemoResult] = useState<Record<string, any> | null>(null);
  const [demoError, setDemoError] = useState("");
  const [demoBusy, setDemoBusy] = useState(false);
  const [selected, setSelected] = useState<Rule | null>(null), [resources, setResources] = useState<Resource[]>([]),
    [token, setToken] = useState<string | undefined>(), [detailError, setDetailError] = useState(""),
    [detailNotice, setDetailNotice] = useState(""), [loading, setLoading] = useState(false),
    [observed, setObserved] = useState<Record<string, string[]>>({});
  const [mode, setMode] = useState("Checking mode");
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [section, setSection] = useState<"dashboard" | "controls" | "accounts">("dashboard");
  const [dashboard, setDashboard] = useState<"management" | "security" | "operations">(() => {
    try {
      const saved = localStorage.getItem("seccop-config-dashboard");
      if (saved === "management" || saved === "security" || saved === "operations") return saved;
    } catch { return "management"; }
    return "management";
  });
  const chooseDashboard = (value: "management" | "security" | "operations") => {
    setDashboard(value); setSection("dashboard");
    try { localStorage.setItem("seccop-config-dashboard", value); } catch { /* Local preference is optional. */ }
  };
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
      const aliases = health.allAccounts === true
        ? (health.mode === "SYNTHETIC" ? SYNTHETIC_ACCOUNTS : LAB_ACCOUNTS)
        : ["DEV", "PROD"];
      if (health.region !== "ap-southeast-1" || !["SYNTHETIC", "AWS_READ_ONLY"].includes(health.mode) ||
          !Array.isArray(health.environments) || health.environments.length !== aliases.length ||
          !aliases.every((alias) => health.environments.filter((x: string) => x === alias).length === 1))
        throw Error("Unsupported account configuration");
      if (cancelled) return;
      setMode(health.mode); setEnvironments(aliases); setAllAccounts(health.allAccounts === true);
      setDemoControlsAvailable(health.demoControls === true);
      setEnvironment(health.allAccounts === true ? "ALL" : aliases[0]);
    }).catch(() => { if (!cancelled) setMode("Unavailable"); });
    return () => { cancelled = true; };
  }, []);
  const closeDetail = () => {
    detailGeneration.current++; setSelected(null); setResources([]); setToken(undefined); setDetailError(""); setDetailNotice("");
  };
  const changeEnvironment = (value: string) => { closeDetail(); setObserved({}); setEnvironment(value); };
  const openRule = (rule: Rule) => {
    detailGeneration.current++; setResources([]); setToken(undefined); setDetailError(""); setDetailNotice(""); setSelected(rule);
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
        setResources(body.resources); setToken(body.nextToken); setDetailNotice(body.message || "");
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
    (status === "ALL" || (status === "ATTENTION"
      ? ["INSUFFICIENT_DATA", "NOT_REPORTED"].includes(r.status) || r.warning
      : r.status === status)) &&
    `${r.accountAlias || ""} ${r.ConfigRuleName} ${r.Source?.SourceIdentifier} ${r.Description || ""}`.toLowerCase().includes(search.toLowerCase()));
  const ranks: Record<string, number> = { NON_COMPLIANT: 0, INSUFFICIENT_DATA: 1, NOT_REPORTED: 2, COMPLIANT: 3, NOT_APPLICABLE: 4 };
  filtered.sort((a, b) => {
    let comparison = 0;
    if (sort === "name") comparison = a.ConfigRuleName.localeCompare(b.ConfigRuleName);
    else if (sort === "account") comparison = (a.accountAlias || "").localeCompare(b.accountAlias || "");
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
  const compliant = rules.filter((r) => r.status === "COMPLIANT").length;
  const noncompliant = rules.filter((r) => r.status === "NON_COMPLIANT").length;
  const attention = rules.filter((r) => ["INSUFFICIENT_DATA", "NOT_REPORTED"].includes(r.status) || r.warning).length;
  const evaluated = compliant + noncompliant;
  const compliancePct = evaluated ? Math.round((compliant / evaluated) * 100) : 0;
  const affectedResources = rules.filter((r) => r.status === "NON_COMPLIANT").reduce((sum, r) => sum + (r.count ?? 0), 0);
  const accountsAtRisk = new Set(rules.filter((r) => r.status === "NON_COMPLIANT").map((r) => r.accountAlias).filter(Boolean)).size;
  const metrics = [
    { label: allAccounts ? "Account / control checks" : "Controls", count: rules.length, icon: "grid", tone: "neutral" },
    { label: "Compliance", count: hasEvidence ? compliancePct + "%" : "--", icon: "check", tone: "good" },
    { label: "Non-compliant checks", count: noncompliant, icon: "alert", tone: "danger" },
    { label: "Affected resources", count: affectedResources, icon: "layers", tone: "warning" },
  ];
  const controlGroups = Object.values(rules.reduce((acc: Record<string, any>, r) => {
    const key = r.ConfigRuleName;
    acc[key] ||= { name: key, category: r.category, total: 0, compliant: 0, noncompliant: 0, affected: 0 };
    acc[key].total++;
    if (r.status === "COMPLIANT") acc[key].compliant++;
    if (r.status === "NON_COMPLIANT") { acc[key].noncompliant++; acc[key].affected += r.count ?? 0; }
    return acc;
  }, {})).sort((a: any, b: any) => b.noncompliant - a.noncompliant || a.name.localeCompare(b.name)) as any[];
  const accountGroups = environments.map((alias) => {
    const group = rules.filter((r) => r.accountAlias === alias);
    const account = snapshot?.accounts?.find((item) => item.alias === alias);
    return { alias, available: account?.available !== false, total: group.length,
      compliant: group.filter((r) => r.status === "COMPLIANT").length,
      noncompliant: group.filter((r) => r.status === "NON_COMPLIANT").length };
  });
  const heatmapRows = controlGroups.map((group: any) => ({
    name: group.name,
    cells: environments.map((alias) => {
      const rule = rules.find((item) => item.accountAlias === alias && item.ConfigRuleName === group.name);
      const account = accountGroups.find((item) => item.alias === alias);
      return { alias, available: account?.available !== false, status: rule?.status || "UNAVAILABLE" };
    }),
  }));
  useEffect(() => {
    if (environment !== "ALL" || !snapshot?.fetchedAt) return;
    let cancelled = false;
    request("/api/history?limit=30")
      .then((value) => { if (!cancelled) setHistory(Array.isArray(value.snapshots) ? value.snapshots : []); })
      .catch(() => { if (!cancelled) setHistory([]); });
    return () => { cancelled = true; };
  }, [environment, snapshot?.fetchedAt]);
  const previousHistorical = [...history].reverse().find((item) => item.fetchedAt !== snapshot?.fetchedAt);
  const trend = (current: number, previous: number | undefined, inverse = false) => {
    if (previous === undefined) return { text: "Historical baseline", kind: "neutral" };
    const delta = current - previous;
    if (delta === 0) return { text: "No change", kind: "neutral" };
    const good = inverse ? delta < 0 : delta > 0;
    return { text: (delta > 0 ? "+" : "") + delta + " vs previous snapshot", kind: good ? "good" : "danger" };
  };
  const trends = [
    { label: "Compliant checks", value: compliant, ...trend(compliant, previousHistorical?.compliant) },
    { label: "Non-compliant checks", value: noncompliant, ...trend(noncompliant, previousHistorical?.noncompliant, true) },
    { label: "Affected resources", value: affectedResources, ...trend(affectedResources, previousHistorical?.affectedResources, true) },
  ];
  const domainFor = (rule: Rule) => rule.category === "S3" ? "Storage"
    : rule.category === "Security Groups" ? "Network"
      : ["EC2", "Lambda"].includes(rule.category) ? "Compute"
        : rule.category === "IAM" ? "Identity" : "Other";
  const domainGroups = ["Storage", "Network", "Compute", "Identity", "Other"].map((name) => {
    const scoped = rules.filter((rule) => domainFor(rule) === name);
    return {
      name, total: scoped.length,
      noncompliant: scoped.filter((rule) => rule.status === "NON_COMPLIANT").length,
      affected: scoped.filter((rule) => rule.status === "NON_COMPLIANT").reduce((sum, rule) => sum + (rule.count ?? 0), 0),
    };
  }).filter((item) => item.total > 0);
  const previewDemo = async (control: string) => {
    setDemoBusy(true); setDemoError(""); setDemoResult(null);
    try { setDemoPreview(await post("/api/demo/preview", { control })); }
    catch (error) { setDemoError((error as Error).message); setDemoPreview(null); }
    finally { setDemoBusy(false); }
  };
  const rearmDemo = async () => {
    if (!demoPreview) return;
    setDemoBusy(true); setDemoError("");
    try {
      const started = await post("/api/demo/rearm", {
        control: demoPreview.control, confirmationToken: demoPreview.confirmationToken,
      });
      if (!started?.jobId) throw Error("Demo job did not start correctly");
      setDemoPreview(null);
      if (started.state === "SUCCEEDED") {
        setDemoResult(started); setRefresh((x) => x + 1); return;
      }
      if (started.state !== "RUNNING")
        throw Error(started.error || "Previous demo job is not verified. Refresh Config evidence before retrying.");
      let result = started;
      for (let attempt = 0; attempt < 180 && result.state === "RUNNING"; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        result = await request("/api/demo/jobs/" + encodeURIComponent(started.jobId));
      }
      if (result.state === "RUNNING") throw Error("Demo re-arm is still running; refresh and try again later");
      if (result.state !== "SUCCEEDED") throw Error(result.error || "Demo re-arm failed");
      setDemoResult(result); setRefresh((x) => x + 1);
    } catch (error) { setDemoError((error as Error).message); }
    finally { setDemoBusy(false); }
  };
  const openHeatmapCell = (alias: string, control: string) => {
    changeEnvironment(alias); setCategory("All Controls"); setStatus("ALL"); setSearch(control); setSection("controls");
  };
  return <div className="app-shell">
    <a href="#main-content" className="skip-link">Skip to controls</a>
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark"><Icon name="shield" size={25} /></span>
        <div><strong>SecCop</strong><small>CONFIG EXPLORER</small></div>
        <button type="button" className="nav-toggle" aria-label="Toggle categories" aria-expanded={navigationOpen}
          aria-controls="category-list" onClick={() => setNavigationOpen((value) => !value)}><Icon name={navigationOpen ? "close" : "menu"} /></button>
      </div>
      <div id="category-list" className={`sidebar-content ${navigationOpen ? "is-open" : ""}`}>
        <div className="sidebar-label">Workspace</div>
        <nav aria-label="Primary navigation">
          <button className="category-button" aria-pressed={section === "dashboard"} onClick={() => { setSection("dashboard"); setNavigationOpen(false); }}><Icon name="dashboard" /><span>Dashboard</span></button>
          <button className="category-button" aria-pressed={section === "controls"} onClick={() => { setSection("controls"); setCategory("All Controls"); setNavigationOpen(false); }}><Icon name="shield" /><span>Controls</span><span className="category-count">{hasEvidence ? rules.length : "--"}</span></button>
          <button className="category-button" aria-pressed={section === "accounts"} onClick={() => { setSection("accounts"); setNavigationOpen(false); }}><Icon name="layers" /><span>Accounts</span><span className="category-count">{environments.length || "--"}</span></button>
        </nav>
        <div className="sidebar-label secondary-label">Control library</div>
        <nav aria-label="Control categories">{["All Controls", ...categories].map((c) => {
          const group = rules.filter((r) => c === "All Controls" || r.category === c);
          return <button key={c} onClick={() => { setCategory(c); setSection("controls"); setNavigationOpen(false); }} aria-pressed={section === "controls" && category === c}
            className="category-button"><Icon name={categoryIcon[c]} /><span>{c}</span>
            <span className="category-count" title={`${group.filter((r) => r.status === "NON_COMPLIANT").length} non-compliant`}>
              {hasEvidence ? `${group.length} / ${group.filter((r) => r.status === "NON_COMPLIANT").length}` : "--"}
            </span></button>;
        })}</nav>
        <p className="sidebar-hint">Counts: total / non-compliant</p>
        <div className="sidebar-footer"><Icon name="shield" /><div>Read-only exploration<small>No remediation actions</small></div></div>
      </div>
    </aside>
    <main id="main-content" className="main-content" tabIndex={-1}>
      <header className="page-header">
        <div><div className="eyebrow">AWS Config · Multi-account security</div>
          <h1>{section === "dashboard" ? "Compliance dashboard" : section === "accounts" ? "Account fleet" : "Config controls"}</h1>
          <p className="muted page-intro">{section === "dashboard" ? "A concise view of compliance posture, risk concentration and operational readiness." : section === "accounts" ? "Scalable account scope and per-account compliance posture." : allAccounts ? "One account and control per row. The same rule in multiple accounts counts as separate checks." : "One control per row. Open a control to inspect its affected resources."}</p></div>
        <div className="header-actions"><ThemeToggle />
          <Button asChild variant="outline"><a href="https://sec.astromedicomp.org/"><Icon name="shield" />Compliance Agent</a></Button>
          {demoControlsAvailable && <Button variant="outline" onClick={() => { setDemoOpen(true); setDemoPreview(null); setDemoResult(null); setDemoError(""); }}><Icon name="settings" />Demo controls</Button>}
          <label className="selector-label">{allAccounts ? "Account" : "Environment"}
            <select aria-label={allAccounts ? "Account" : "Environment"} value={environment} disabled={!environments.length} onChange={(e) => changeEnvironment(e.target.value)}>
              {!environments.length && <option value="">Loading accounts</option>}
              {allAccounts && <option value="ALL">All Accounts</option>}
              {environments.map((alias) => <option key={alias} value={alias}>{alias}</option>)}
            </select></label>
          <Button disabled={!environment || query.isFetching} onClick={() => { closeDetail(); setObserved({}); setRefresh((x) => x + 1); }}>
            <Icon name="refresh" className={query.isFetching ? "spinning" : ""} />Refresh
          </Button>
        </div>
      </header>
      <div className="evidence-bar"><span className={`mode-label ${mode === "SYNTHETIC" ? "synthetic" : ""}`}><Icon name="shield" size={15} />{mode}</span>
        <span className="muted">Provider reads only</span>
        <span className="fetch-time"><Icon name="clock" size={14} />{allAccounts ? "Oldest included fetch" : "Fetched"}: {date(snapshot?.fetchedAt)}</span>
      </div>
      {mode === "Unavailable" && <p role="alert" className="notice danger">Account configuration unavailable. No provider read has been started.</p>}
      {section === "dashboard" && <section className="dashboard-switcher" aria-label="Dashboard view">
        <div><strong>Dashboard view</strong><span className="muted">Saved as your landing view on this browser</span></div>
        <div className="dashboard-tabs">
          <Button variant={dashboard === "management" ? "default" : "outline"} onClick={() => chooseDashboard("management")}><Icon name="chart" />Management</Button>
          <Button variant={dashboard === "security" ? "default" : "outline"} onClick={() => chooseDashboard("security")}><Icon name="shield" />Security</Button>
          <Button variant={dashboard === "operations" ? "default" : "outline"} onClick={() => chooseDashboard("operations")}><Icon name="server" />Operations</Button>
        </div>
      </section>}
      {snapshot?.partial && <p role="alert" className="notice warning"><Icon name="alert" />
        Partial evidence: {snapshot.availableAccounts} of {snapshot.totalAccounts} accounts available. Counts exclude unavailable accounts; they are not compliant.</p>}
      {query.isError && <div role="alert" className="notice danger"><Icon name="alert" />{query.error?.message}. No successful inventory is asserted.</div>}
      {query.isFetching && <p role="status" className="loading-note"><Icon name="refresh" className="spinning" />Reading inventory...</p>}
      {section === "dashboard" && <>
        <section aria-label="Executive summary" className="summary-grid">{metrics.map(({ label, count, icon, tone }) =>
          <div key={label} className={`summary-card ${tone}`}><div className="summary-top"><span>{label}</span><span className="metric-symbol"><Icon name={icon} size={20} /></span></div>
            <strong className="summary-count">{hasEvidence ? count : "--"}</strong>
            <small>{snapshot?.partial ? "Available accounts only" : label === "Compliance" ? compliant + " compliant / " + noncompliant + " non-compliant" : "Current inventory snapshot"}</small>
          </div>)}</section>
        {environment === "ALL" && !snapshot?.partial && <section className="trend-strip" aria-label="Historical changes">
          <div className="trend-intro"><span className="eyebrow">Historical snapshots</span><small>Persisted sanitized server history · previous successful full snapshot</small></div>
          {trends.map((item) => <div key={item.label} className="trend-item"><span>{item.label}</span><b>{item.value}</b><small className={"trend-chip " + item.kind}>{item.text}</small></div>)}
        </section>}
        {dashboard === "management" && <section className="dashboard-grid">
          <article className="insight-card hero-card">
            <div className="card-heading"><div><span className="eyebrow">Overall posture</span><h2>Compliance coverage</h2></div><span className="status-chip good">{compliancePct}% compliant</span></div>
            <div className="compliance-visual">
              <div className="donut" style={{ "--pct": compliancePct } as React.CSSProperties}><div><strong>{compliancePct}%</strong><span>compliant</span></div></div>
              <div className="legend">
                <span><i className="dot good-dot" />Compliant <b>{compliant}</b></span>
                <span><i className="dot danger-dot" />Non-compliant <b>{noncompliant}</b></span>
                <span><i className="dot warning-dot" />Attention <b>{attention}</b></span>
              </div>
            </div>
          </article>
          <article className="insight-card">
            <div className="card-heading"><div><span className="eyebrow">Risk concentration</span><h2>Controls needing attention</h2></div><span className="big-number">{controlGroups.filter((x:any)=>x.noncompliant).length}</span></div>
            <div className="rank-list">{controlGroups.slice(0,5).map((g:any) => <button key={g.name} onClick={() => { setSection("controls"); setSearch(g.name); }} className="rank-row">
              <span><b>{g.name}</b><small>{g.noncompliant} of {g.total} checks non-compliant</small></span>
              <span className="risk-count">{g.affected} resources</span>
            </button>)}</div>
          </article>
          <article className="insight-card wide-card">
            <div className="card-heading"><div><span className="eyebrow">Fleet</span><h2>Accounts needing attention</h2></div><span className="big-number">{accountsAtRisk}/{environments.length}</span></div>
            <div className="fleet-strip">{accountGroups.map((a) => <button key={a.alias} className="fleet-pill" onClick={() => { changeEnvironment(a.alias); setSection("controls"); }}>
              <span className={"fleet-state " + (!a.available ? "warning" : a.noncompliant ? "danger" : "good")} />
              <b>{a.alias}</b><small>{!a.available ? "Unavailable" : a.noncompliant ? a.noncompliant + " issue" + (a.noncompliant===1?"":"s") : "Compliant"}</small>
            </button>)}</div>
          </article>
          <article className="insight-card wide-card heatmap-card">
            <div className="card-heading"><div><span className="eyebrow">Control × account</span><h2>Compliance heatmap</h2></div><span className="muted">Select a cell to investigate</span></div>
            <div className="heatmap-scroll" role="region" aria-label="Account control heatmap" tabIndex={0}>
              <div className="heatmap" style={{ gridTemplateColumns: "minmax(220px,1.4fr) repeat(" + Math.max(environments.length,1) + ",minmax(105px,1fr))" }}>
                <div className="heatmap-head">Control</div>{environments.map((alias) => <div className="heatmap-head" key={alias}>{alias}</div>)}
                {heatmapRows.flatMap((row:any) => [
                  <div className="heatmap-control" key={row.name+"-label"} title={row.name}>{row.name}</div>,
                  ...row.cells.map((cell:any) => {
                    const kind = !cell.available || cell.status === "UNAVAILABLE" ? "unavailable" : cell.status === "COMPLIANT" ? "good" : cell.status === "NON_COMPLIANT" ? "danger" : "warning";
                    return <button key={row.name+"-"+cell.alias} className={"heatmap-cell " + kind} onClick={() => openHeatmapCell(cell.alias,row.name)} aria-label={[cell.alias,row.name,cell.status].join(" ")}>
                      <span>{cell.status === "COMPLIANT" ? "Compliant" : cell.status === "NON_COMPLIANT" ? "Non-compliant" : cell.status.replaceAll("_"," ")}</span>
                    </button>;
                  }),
                ])}
              </div>
            </div>
            <div className="heatmap-legend"><span><i className="dot good-dot"/>Compliant</span><span><i className="dot danger-dot"/>Non-compliant</span><span><i className="dot warning-dot"/>Attention</span><span><i className="dot neutral-dot"/>Unavailable</span></div>
          </article>
        </section>}
        {dashboard === "security" && <section className="dashboard-grid">
          <article className="insight-card wide-card">
            <div className="card-heading"><div><span className="eyebrow">Security view</span><h2>Control risk by account coverage</h2></div><span className="status-chip danger">{noncompliant} open checks</span></div>
            <div className="control-bars">{controlGroups.map((g:any) => <button key={g.name} className="control-bar" onClick={() => { setSection("controls"); setSearch(g.name); }}>
              <span className="bar-label"><b>{g.name}</b><small>{g.affected} affected resources</small></span>
              <span className="bar-track"><i style={{ width: (g.total ? Math.round(g.noncompliant/g.total*100) : 0) + "%" }} /></span>
              <span className="bar-value">{g.noncompliant}/{g.total}</span>
            </button>)}</div>
          </article>
          <article className="insight-card">
            <div className="card-heading"><div><span className="eyebrow">Priority</span><h2>Open findings</h2></div><span className="big-number">{affectedResources}</span></div>
            <p className="muted">Affected-resource count is based on current Config contributor counts. It is not a severity score.</p>
          </article>
          <article className="insight-card wide-card">
            <div className="card-heading"><div><span className="eyebrow">Operational grouping</span><h2>Control domains</h2></div><span className="muted">No framework or severity mapping</span></div>
            <div className="domain-grid">{domainGroups.map((item) => <div className="domain-card" key={item.name}>
              <span>{item.name}</span><b>{item.total} checks</b><small>{item.noncompliant} non-compliant · {item.affected} affected resources</small>
            </div>)}</div>
          </article>
        </section>}
        {dashboard === "operations" && <section className="dashboard-grid">
          <article className="insight-card wide-card">
            <div className="card-heading"><div><span className="eyebrow">Operations view</span><h2>Account fleet health</h2></div><span className="status-chip good">{snapshot?.availableAccounts ?? environments.length}/{snapshot?.totalAccounts ?? environments.length} readable</span></div>
            <div className="account-table">{accountGroups.map((a) => <button key={a.alias} className="account-row" onClick={() => { changeEnvironment(a.alias); setSection("controls"); }}>
              <span><b>{a.alias}</b><small>{a.total} checks</small></span><span>{a.compliant} compliant</span><span className={a.noncompliant ? "danger-text" : "good-text"}>{a.noncompliant} non-compliant</span><Icon name="chevron" size={14}/>
            </button>)}</div>
          </article>
          <article className="insight-card">
            <div className="card-heading"><div><span className="eyebrow">Evidence</span><h2>Inventory freshness</h2></div><Icon name="clock" size={22}/></div>
            <strong className="freshness-value">{date(snapshot?.fetchedAt)}</strong><p className="muted">Oldest included successful fetch for the current scope.</p>
          </article>
        </section>}
      </>}
      {section === "accounts" && <section className="account-fleet-panel">
        <div className="card-heading"><div><span className="eyebrow">Account fleet</span><h2>{environments.length} connected accounts</h2></div><span className="muted">Designed to scale beyond four accounts</span></div>
        <div className="fleet-grid">{accountGroups.map((a) => <button key={a.alias} className="fleet-card" onClick={() => { changeEnvironment(a.alias); setSection("controls"); }}>
          <span className="account-symbol"><Icon name="layers" size={19}/></span><span><b>{a.alias}</b><small>{a.available ? "Read available" : "Unavailable"}</small></span>
          <span className="fleet-metrics"><b>{a.compliant}</b> compliant · <b className={a.noncompliant ? "danger-text":""}>{a.noncompliant}</b> non-compliant</span><Icon name="chevron" size={15}/>
        </button>)}</div>
      </section>}
      <details className="recorder-health"><summary><Icon name="clock" size={16} />Recorder health <span className="muted">Read-only provider status</span></summary>
        <div>{hasEvidence && snapshot ? snapshot.recorders.length ? snapshot.recorders.map((r) =>
          <p key={r.accountAlias || r.name || "recorder"}>{r.accountAlias ? `${r.accountAlias}: ` : ""}{r.recording === true ? "Recording" : r.recording === false ? "Not recording" : "Not reported"} · {r.lastStatus || "Not reported"} · {date(r.lastStatusChangeTime)}{r.lastErrorCode ? ` · ${r.lastErrorCode}: ${r.lastErrorMessage || ""}` : ""}</p>)
          : "No recorder status returned" : "Not loaded"}</div>
      </details>
      <section className={`table-panel ${section === "controls" ? "" : "section-secondary"}`} aria-label="Control inventory">
        <div className="table-heading"><h2>{category}</h2><span className="muted">{hasEvidence ? filtered.length : "--"} shown</span></div>
        <div className="quick-filters" aria-label="Quick views">
          <span className="muted">Quick view</span>
          <button aria-pressed={status === "ALL"} onClick={() => setStatus("ALL")}>All <b>{rules.length}</b></button>
          <button aria-pressed={status === "NON_COMPLIANT"} onClick={() => setStatus("NON_COMPLIANT")}>Non-compliant <b>{noncompliant}</b></button>
          <button aria-pressed={status === "ATTENTION"} onClick={() => setStatus("ATTENTION")}>Attention <b>{attention}</b></button>
        </div>
        <div className="table-toolbar">
          <label className="search-field"><Icon name="search" /><input aria-label="Search controls" placeholder={allAccounts ? "Search account, control or AWS rule" : "Search controls and AWS rules"} value={search} onChange={(e) => setSearch(e.target.value)} /></label>
          <label className="filter-field"><Icon name="filter" /><select aria-label="Compliance filter" value={status} onChange={(e) => setStatus(e.target.value)}>
            {["ALL", "NON_COMPLIANT", "ATTENTION", "COMPLIANT", "INSUFFICIENT_DATA", "NOT_APPLICABLE", "NOT_REPORTED"].map((x) => <option key={x} value={x}>{x === "ALL" ? "All statuses" : x === "ATTENTION" ? "Attention / evaluation issues" : x.replaceAll("_", " ")}</option>)}
          </select></label>
          <select aria-label="Sort controls" value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="status">Compliance priority</option><option value="count">Affected resources</option><option value="name">Control</option>{allAccounts && <option value="account">Account</option>}<option value="time">Last evaluated</option>
          </select>
          <Button className="sort-direction" variant="outline" onClick={() => setDescending((x) => !x)} aria-label={descending ? "Sort ascending" : "Sort descending"} title={descending ? "Sort ascending" : "Sort descending"}>
            <Icon name="sort" /><span>{descending ? "Asc" : "Desc"}</span>
          </Button>
        </div>
        <div className="table-scroll" role="region" aria-label="Scrollable controls table" tabIndex={0}>
          <table><thead><tr>{["Status", ...(allAccounts ? ["Account"] : []), "Control", "Category", "AWS rule", "Scope", "Trigger", "Mode", "Non-compliant", "Last evaluated", "Health"].map((x) => <th scope="col" key={x}>{x}</th>)}</tr></thead>
            <tbody>{filtered.map((r) => <tr key={r.id}><td><Status value={r.status} /></td>{allAccounts && <td><span className="account-tag">{r.accountAlias}</span></td>}
              <td><button className="control-link" title={r.Description} onClick={() => openRule(r)}>{r.ConfigRuleName}<Icon name="chevron" size={14} /></button></td>
              <td><span className="category-cell"><Icon name={categoryIcon[r.category]} size={15} />{r.category}</span></td>
              <td className="aws-rule">{r.Source?.SourceIdentifier}<small className="muted">{r.Source?.Owner}</small></td>
              <td className="scope-cell">{r.Scope?.ComplianceResourceTypes?.join(", ") || "Not scoped by type"}</td><td>{r.trigger}</td>
              <td>{r.EvaluationModes?.map((m: any) => m.Mode).join(", ") || "Not reported"}</td>
              <td className="numeric">{r.count == null ? "--" : `${r.count}${r.capped ? "+" : ""}`}</td><td className="timestamp">{date(r.health.LastSuccessfulEvaluationTime)}</td>
              <td>{r.warning ? <span className="warning-text" title={r.health.LastErrorMessage}>Recent failure</span> : "--"}</td>
            </tr>)}</tbody>
          </table>
          {!filtered.length && !query.isFetching && <p className="empty-state"><Icon name="search" size={28} />{!hasEvidence ? "Inventory unavailable" : "No matching controls"}</p>}
        </div>
        <footer className="table-footer">{hasEvidence ? `${filtered.length} of ${rules.length}` : "No current"} {allAccounts ? "account/control checks" : "controls"} · "+" is a capped provider count, not an exact total.{snapshot?.partial ? " Partial scope." : ""}</footer>
      </section>
      <p className="page-footer"><Icon name="shield" size={14} />Evidence is read-only. Demo controls are a separate bounded personal-LAB preparation path.</p>
    </main>
    <Sheet open={Boolean(selected)} onOpenChange={(open) => { if (!open) closeDetail(); }} title={selected ? `${selected.accountAlias ? selected.accountAlias + " / " : ""}${selected.ConfigRuleName}` : "Control"}>
      {selected && <div className="detail"><div className="detail-status"><Status value={selected.status} /></div><h3>Overview</h3><p>{selected.Description || "No description reported"}</p>
        <Fields value={{ ...(selected.accountAlias ? { Account: selected.accountAlias } : {}), Compliance: selected.status,
          [selected.accountAlias ? "Console key" : "Rule ID"]: selected.ConfigRuleId,
          Owner: selected.Source?.Owner, "AWS rule": selected.Source?.SourceIdentifier, State: selected.ConfigRuleState,
          Scope: selected.Scope, Category: classify(selected, observed[selected.id] || []), Trigger: selected.trigger,
          Frequency: frequency(selected), Mode: selected.EvaluationModes, Visibility: selected.RuleEvaluationVisibility, Creator: selected.CreatedBy }} />
        <h3>Input parameters</h3><pre>{(() => { try { return JSON.stringify(JSON.parse(selected.InputParameters || "{}"), null, 2); } catch { return selected.InputParameters; } })()}</pre>
        <h3><Icon name="layers" />Affected resources · NON_COMPLIANT</h3><p className="muted">Fetched only on opening this control. Empty results do not override the inventory compliance state.{allAccounts ? " Resource identifiers are shown as account-scoped aliases." : ""}</p>
        {loading && <p role="status">Reading resource page...</p>}{detailError && <p role="alert" className="danger-text">{detailError}</p>}
        {detailNotice && <p role="note" className="detail-notice">{detailNotice}</p>}
        {resources.map((r, i) => <div className="resource-card" key={`${r.ResourceId}-${i}`}><Fields value={r} /></div>)}
        {!loading && !detailError && !detailNotice && !resources.length && <p>No non-compliant resource evaluations returned.</p>}
        {token && <Button onClick={loadMore} disabled={loading}><Icon name="layers" />Load more resources</Button>}
        <h3><Icon name="clock" />Evaluation health</h3><Fields value={Object.fromEntries(["FirstActivatedTime", "LastSuccessfulInvocationTime", "LastFailedInvocationTime", "LastSuccessfulEvaluationTime", "LastFailedEvaluationTime", "LastErrorCode", "LastErrorMessage"].map((key) => [key, selected.health[key]]))} />
        <p className="muted">Latest provider timestamps only; this is not historical timeline data.</p>
      </div>}
    </Sheet>
    <Sheet open={demoOpen} onOpenChange={(open) => { setDemoOpen(open); if (!open) { setDemoPreview(null); setDemoResult(null); setDemoError(""); } }}
      title="Demo controls" eyebrow="Personal LAB only"
      description="Re-arm exactly one retained demo resource in each of the four registered LAB accounts. This is not a general remediation console."
      closeLabel="Close demo controls">
      <div className="demo-panel">
        <div className="demo-scope"><Icon name="layers" /><div><strong>Four-account scope</strong><span>lab-dev · lab-poc · lab-qa · lab-sec</span><small>Exactly 4 S3 demo buckets or 4 unattached demo Security Groups. Legacy 100/10 resources are not used.</small></div></div>
        {[
          ["s3-bucket-level-public-access-prohibited", "S3 Block Public Access", "4 retained demo buckets"],
          ["restricted-ssh", "Restricted SSH", "4 retained unattached Security Groups"],
        ].map(([control, title, scope]) => <div className="demo-control-card" key={control}>
          <div><strong>{title}</strong><span>{scope}</span><small>Target starting state: NON_COMPLIANT in all four LAB accounts.</small></div>
          <Button variant="outline" disabled={demoBusy} onClick={() => previewDemo(control)}>{demoBusy ? "Checking…" : "Preview re-arm"}</Button>
        </div>)}
        {demoPreview && <div className="demo-confirm">
          <div className="eyebrow">Confirmation</div>
          <h3>Re-arm {demoPreview.resourceCount} four-account demo resources?</h3>
          <p>{demoPreview.note}</p>
          <div className="demo-state-grid">{demoPreview.current.map((item) => <span key={item.alias}><b>{item.alias}</b><small>{item.status.replaceAll("_"," ")}</small></span>)}</div>
          <p className="muted">The bounded executor will validate the exact retained resources, change only what is necessary, and verify provider state.</p>
          <div className="demo-actions"><Button variant="outline" onClick={() => setDemoPreview(null)} disabled={demoBusy}>Cancel</Button><Button onClick={rearmDemo} disabled={demoBusy}>{demoBusy ? "Re-arming…" : "Confirm re-arm"}</Button></div>
        </div>}
        {demoResult && <div className="notice good"><Icon name="check" /><div><strong>Demo ready</strong><span>4/4 accounts verified NON_COMPLIANT · {demoResult.mutationCount} provider change{demoResult.mutationCount === 1 ? "" : "s"}.</span></div></div>}
        {demoError && <div role="alert" className="notice danger"><Icon name="alert" />{demoError}</div>}
      </div>
    </Sheet>
  </div>;
}
createRoot(document.getElementById("root")!).render(<Refine dataProvider={dataProvider} options={{ disableTelemetry: true }}><App /></Refine>);
