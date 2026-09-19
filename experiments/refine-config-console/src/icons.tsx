import type { ReactNode } from "react";

// Two Lucide adaptations (shield-check/server); other geometric symbols are local.
// No CDN, icon font, runtime download or raw provider-controlled SVG. See NOTICE.md.
const shapes: Record<string, ReactNode> = {
  shield: <><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></>,
  server: <><rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/></>,
  grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
  bucket: <><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="m4 5 2 14c1.5 3 10.5 3 12 0l2-14M6 13c3 2 9 2 12 0"/></>,
  lambda: <><path d="M5 3h4l9 18h3M11 8 3 21"/></>,
  key: <><circle cx="15.5" cy="8.5" r="5.5"/><path d="m11.5 12.5-8 8H2v-4l3-3 2 2 3-3"/></>,
  layers: <><path d="M12 3 22 8 12 13 2 8Z M2 12l10 5 10-5 M2 16l10 5 10-5"/></>,
  search: <><circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5 5"/></>,
  refresh: <><path d="M20 8a8 8 0 0 0-14-3L3 8m0-5v5h5M4 16a8 8 0 0 0 14 3l3-3m0 5v-5h-5"/></>,
  check: <><circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/></>,
  alert: <><path d="m12 3 10 18H2L12 3ZM12 9v5M12 18h.01"/></>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5"/></>,
  moon: <><path d="M20.5 14.5A9 9 0 0 1 9.5 3.5a9 9 0 1 0 11 11Z"/></>,
  filter: <><path d="M3 6h18M3 12h18M3 18h18M8 3v6M16 9v6M10 15v6"/></>,
  sort: <><path d="M7 3v18m-4-4 4 4 4-4M17 21V3m-4 4 4-4 4 4"/></>,
  menu: <><path d="M3 6h18M3 12h18M3 18h18"/></>,
  close: <><path d="m6 6 12 12M6 18 18 6"/></>,
  chevron: <><path d="m9 5 7 7-7 7"/></>,
  dashboard: <><rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="5" rx="1.5"/><rect x="13" y="10" width="8" height="11" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/></>,
  chart: <><path d="M4 19V10M10 19V5M16 19v-7M22 19V8"/><path d="M2 19h22"/></>,
  settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6 1.7 1.7 0 0 0-.4 1.1V21H9.6v-.09A1.7 1.7 0 0 0 8.5 19.4a1.7 1.7 0 0 0-1.88.34l-.06.06-2.83-2.83.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-.6-1 1.7 1.7 0 0 0-1.1-.4H3V9.6h.09A1.7 1.7 0 0 0 4.6 8.5a1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.83-2.83.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-.6 1.7 1.7 0 0 0 .4-1.1V3h4v.09A1.7 1.7 0 0 0 15.5 4.6a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.83 2.83-.06.06A1.7 1.7 0 0 0 19.4 9c.22.36.58.7 1 .9.34.16.72.23 1.1.2H21v4h-.09A1.7 1.7 0 0 0 19.4 15Z"/></>,
  external: <><path d="M14 3h7v7M10 14 21 3"/><path d="M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"/></>,
};
export const categoryIcon: Record<string, string> = {
  "All Controls": "grid", EC2: "server", S3: "bucket", "Security Groups": "shield",
  Lambda: "lambda", IAM: "key", Other: "layers",
};
export function Icon({ name, size = 18, className = "" }: { name: string; size?: number; className?: string }) {
  return <svg className={`icon ${className}`} width={size} height={size} viewBox="0 0 24 24"
    fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
    aria-hidden="true" focusable="false">{shapes[name] || shapes.layers}</svg>;
}
