import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
const script = readFileSync(new URL("../public/theme.js", import.meta.url), "utf8");
function boot({ saved = null, dark = false, denied = false } = {}) {
  const root = { dataset: {} }, listeners = new Map(), writes = [];
  const media = { matches: dark, addEventListener: (event, callback) => listeners.set(event, callback) };
  const storage = { getItem: () => saved, setItem: (...args) => writes.push(args) };
  const window = { matchMedia: () => media, dispatchEvent: () => {} };
  Object.defineProperty(window, "localStorage", { get() { if (denied) throw Error("Storage denied"); return storage; } });
  // No fetch/HTTP/AWS capability is supplied to the theme script.
  vm.runInNewContext(script, { window, document: { documentElement: root }, Event });
  return { root, window, media, writes, system: (value) => { media.matches = value; listeners.get("change")(); } };
}
test("system preference applies before a saved choice; explicit choice overrides later changes", () => {
  const app = boot({ dark: true });
  assert.equal(app.root.dataset.theme, "dark");
  app.system(false);
  assert.equal(app.root.dataset.theme, "light");
  app.window.configConsoleTheme.set("dark");
  app.system(false);
  assert.equal(app.root.dataset.theme, "dark");
  assert.deepEqual(app.writes, [["seccop-config-theme", "dark"]]);
});
test("stored light/dark choices survive a new page; invalid values use system preference", () => {
  for (const saved of ["light", "dark"])
    assert.equal(boot({ saved, dark: saved === "light" }).root.dataset.theme, saved);
  assert.equal(boot({ saved: "untrusted", dark: true }).root.dataset.theme, "dark");
});
test("denied storage does not break startup or toggling", () => {
  const app = boot({ denied: true });
  app.window.configConsoleTheme.set("dark");
  assert.equal(app.root.dataset.theme, "dark");
  app.window.configConsoleTheme.set("light");
  assert.equal(app.root.dataset.theme, "light");
});
test("unknown theme does not change state or write storage", () => {
  const app = boot();
  app.window.configConsoleTheme.set("unexpected");
  assert.equal(app.root.dataset.theme, "light");
  assert.equal(app.writes.length, 0);
});
