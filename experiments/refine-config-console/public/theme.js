// Same-origin blocking head script: presentation only, with no API side effects.
(() => {
  const key = "seccop-config-theme";
  const root = document.documentElement;
  const media = typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  let choice = null;
  try {
    const saved = window.localStorage.getItem(key);
    if (saved === "light" || saved === "dark") choice = saved;
  } catch { /* Storage can be denied; the page and toggle still work. */ }
  function apply() {
    root.dataset.theme = choice || (media?.matches ? "dark" : "light");
    window.dispatchEvent(new Event("config-theme-change"));
  }
  window.configConsoleTheme = {
    set(value) {
      if (value !== "light" && value !== "dark") return;
      choice = value;
      try { window.localStorage.setItem(key, value); } catch { /* Local-only fallback. */ }
      apply();
    },
  };
  apply();
  media?.addEventListener?.("change", () => { if (choice === null) apply(); });
})();
