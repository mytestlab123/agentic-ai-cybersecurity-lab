// Opt-in synthetic proof. Owns only its ephemeral loopback server and browser.
import { chromium } from "../../../node_modules/playwright-core/index.mjs";
import { createServer } from "../server.mjs";
import { createMultiAccountProvider, fourAccountFixtureRead } from "../multi-account.mjs";
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";

let clock = Date.now();
const unavailable = new Set(), calls = [], errors = [], external = [], requests = [];
const provider = createMultiAccountProvider(async (alias, operation, params) => {
  calls.push({ alias, operation });
  if (unavailable.has(alias)) throw Error("Synthetic unavailable account");
  return fourAccountFixtureRead(alias, operation, params);
}, () => clock);
const server = createServer(provider, { fixture: true });
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
let browser;
const screenshotDir = process.env.SCREENSHOT_DIR;
async function screenshot(page, name) {
  if (!screenshotDir) return;
  const body = await page.locator("body").innerText();
  assert.ok(body.includes("SYNTHETIC"));
  assert.ok(!/MUST_NOT_LEAK|arn:aws|\b\d{12}\b/.test(body));
  if (await page.getByRole("dialog").count()) {
    await page.getByRole("dialog").evaluate((node) => { node.scrollTop = 0; });
  } else {
    await page.evaluate(() => {
      document.activeElement?.blur();
      window.scrollTo(0, 0);
      const table = document.querySelector(".table-scroll");
      if (table) table.scrollLeft = 0;
    });
  }
  await mkdir(screenshotDir, { recursive: true });
  // Viewport screenshots avoid misleading full-page captures of fixed overlays.
  await page.screenshot({ path: `${screenshotDir}/${name}.png`, fullPage: false });
}
async function rows(page, count) {
  await page.waitForFunction((expected) => document.querySelectorAll("tbody tr").length === expected, count);
}
async function theme(page, value) {
  await page.waitForFunction((expected) => document.documentElement.dataset.theme === expected, value);
  assert.equal(await page.getByRole("button", { name: "Dark mode", exact: true }).getAttribute("aria-pressed"), String(value === "dark"));
}
async function contrast(page) {
  const pairs = await page.evaluate(() => ["body", ".summary-top", ".status-chip.good", ".status-chip.danger", ".status-chip.warning", ".sidebar-hint"].map((selector) => {
    const node = document.querySelector(selector);
    if (!node) return null;
    let parent = node, background = "rgba(0, 0, 0, 0)";
    while (parent && background === "rgba(0, 0, 0, 0)") {
      background = getComputedStyle(parent).backgroundColor;
      parent = parent.parentElement;
    }
    return { selector, foreground: getComputedStyle(node).color, background };
  }).filter(Boolean));
  const luminance = (color) => {
    const rgb = color.match(/[\d.]+/g).slice(0, 3).map(Number).map((c) => {
      c /= 255;
      return c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4;
    });
    return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
  };
  for (const pair of pairs) {
    const a = luminance(pair.foreground), b = luminance(pair.background);
    assert.ok((Math.max(a, b) + .05) / (Math.min(a, b) + .05) >= 4.5, `Text contrast: ${pair.selector}`);
  }
}
async function noPageOverflow(page) {
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "Page must not overflow horizontally");
}
function observe(page) {
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) external.push(request.url());
    if (url.pathname.startsWith("/api/")) requests.push({ method: request.method(), path: url.pathname });
  });
}
try {
  browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}) });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 }, colorScheme: "light" });
  page.setDefaultTimeout(15000);
  observe(page);
  await page.goto(origin);
  await rows(page, 22);
  await theme(page, "light");
  assert.equal(await page.getByLabel("Account", { exact: true }).locator("option").count(), 5);
  assert.equal(await page.getByLabel("Executive summary", { exact: true }).locator(":scope > div").count(), 4);
  assert.equal(await page.getByRole("link", { name: /Admin Control Center/ }).getAttribute("href"), "https://ops.astromedicomp.org/");
  assert.equal((await page.locator("body").innerText()).includes("Singapore"), false);
  assert.equal((await page.locator("body").innerText()).includes("ap-southeast-1"), false);
  await page.getByRole("button", { name: "Security", exact: true }).click();
  await page.getByText("Control risk by account coverage").waitFor();
  await page.reload();
  await page.getByText("Control risk by account coverage").waitFor();
  await page.getByRole("button", { name: "Management", exact: true }).click();
  await page.getByText("Compliance coverage").waitFor();
  await page.getByLabel("Browser session changes", { exact: true }).waitFor();
  assert.ok((await page.getByLabel("Browser session changes", { exact: true }).innerText()).includes("not historical AWS trend data"));
  const heatmap = page.getByLabel("Account control heatmap", { exact: true });
  await heatmap.waitFor();
  assert.ok(await heatmap.locator(".heatmap-cell").count() > 0);
  assert.equal(await page.locator("thead th").first().evaluate((node) => getComputedStyle(node).position), "sticky");
  const quick = page.getByLabel("Quick views", { exact: true });
  await quick.getByRole("button", { name: /Non-compliant/ }).click();
  assert.ok(await page.locator("tbody tr").count() > 0);
  assert.ok((await page.locator("tbody").innerText()).includes("NON COMPLIANT"));
  await quick.getByRole("button", { name: /All/ }).click();
  const firstHeatmap = heatmap.locator(".heatmap-cell").first();
  await firstHeatmap.click();
  assert.notEqual(await page.getByLabel("Account", { exact: true }).inputValue(), "ALL");
  assert.notEqual(await page.getByLabel("Search controls").inputValue(), "");
  await page.getByLabel("Account", { exact: true }).selectOption("ALL");
  await page.getByLabel("Search controls").fill("");
  await page.getByRole("button", { name: "Dashboard", exact: true }).click();
  assert.equal(calls.filter((call) => call.operation.startsWith("get-")).length, 0);
  await noPageOverflow(page);
  await contrast(page);
  await screenshot(page, "01-synthetic-light-inventory");

  const toggle = page.getByRole("button", { name: "Dark mode", exact: true });
  await page.waitForLoadState("networkidle");
  const requestCount = requests.length;
  await toggle.focus();
  await toggle.press("Enter");
  await theme(page, "dark");
  assert.equal(requests.length, requestCount, "Theme toggle must not call an API");
  await contrast(page);
  await screenshot(page, "02-synthetic-dark-inventory");
  await page.reload();
  await rows(page, 22);
  await theme(page, "dark");
  await toggle.press("Space");
  await theme(page, "light");
  await page.reload();
  await rows(page, 22);
  await theme(page, "light");
  await toggle.click();
  await theme(page, "dark");

  const ruleRow = page.locator("tbody tr").filter({ hasText: "ACCOUNT_A" }).filter({ hasText: "ec2-metadata-check" });
  await ruleRow.getByRole("button", { name: "ec2-metadata-check", exact: true }).click();
  await page.waitForFunction(() => document.querySelectorAll(".resource-card").length === 1);
  assert.equal(calls.filter((call) => call.operation.startsWith("get-")).at(-1).alias, "ACCOUNT_A");
  await page.getByRole("button", { name: "Load more resources" }).click();
  await page.waitForFunction(() => document.querySelectorAll(".resource-card").length === 2);
  assert.ok((await page.getByRole("dialog").innerText()).includes("RESOURCE_"));
  await screenshot(page, "03-synthetic-dark-detail");
  await page.keyboard.press("Escape");
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  await page.waitForFunction(() => document.activeElement?.textContent?.trim() === "ec2-metadata-check");

  await page.getByLabel("Account", { exact: true }).selectOption("ACCOUNT_A");
  await rows(page, 6);
  await page.getByRole("button", { name: /Security Groups/ }).click();
  await rows(page, 1);
  await page.getByRole("button", { name: /All Controls/ }).click();
  await page.getByLabel("Search controls").fill("lambda");
  await rows(page, 1);
  await page.getByLabel("Search controls").fill("");
  await page.getByLabel("Compliance filter").selectOption("NON_COMPLIANT");
  await rows(page, 3);
  await page.getByLabel("Sort controls").selectOption("name");
  assert.match(await page.locator("tbody tr").first().innerText(), /ec2-metadata-check/);
  await page.getByLabel("Sort descending").click();
  assert.match(await page.locator("tbody tr").first().innerText(), /security-group-check/);
  await page.getByLabel("Compliance filter").selectOption("ALL");
  await page.getByLabel("Account", { exact: true }).selectOption("ALL");
  await rows(page, 22);

  unavailable.add("ACCOUNT_B"); clock += 5000;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await rows(page, 18);
  await page.getByRole("alert").filter({ hasText: "3 of 4 accounts available" }).waitFor();
  await page.getByRole("button", { name: "Dashboard", exact: true }).click();
  assert.ok((await page.getByLabel("Executive summary", { exact: true }).innerText()).includes("Available accounts only"));
  for (const alias of ["ACCOUNT_A", "ACCOUNT_C", "ACCOUNT_D"]) unavailable.add(alias);
  clock += 5000;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await rows(page, 0);
  assert.equal(await page.locator(".summary-count").first().innerText(), "--");
  unavailable.clear(); clock += 5000;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await rows(page, 22);

  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    await noPageOverflow(page);
    await page.getByRole("button", { name: "Toggle categories" }).click();
    await page.getByRole("navigation", { name: "Control categories" }).waitFor({ state: "visible" });
    await page.getByRole("button", { name: /All Controls/ }).click();
    assert.equal(await page.getByRole("button", { name: "Toggle categories" }).getAttribute("aria-expanded"), "false");
    for (const value of ["light", "dark"]) {
      if (await page.locator("html").getAttribute("data-theme") !== value) await toggle.click();
      await theme(page, value);
      await noPageOverflow(page);
    }
    await ruleRow.getByRole("button", { name: "ec2-metadata-check", exact: true }).click();
    await page.getByRole("dialog").waitFor();
    assert.ok(await page.getByRole("dialog").evaluate((node) => node.scrollWidth <= node.clientWidth + 1));
    await page.getByRole("button", { name: "Close details" }).click();
    await page.getByRole("dialog").waitFor({ state: "hidden" });
    await page.waitForFunction(() => document.activeElement?.textContent?.trim() === "ec2-metadata-check");
  }
  await page.setViewportSize({ width: 320, height: 1150 });
  await screenshot(page, "04-synthetic-mobile-dark");

  const denied = await browser.newPage({ viewport: { width: 390, height: 844 }, colorScheme: "dark" });
  observe(denied);
  await denied.addInitScript(() => Object.defineProperty(window, "localStorage", { get() { throw Error("Denied for synthetic test"); } }));
  await denied.goto(origin);
  await rows(denied, 22);
  await theme(denied, "dark");
  await denied.getByRole("button", { name: "Dark mode", exact: true }).click();
  await theme(denied, "light");
  await denied.close();
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  assert.ok(requests.every((request) => request.method === "GET"));
  assert.ok(calls.every((call) => /^(describe-|get-compliance-details)/.test(call.operation)));
  console.log(JSON.stringify({ result: "PASS", mode: "SYNTHETIC", viewports: [1600, 390, 320],
    checks: ["icons", "saved dashboard", "session-only trend labels", "account/control heatmap", "sticky table header", "quick compliance filters", "admin navigation", "no visible region text", "light/dark contrast", "Enter/Space", "saved reload", "denied storage", "no theme API calls", "account switch", "filters/sort", "lazy details/pagination", "partial/all failures/recovery", "mobile navigation", "drawer focus restoration", "no page overflow", "no external requests"],
    awsCalls: 0, pageErrors: errors.length, screenshots: screenshotDir ? 4 : 0 }));
} finally {
  await browser?.close();
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
