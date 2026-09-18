// Repo-owned synthetic-only browser proof; never connects to the live SecCop GUI.
// Reuses the repository's installed playwright-core and browser (no install).
import { chromium } from "../../../node_modules/playwright-core/index.mjs";
import { createServer } from "../server.mjs";
import { createProvider } from "../provider.mjs";
import { fixtureRead } from "../fixtures.mjs";
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
const calls = [];
const server = createServer(
  createProvider(async (...args) => {
    calls.push(args);
    return fixtureRead(...args);
  }),
  { fixture: true },
);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
let browser;
try {
  browser = await chromium.launch({
    headless: true,
    ...(process.env.CHROMIUM_EXECUTABLE
      ? { executablePath: process.env.CHROMIUM_EXECUTABLE }
      : {}),
  });
  const page = await browser.newPage({
    viewport: { width: 1920, height: 1080 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page
    .getByRole("button", { name: "ec2-metadata-check", exact: true })
    .waitFor();
  assert.equal(await page.locator("tbody tr").count(), 6);
  assert.equal(calls.filter((x) => x[1].startsWith("get-")).length, 0);
  assert.equal(
    await page.getByLabel("Control summary").locator(":scope > div").count(),
    4,
  );
  assert.ok(await page.getByText("25+", { exact: true }).isVisible());
  await page.getByLabel("Environment").selectOption("PROD");
  await page.waitForFunction(
    () => document.querySelectorAll("tbody tr").length === 4,
  );
  await page.getByLabel("Environment").selectOption("DEV");
  await page.waitForFunction(
    () => document.querySelectorAll("tbody tr").length === 6,
  );
  await page.getByRole("button", { name: /Security Groups/ }).click();
  assert.equal(await page.locator("tbody tr").count(), 1);
  await page.getByRole("button", { name: /All Controls/ }).click();
  await page.getByLabel("Search controls").fill("lambda");
  assert.equal(await page.locator("tbody tr").count(), 1);
  await page.getByLabel("Search controls").fill("");
  await page.getByLabel("Compliance filter").selectOption("NON_COMPLIANT");
  assert.equal(await page.locator("tbody tr").count(), 3);
  await page.getByLabel("Sort controls").selectOption("name");
  assert.match(
    await page.locator("tbody tr").first().innerText(),
    /ec2-metadata-check/,
  );
  await page.getByLabel("Reverse sort order").click();
  assert.match(
    await page.locator("tbody tr").first().innerText(),
    /security-group-check/,
  );
  await page.getByLabel("Compliance filter").selectOption("ALL");
  await page.getByLabel("Reverse sort order").click();
  if (process.env.SCREENSHOT_DIR) {
    await mkdir(process.env.SCREENSHOT_DIR, { recursive: true });
    await page.screenshot({
      path: `${process.env.SCREENSHOT_DIR}/01-synthetic-control-inventory.png`,
      fullPage: true,
    });
  }
  await page
    .getByRole("button", { name: "ec2-metadata-check", exact: true })
    .click();
  await page.getByText("RESOURCE_ALIAS_01", { exact: true }).waitFor();
  assert.equal(calls.filter((x) => x[1].startsWith("get-")).length, 1);
  await page.getByRole("button", { name: "Load more resources" }).click();
  await page.getByText("RESOURCE_ALIAS_02", { exact: true }).waitFor();
  assert.equal(calls.filter((x) => x[1].startsWith("get-")).length, 2);
  assert.ok(
    !(await page.locator("body").innerText()).includes("MUST_NOT_LEAK"),
  );
  if (process.env.SCREENSHOT_DIR)
    await page.screenshot({
      path: `${process.env.SCREENSHOT_DIR}/02-synthetic-control-detail.png`,
      fullPage: true,
    });
  await page.getByRole("button", { name: "Close details" }).click();
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page
    .getByRole("button", { name: "Refresh", exact: true })
    .waitFor({ state: "visible" });
  assert.deepEqual(errors, []);
  console.log(
    JSON.stringify({
      result: "PASS",
      mode: "SYNTHETIC",
      browser: "Chromium",
      checks: [
        "DEV/PROD",
        "categories",
        "search",
        "compliance filter",
        "sort/reverse",
        "four cards",
        "capped count",
        "lazy drawer",
        "pagination",
        "token omitted",
        "no page errors",
      ],
      awsCalls: 0,
    }),
  );
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
