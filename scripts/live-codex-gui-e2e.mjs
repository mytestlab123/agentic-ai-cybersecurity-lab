import { pathToFileURL } from 'node:url';

const playwrightCorePath = process.env.PLAYWRIGHT_CORE;
const appUrl = process.env.APP_URL;
const cdpUrl = process.env.CDP_URL;
const outputDir = process.env.OUTPUT_DIR;
if (!playwrightCorePath || !appUrl || !cdpUrl || !outputDir) throw new Error('missing runtime input');
const { chromium } = await import(pathToFileURL(playwrightCorePath).href);

const browser = await chromium.connectOverCDP(cdpUrl);
const context = browser.contexts()[0] ?? await browser.newContext();
const page = context.pages()[0] ?? await context.newPage();
await page.setViewportSize({ width: 1920, height: 1080 });

const consoleErrors = [];
const externalRequests = [];
const timingsMs = {};
const unsafe = /(?:arn:aws|sha256:|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]|\bi-[0-9a-f]{8,17}\b|\/home\/|\/mnt\/|\\Users\\)/i;
page.on('console', (message) => {
  if (message.type() === 'error') consoleErrors.push(message.text());
});
page.on('pageerror', (error) => consoleErrors.push(error.message));
page.on('request', (request) => {
  const url = new URL(request.url());
  if (['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol) && url.hostname !== 'localhost') {
    externalRequests.push(request.url());
  }
});
await page.route('**/favicon.ico', (route) => route.fulfill({ status: 204, body: '' }));

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const assertPublicSafe = (value, label) => assert(!unsafe.test(JSON.stringify(value)), `${label} exposed private data`);
const reset = async () => {
  const response = page.waitForResponse((item) => item.url().endsWith('/api/codex-reset'), { timeout: 15_000 });
  await page.locator('#new-chat').click();
  assert((await response).ok(), 'reset failed');
};
const scan = async (source) => {
  const started = Date.now();
  await page.getByRole('button', { name: source, exact: true }).click();
  const response = page.waitForResponse((item) => item.url().endsWith('/api/scan'), { timeout: 120_000 });
  await page.locator('#scan-environment').click();
  const httpResponse = await response;
  assert(httpResponse.ok(), `${source} scan failed`);
  const result = (await httpResponse.json()).result;
  assertPublicSafe(result, `${source} scan`);
  timingsMs[`${source.toLowerCase()}Scan`] = Date.now() - started;
  return result;
};
const investigate = async (source) => {
  const started = Date.now();
  const button = page.getByRole('button', { name: 'Investigate with Codex', exact: true }).last();
  await button.waitFor({ state: 'visible', timeout: 15_000 });
  const response = page.waitForResponse((item) => item.url().endsWith('/api/codex-investigate'), { timeout: 90_000 });
  await button.click();
  const result = (await (await response).json()).result;
  assert(result.live_turn_status === 'LIVE_TURN_COMPLETED', `${source} live turn did not complete`);
  assert(typeof result.prompt_sent === 'string' && result.prompt_sent.length > 0, `${source} prompt missing`);
  assert(typeof result.response_text === 'string' && result.response_text.length > 0, `${source} response missing`);
  assertPublicSafe(result, `${source} live receipt`);
  await page.getByText('Prompt sent', { exact: true }).last().waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByText('Model response', { exact: true }).last().waitFor({ state: 'visible', timeout: 15_000 });
  const body = await page.locator('body').innerText();
  assert(!body.includes('optional AI explanation was unavailable'), `${source} showed deterministic fallback`);
  assert(!body.includes('Codex investigation was blocked'), `${source} showed blocked investigation`);
  timingsMs[`${source.toLowerCase()}Investigate`] = Date.now() - started;
};
const screenshot = (name) => page.screenshot({ path: `${outputDir}/${name}`, fullPage: true });

try {
  const response = await page.goto(appUrl, { waitUntil: 'domcontentloaded', timeout: 20_000 });
  assert(response?.ok(), 'GUI did not load');
  const health = await page.evaluate(async () => (await fetch('/api/health')).json());
  assert(health.review_mode === 'ECR_S3_EC2_COMBINED', 'wrong review mode');
  assert(JSON.stringify(health.enabled_sources) === JSON.stringify(['ec2', 'ecr', 's3']), 'wrong source set');
  assertPublicSafe(health, 'health');

  await reset();
  const ec2 = await scan('EC2');
  assert(ec2.state === 'NON_COMPLIANT' && ec2.findings?.length === 1, 'EC2 finding missing');
  await investigate('EC2');
  await screenshot('SecCop-PR74-01-EC2-Live-Codex-Investigation.png');

  await reset();
  const s3 = await scan('S3');
  assert(s3.state === 'NON_COMPLIANT' && s3.findings?.length === 1, 'S3 finding missing');
  await investigate('S3');
  await screenshot('SecCop-PR74-02-S3-Live-Codex-Investigation.png');
  await page.getByRole('button', { name: 'Show Ask SecCop', exact: true }).click();
  await page.locator('#prompt').fill('What should the operator verify before approval?');
  const followupStarted = Date.now();
  const followupResponse = page.waitForResponse((item) => item.url().endsWith('/api/ask'), { timeout: 90_000 });
  await page.locator('#run-form').evaluate((form) => form.requestSubmit());
  const followup = (await (await followupResponse).json()).result;
  assert(followup.live_turn_status === 'LIVE_TURN_COMPLETED', 'S3 follow-up did not complete');
  assert(typeof followup.prompt_sent === 'string' && followup.prompt_sent.length > 0, 'S3 follow-up prompt missing');
  assert(typeof followup.response_text === 'string' && followup.response_text.length > 0, 'S3 follow-up response missing');
  assertPublicSafe(followup, 'S3 follow-up');
  timingsMs.s3Followup = Date.now() - followupStarted;
  await page.getByText('Model response', { exact: true }).last().waitFor({ state: 'visible', timeout: 15_000 });
  await screenshot('SecCop-PR74-03-S3-Live-Codex-Follow-Up.png');

  await reset();
  const ecr = await scan('ECR');
  assert(ecr.state === 'NON_COMPLIANT' && ecr.findings?.length === 1, 'ECR finding missing; a clean provider state is not Codex investigation proof');
  await investigate('ECR');
  await screenshot('SecCop-PR74-04-ECR-Live-Codex-Investigation.png');

  await reset();
  await page.getByRole('button', { name: 'Show Ask SecCop', exact: true }).click();
  await page.locator('#prompt').fill('Why is IMDSv2 safer than IMDSv1?');
  const generalStarted = Date.now();
  const generalResponse = page.waitForResponse((item) => item.url().endsWith('/api/ask'), { timeout: 90_000 });
  await page.locator('#run-form').evaluate((form) => form.requestSubmit());
  const general = (await (await generalResponse).json()).result;
  assert(general.reason_code === 'GENERAL_CODEX_QUESTION_READY', 'general question route failed');
  assert(general.live_turn_status === 'LIVE_TURN_COMPLETED', 'general live turn did not complete');
  assert(typeof general.prompt_sent === 'string' && general.prompt_sent.length > 0, 'general prompt missing');
  assert(typeof general.response_text === 'string' && general.response_text.length > 0, 'general response missing');
  assertPublicSafe(general, 'general live receipt');
  timingsMs.generalQuestion = Date.now() - generalStarted;
  await page.getByText('Model response', { exact: true }).last().waitFor({ state: 'visible', timeout: 15_000 });
  await screenshot('SecCop-PR74-05-General-Live-Codex-Question.png');

  assert(consoleErrors.length === 0, `console errors: ${consoleErrors.join(' | ')}`);
  assert(externalRequests.length === 0, `external requests: ${externalRequests.join(' | ')}`);
  console.log(JSON.stringify({ status: 'PASS', screenshots: 5, consoleErrors: 0, externalRequests: 0, timingsMs }));
} finally {
  await browser.close();
}
