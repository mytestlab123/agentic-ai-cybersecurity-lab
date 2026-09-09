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
const assertToolReceipt = (result, tool, alias, source) => {
  assert(result.tool_requested === tool, `${source} selected ${result.tool_requested || 'no tool'} instead of ${tool}`);
  assert(JSON.stringify(result.sanitized_arguments) === JSON.stringify({ target_alias: alias }), `${source} arguments were not alias-only`);
  assert(result.provider_tool_result?.target_alias === (tool === 'get_security_group_summary' ? 'SG_LAB_01' : alias), `${source} provider result alias mismatch`);
  assert(result.provider_tool_result?.read_only === true, `${source} provider result was not read-only`);
  const expectedProvider = tool === 'get_ecr_inspector_finding' ? 'AMAZON_INSPECTOR' : tool === 'get_security_group_summary' ? 'AMAZON_EC2' : 'AWS_CONFIG';
  assert(result.provider_tool_result?.provider === expectedProvider, `${source} provider evidence label mismatch`);
};
const investigate = async (source, tool, alias) => {
  const started = Date.now();
  const button = page.getByRole('button', { name: 'Investigate with Codex', exact: true }).last();
  await button.waitFor({ state: 'visible', timeout: 15_000 });
  const response = page.waitForResponse((item) => item.url().endsWith('/api/codex-investigate'), { timeout: 210_000 });
  await button.click();
  const result = (await (await response).json()).result;
  assert(result.live_turn_status === 'LIVE_TURN_COMPLETED', `${source} live turn did not complete`);
  assert(typeof result.prompt_sent === 'string' && result.prompt_sent.length > 0, `${source} prompt missing`);
  assert(typeof result.response_text === 'string' && result.response_text.length > 0, `${source} response missing`);
  assertToolReceipt(result, tool, alias, source);
  assertPublicSafe(result, `${source} live receipt`);
  await page.getByText('Prompt sent', { exact: true }).last().waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByText('Model response', { exact: true }).last().waitFor({ state: 'visible', timeout: 15_000 });
  const body = await page.locator('body').innerText();
  assert(!body.includes('optional AI explanation was unavailable'), `${source} showed deterministic fallback`);
  assert(!body.includes('Codex investigation was blocked'), `${source} showed blocked investigation`);
  timingsMs[`${source.toLowerCase()}Investigate`] = Date.now() - started;
  return result;
};
const ask = async (question) => {
  if (!await page.locator('#prompt').isVisible()) {
    await page.getByRole('button', { name: 'Show Ask SecCop', exact: true }).click();
  }
  await page.locator('#prompt').fill(question);
  const response = page.waitForResponse((item) => item.url().endsWith('/api/ask'), { timeout: 120_000 });
  await page.locator('#run-form').evaluate((form) => form.requestSubmit());
  return (await (await response).json()).result;
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
  await investigate('EC2', 'get_ec2_imdsv2', 'DEV_EC2_LAB_01');
  await screenshot('SecCop-PR76-01-EC2-Codex-Tool-Call.png');
  const sgStarted = Date.now();
  const sg = await ask('Does its security group expose SSH?');
  assert(sg.live_turn_status === 'LIVE_TURN_COMPLETED', 'SG follow-up did not complete');
  assertToolReceipt(sg, 'get_security_group_summary', 'DEV_EC2_LAB_01', 'SG');
  assertPublicSafe(sg, 'SG follow-up');
  timingsMs.sgFollowup = Date.now() - sgStarted;
  await screenshot('SecCop-PR76-02-Security-Group-Codex-Tool-Call.png');
  const unsupported = await ask('List the GuardDuty malware findings for this account.');
  assert(unsupported.status === 'BLOCKED' && unsupported.reason_code === 'CODEX_TOOL_NOT_USED', 'unsupported request was not truthful no-tool');
  assert(!unsupported.tool_requested && !unsupported.provider_tool_result, 'unsupported request silently substituted a tool');
  assertPublicSafe(unsupported, 'unsupported result');
  await screenshot('SecCop-PR76-03-Unsupported-No-Tool.png');

  await reset();
  const s3 = await scan('S3');
  assert(s3.state === 'NON_COMPLIANT' && s3.findings?.length === 1, 'S3 finding missing');
  await investigate('S3', 'get_s3_public_access', 'S3_BUCKET_ALIAS_03');
  await screenshot('SecCop-PR76-04-S3-Codex-Tool-Call.png');

  await reset();
  const ecr = await scan('ECR');
  assert(ecr.state === 'NON_COMPLIANT' && ecr.findings?.length === 1, 'ECR finding missing; a clean provider state is not Codex investigation proof');
  await investigate('ECR', 'get_ecr_inspector_finding', 'ECR_IMAGE_01');
  await screenshot('SecCop-PR76-05-ECR-Codex-Tool-Call.png');

  assert(consoleErrors.length === 0, `console errors: ${consoleErrors.join(' | ')}`);
  assert(externalRequests.length === 0, `external requests: ${externalRequests.join(' | ')}`);
  console.log(JSON.stringify({ status: 'PASS', screenshots: 5, tools: 4, unsupportedNoTool: true, awsWrites: 0, consoleErrors: 0, externalRequests: 0, timingsMs }));
} finally {
  await browser.close();
}
