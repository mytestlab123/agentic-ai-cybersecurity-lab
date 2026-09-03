import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const playwrightCorePath = process.env.PLAYWRIGHT_CORE;
if (!playwrightCorePath) throw new Error('PLAYWRIGHT_CORE is required');
const playwrightCore = process.platform === 'win32'
  ? pathToFileURL(playwrightCorePath).href
  : playwrightCorePath;
const { chromium } = await import(playwrightCore);

const appUrl = process.env.APP_URL;
const cdpUrl = process.env.CDP_URL;
const evidenceDir = process.env.EVIDENCE_DIR;
const reviewDir = process.env.REVIEW_DIR;
const liveAdvisory = process.env.LIVE_ADVISORY;
const liveScanOnly = ['1', 'hybrid', 'hybrid-local'].includes(process.env.LIVE_SCAN_ONLY);
const hybridLive = process.env.LIVE_SCAN_ONLY === 'hybrid';
const hybridFixture = process.env.LIVE_SCAN_ONLY === 'hybrid-local';
const codexPreflight = process.env.LIVE_SCAN_ONLY === 'codex';
const unifiedEc2 = process.env.UNIFIED_EC2 === '1';
const ec2Rnd = process.env.EC2_RND === '1';
if (!appUrl || !cdpUrl || !evidenceDir || !reviewDir) {
  throw new Error('APP_URL, CDP_URL, EVIDENCE_DIR, and REVIEW_DIR are required');
}

await mkdir(evidenceDir, { recursive: true });
const consoleErrors = [];
const externalRequests = [];
const browserRequests = [];
const isLocal = (rawUrl) => {
  const url = new URL(rawUrl);
  return !['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)
    || url.hostname === 'localhost'
    || url.hostname.endsWith('.localhost');
};
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const saveJson = async (name, value) => {
  await writeFile(path.join(evidenceDir, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
};
const shot = async (name, options = {}) => {
  await page.screenshot({ path: path.join(evidenceDir, name), ...options });
};
const focusedShot = async (locator, name) => {
  await locator.screenshot({ path: path.join(evidenceDir, name) });
};

let browser;
let page;
try {
  browser = await chromium.connectOverCDP(cdpUrl);
  const context = browser.contexts()[0] ?? await browser.newContext();
  page = context.pages()[0] ?? await context.newPage();
  await page.setViewportSize({ width: 1920, height: 1080 });
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', (error) => consoleErrors.push(error.message));
  page.on('request', (request) => {
    const entry = { method: request.method(), resourceType: request.resourceType(), url: request.url() };
    browserRequests.push(entry);
    if (!isLocal(entry.url)) externalRequests.push(entry);
  });
  await page.route('**/favicon.ico', async (route) => {
    await route.fulfill({ status: 204, contentType: 'image/x-icon', body: '' });
  });

  const response = await page.goto(appUrl, { waitUntil: 'domcontentloaded', timeout: 15_000 });
  assert(response?.ok(), 'The SecCop page did not return HTTP success');
  await page.locator('#welcome').waitFor({ state: 'visible', timeout: 10_000 });
  const initialText = await page.locator('body').innerText();
  assert(unifiedEc2 || ec2Rnd ? initialText.includes('review boundary.') : initialText.includes('Safe demo boundary.'), 'Safety banner was not visible');
  await shot('SecCop-Scan-01.png');

  if (ec2Rnd) {
    const health = await page.evaluate(async () => (await fetch('/api/health')).json());
    assert(health.review_mode === 'ECR_S3_EC2_COMBINED', 'The R&D backend did not advertise the unified source set');
    assert(JSON.stringify(health.enabled_sources) === JSON.stringify(['ec2', 'ecr', 's3']), 'The R&D backend source set was incomplete');
    assert(health.demo_backend === 'AWS' && health.ec2_rnd_rearm === true, 'The R&D backend mode was not enabled');
    await page.getByRole('button', { name: 'EC2', exact: true }).click();
    const selector = page.locator('#ec2-target-selector');
    await selector.waitFor({ state: 'visible', timeout: 10_000 });
    assert(await selector.locator('option').count() === 2, 'The R&D selector did not expose exactly two aliases');
    const states = [];
    for (const alias of ['DEV_EC2_LAB_01', 'DEV_EC2_LAB_02']) {
      await page.getByRole('button', { name: 'EC2', exact: true }).click();
      await selector.selectOption(alias);
      const scanResponsePromise = page.waitForResponse(
        (item) => item.url().endsWith('/api/scan') && item.request().method() === 'POST',
        { timeout: 360_000 },
      );
      await page.locator('#scan-environment').click();
      const scanResponse = await scanResponsePromise;
      assert(scanResponse.ok(), `The ${alias} R&D scan endpoint did not return HTTP success`);
      const scanPayload = await scanResponse.json();
      const scanResult = scanPayload.result || {};
      assert(scanResult.state === 'NON_COMPLIANT' && scanResult.reason_code === 'SECCOP_EC2_IMDSV2_NON_COMPLIANT', `${alias} was not NON_COMPLIANT`);
      assert(!JSON.stringify(scanPayload).match(/arn:|i-[0-9a-f]{8,17}|\\Users\\|\/home\/|\/mnt\//), `Private data was exposed for ${alias}`);
      await page.getByText('X ACTION REQUIRED', { exact: true }).last().waitFor({ state: 'visible', timeout: 10_000 });
      const findingAction = page.locator('.scan-finding').last().getByRole('button', { name: 'Reopen Finding', exact: true });
      await findingAction.click();
      await page.getByRole('button', { name: 'Reopen Finding', exact: true }).last().waitFor({ state: 'visible', timeout: 10_000 });
      states.push({ alias, state: scanResult.state, reason_code: scanResult.reason_code });
      await saveJson(`unified-ec2-rnd-${alias.toLowerCase()}.json`, { alias, state: scanResult.state, reason_code: scanResult.reason_code });
      await shot(`SecCop-RND-${alias}.png`, { fullPage: true });
      if (alias === 'DEV_EC2_LAB_01') await page.locator('#new-chat').click();
    }
    await saveJson('unified-ec2-rnd-state.json', { review_mode: health.review_mode, enabled_sources: health.enabled_sources, targets: states });
  } else if (unifiedEc2) {
    const health = await page.evaluate(async () => (await fetch('/api/health')).json());
    assert(health.review_mode === 'ECR_S3_EC2_COMBINED', 'The unified backend did not advertise all three sources');
    assert(JSON.stringify(health.enabled_sources) === JSON.stringify(['ec2', 'ecr', 's3']), 'The unified backend source set was incomplete');
    assert(health.demo_backend === 'AWS', 'The unified runner reached the wrong backend');
    assert(!JSON.stringify(health).match(/arn:|i-[0-9a-f]{8,17}|\\Users\\|\/home\/|\/mnt\//), 'Private backend data was exposed in health');
    const tabs = page.locator('.source-tab');
    assert(await tabs.count() === 3, 'The unified source navigation did not render three tabs');
    for (const source of ['EC2', 'ECR', 'S3']) {
      const tab = page.getByRole('button', { name: source, exact: true });
      assert(await tab.getAttribute('aria-disabled') !== 'true', `${source} remained disabled in unified mode`);
    }
    await page.getByRole('button', { name: 'EC2', exact: true }).click();
    assert((await page.locator('#review-title').textContent()).includes('EC2 IMDSv2 Compliance Review'), 'The EC2 review view did not open');
    const scanResponsePromise = page.waitForResponse(
      (item) => item.url().endsWith('/api/scan') && item.request().method() === 'POST',
      { timeout: 360_000 },
    );
    await page.locator('#scan-environment').click();
    const scanResponse = await scanResponsePromise;
    assert(scanResponse.ok(), 'The unified EC2 scan endpoint did not return HTTP success');
    const scanPayload = await scanResponse.json();
    const scanResult = scanPayload.result || {};
    assert(scanResult.state === 'COMPLIANT' && ['COMPLIANT', 'NO_FINDINGS'].includes(scanResult.status), 'The unified EC2 scan was not COMPLIANT');
    assert(scanResult.reason_code === 'SECCOP_EC2_IMDSV2_COMPLIANT', 'The unified EC2 result reason was not truthful');
    assert(Array.isArray(scanResult.findings) && scanResult.findings.length === 0, 'The compliant EC2 result contained findings');
    assert(!JSON.stringify(scanPayload).match(/arn:|i-[0-9a-f]{8,17}|\\Users\\|\/home\/|\/mnt\//), 'Private backend data was exposed in the EC2 scan');
    await page.getByText('CHECK VERIFIED', { exact: true }).waitFor({ state: 'visible', timeout: 10_000 });
    assert((await page.locator('body').innerText()).includes('EC2 IMDSv2 Compliance Review'), 'The EC2 review title was not visible');
    await saveJson('unified-ec2-state.json', {
      review_mode: health.review_mode,
      enabled_sources: health.enabled_sources,
      status: scanResult.status,
      reason_code: scanResult.reason_code,
      findings: scanResult.findings.length,
    });
    await shot('SecCop-Unified-EC2-Compliant.png', { fullPage: true });
  } else if (codexPreflight) {
    const preflightResponse = page.waitForResponse(
      (item) => item.url().endsWith('/api/codex-preflight'),
      { timeout: 180_000 },
    );
    await page.locator('#codex-preflight').click();
    const preflightPayload = await (await preflightResponse).json();
    const preflight = preflightPayload.result;
    assert(preflight.reason_code === 'CODEX_CONNECTED', 'Codex did not connect');
    assert(preflight.auth_status === 'CODEX_AUTHENTICATED', 'Codex authentication was unavailable');
    assert(preflight.thread_status === 'THREAD_ACTIVE', 'The isolated thread did not complete');
    assert(preflight.aws_mcp_status === 'AWS_MCP_UNAVAILABLE', 'Phase 1 AWS MCP status was not truthful');
    assert(!JSON.stringify(preflightPayload).match(/arn:|i-[0-9a-f]{8,17}|\\Users\\|\/home\/|\/mnt\//), 'Private backend data was exposed');
    await page.locator('.codex-preflight-card').waitFor({ state: 'visible', timeout: 10_000 });
    await page.locator('.composer-wrap').evaluate((element) => { element.style.display = 'none'; });
    await shot('SecCop-Codex-Preflight.png', { fullPage: true });
    await focusedShot(page.locator('.codex-preflight-card'), 'SecCop-Codex-Preflight-card.png');
    await saveJson('codex-preflight-state.json', {
      reason_code: preflight.reason_code,
      auth_status: preflight.auth_status,
      thread_status: preflight.thread_status,
      aws_mcp_status: preflight.aws_mcp_status,
    });
  } else if (liveScanOnly) {
    const health = await page.evaluate(async () => (await fetch('/api/health')).json());
    assert(hybridFixture ? health.demo_backend === 'LOCAL' : health.demo_backend === 'AWS', 'The scan runner reached the wrong backend');
    const scanResponsePromise = page.waitForResponse((item) => item.url().endsWith('/api/scan'), { timeout: 360_000 });
    await page.locator('#scan-environment').click();
    const scanPayload = await (await scanResponsePromise).json();
    assert(scanPayload.result.status === 'READY', 'The server-owned live scan was not READY');
    assert(hybridFixture ? scanPayload.result.findings.length === 3 : scanPayload.result.findings.length === 1, 'The scan returned an unexpected finding count');
    assert(scanPayload.result.findings[0].source_type === 'EC2_PACKAGE', 'The live finding was not an EC2 package');
    if (hybridLive || hybridFixture) {
      assert(scanPayload.agent?.reason_code === 'HYBRID_INTEGRATION_READY', 'The hybrid integration was not ready');
      assert(scanPayload.agent.aws_evidence_status === (hybridFixture ? 'DETERMINISTIC_FIXTURE' : 'SECCOP_ADAPTER'), 'The evidence source was not truthful');
      assert(scanPayload.agent.aws_mcp_status === 'AWS_MCP_KNOWLEDGE_ONLY', 'The AWS MCP role was not truthful');
    }
    assert(!JSON.stringify(scanPayload).match(/arn:|i-[0-9a-f]{8,17}|\\Users\\|\/home\/|\/mnt\//), 'Private backend data was exposed');
    await page.locator('.composer-wrap').evaluate((element) => { element.style.display = 'none'; });
    await shot('SecCop-Live-Workspace.png', { fullPage: true });
    await focusedShot(page.locator('.scan-finding').first(), 'SecCop-Live-Finding.png');
    if (hybridFixture) {
      await focusedShot(page.locator('.hybrid-agent-card').first(), 'SecCop-Hybrid-Knowledge.png');
      await saveJson('hybrid-local-state.json', {
        finding: scanPayload.agent.reason_code,
        evidence: scanPayload.agent.aws_evidence_status,
        mcp_role: scanPayload.agent.aws_mcp_status,
        mcp_mode: scanPayload.agent.aws_mcp_mode,
        activity: scanPayload.agent.tool_activity,
      });
    } else {

    const proposalResponsePromise = page.waitForResponse((item) => item.url().endsWith('/api/live-scan-proposal'), { timeout: 180_000 });
    await page.getByRole('button', { name: 'Review live fix', exact: true }).click();
    const proposalPayload = await (await proposalResponsePromise).json();
    const proposal = proposalPayload.result;
    assert(proposal.status === 'READY', 'The exact package proposal was not READY');
    assert(!JSON.stringify(proposalPayload).match(/arn:|i-[0-9a-f]{8,17}/), 'A private AWS identifier was exposed in the proposal');
    const approvalCard = page.locator('.result-card').last();
    const approvalControl = page.getByRole('button', { name: 'Approve exact package fix', exact: true });
    await approvalControl.waitFor({ state: 'visible' });
    const [cardBox, controlBox] = await Promise.all([approvalCard.boundingBox(), approvalControl.boundingBox()]);
    assert(cardBox && controlBox && controlBox.y + controlBox.height <= cardBox.y + cardBox.height, 'Approval control is outside its evidence card');
    await focusedShot(approvalCard, 'SecCop-Live-Approval.png');

    const bypass = await page.evaluate(async ({ proposalId, proposalHash }) => {
      const response = await fetch('/api/live-remediation', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ proposal_id:proposalId, proposal_hash:proposalHash, reboot_approved:false }) });
      return response.json();
    }, { proposalId:proposal.proposal_id, proposalHash:proposal.proposal_hash });
    assert((bypass.result || bypass).reason_code === 'SSM_APPROVAL_REQUIRED', 'Remediation bypass was not denied');
    const wrongBinding = await page.evaluate(async ({ proposalId }) => {
      const response = await fetch('/api/live-decision', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ proposal_id:proposalId, proposal_hash:'0'.repeat(64), decision:'APPROVE' }) });
      return response.json();
    }, { proposalId:proposal.proposal_id });
    assert((wrongBinding.result || wrongBinding).reason_code === 'PROPOSAL_BINDING_MISMATCH', 'Wrong approval binding was not denied');
    const expectedConflict = consoleErrors.findIndex((message) => message.includes('status of 409'));
    if (expectedConflict >= 0) consoleErrors.splice(expectedConflict, 1);
    if (hybridLive) {
      const rejected = await page.evaluate(async ({ proposalId, proposalHash }) => {
        const response = await fetch('/api/live-decision', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ proposal_id:proposalId, proposal_hash:proposalHash, decision:'REJECT' }) });
        return response.json();
      }, { proposalId:proposal.proposal_id, proposalHash:proposal.proposal_hash });
      assert(rejected.result.reason_code === 'HUMAN_REJECTED', 'Reject did not fail closed');
      const rejectedRun = await page.evaluate(async ({ proposalId, proposalHash }) => {
        const response = await fetch('/api/live-remediation', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ proposal_id:proposalId, proposal_hash:proposalHash, reboot_approved:false }) });
        return response.json();
      }, { proposalId:proposal.proposal_id, proposalHash:proposal.proposal_hash });
      assert(rejectedRun.result.reason_code === 'SSM_APPROVAL_REQUIRED', 'Rejected proposal could execute');

      const secondProposalResponse = page.waitForResponse((item) => item.url().endsWith('/api/live-scan-proposal'), { timeout: 180_000 });
      await page.getByRole('button', { name: 'Review live fix', exact: true }).click();
      const secondProposal = (await (await secondProposalResponse).json()).result;
      const remediationResponse = page.waitForResponse((item) => item.url().endsWith('/api/live-remediation'), { timeout: 300_000 });
      await page.getByRole('button', { name: 'Approve exact package fix', exact: true }).last().click();
      const remediationPayload = await (await remediationResponse).json();
      assert(remediationPayload.result.mutation_performed === true, 'The approved package fix was not performed');
      assert(['VERIFIED', 'PENDING_RESCAN'].includes(remediationPayload.result.verification_status), 'The follow-up status was not truthful');
      assert(remediationPayload.result.agent_after?.reason_code === 'HYBRID_AFTER_EXPLAINED', 'The same-thread after explanation was not ready');
      assert(!JSON.stringify(remediationPayload).match(/arn:|i-[0-9a-f]{8,17}|\\Users\\|\/home\/|\/mnt\//), 'Private backend data was exposed after remediation');
      await focusedShot(page.locator('.hybrid-agent-card').last(), 'SecCop-Hybrid-After.png');

      const rescanResponse = page.waitForResponse((item) => item.url().endsWith('/api/scan'), { timeout: 180_000 });
      await page.locator('#scan-environment').click();
      const rescanPayload = await (await rescanResponse).json();
      assert(rescanPayload.result.status === 'NO_FINDINGS', 'The verified package was not clean on rescan');
      await focusedShot(page.locator('.result-card').last(), 'SecCop-Hybrid-Clean.png');
      await saveJson('hybrid-live-state.json', {
        finding: scanPayload.agent.reason_code,
        mcp_role: scanPayload.agent.aws_mcp_status,
        rejected: rejected.result.reason_code,
        approved_proposal: secondProposal.status,
        verification: remediationPayload.result.verification_status,
        after: remediationPayload.result.agent_after.reason_code,
        rescan: rescanPayload.result.status,
      });
    }
    await saveJson('live-scan-state.json', {
      scan_status: scanPayload.result.status,
      proposal_status: proposal.status,
      approval_bypass: (bypass.result || bypass).reason_code,
      binding_denial: (wrongBinding.result || wrongBinding).reason_code,
      mutation_performed: false,
    });
    }
  } else if (liveAdvisory) {
    await page.locator('#advisory-upload').setInputFiles(liveAdvisory);
    const checkResponse = page.waitForResponse((item) => item.url().endsWith('/api/live-advisory'), { timeout: 60_000 });
    await page.getByRole('button', { name: 'Check live server', exact: true }).click();
    assert((await checkResponse).ok(), 'The live advisory check failed');
    await page.locator('.composer-wrap').evaluate((element) => { element.style.display = 'none'; });
    assert(await page.locator('.composer-wrap').boundingBox() === null, 'The composer still overlaps live evidence');
    await focusedShot(page.locator('.result-card').last(), 'SecCop-Live-Finding.png');
    const proposalResponsePromise = page.waitForResponse((item) => item.url().endsWith('/api/live-advisory-proposal'), { timeout: 60_000 });
    await page.getByRole('button', { name: 'Prepare update', exact: true }).click();
    const proposalResponse = await proposalResponsePromise;
    const proposalPayload = await proposalResponse.json();
    assert(proposalPayload.result.status === 'READY', 'The exact package proposal was not READY');
    assert(!JSON.stringify(proposalPayload).match(/arn:|i-[0-9a-f]{8,17}/), 'A private AWS identifier was exposed');
    const approvalCard = page.locator('.result-card').last();
    const approvalControl = page.getByRole('button', { name: 'Approve exact package fix', exact: true });
    await approvalControl.waitFor({ state:'visible' });
    const [cardBox, controlBox] = await Promise.all([approvalCard.boundingBox(), approvalControl.boundingBox()]);
    assert(cardBox && controlBox && controlBox.y + controlBox.height <= cardBox.y + cardBox.height, 'Approval control is outside its evidence card');
    await focusedShot(approvalCard, 'SecCop-Live-Approval.png');

    const proposal = proposalPayload.result;
    const bypass = await page.evaluate(async ({ proposalId, proposalHash }) => {
      const response = await fetch('/api/live-remediation', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ proposal_id:proposalId, proposal_hash:proposalHash, reboot_approved:false }) });
      return response.json();
    }, { proposalId:proposal.proposal_id, proposalHash:proposal.proposal_hash });
    const bypassResult = bypass.result || bypass;
    assert(bypassResult.reason_code === 'SSM_APPROVAL_REQUIRED', 'Remediation bypass was not denied');

    const wrongBinding = await page.evaluate(async ({ proposalId }) => {
      const response = await fetch('/api/live-decision', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ proposal_id:proposalId, proposal_hash:'0'.repeat(64), decision:'APPROVE' }) });
      return response.json();
    }, { proposalId:proposal.proposal_id });
    const bindingResult = wrongBinding.result || wrongBinding;
    assert(bindingResult.reason_code === 'PROPOSAL_BINDING_MISMATCH', 'Wrong approval binding was not denied');
    const expectedConflict = consoleErrors.findIndex((message) => message.includes('status of 409'));
    if (expectedConflict >= 0) consoleErrors.splice(expectedConflict, 1);

    const remediationResponse = page.waitForResponse((item) => item.url().endsWith('/api/live-remediation'), { timeout: 180_000 });
    await page.getByRole('button', { name: 'Approve exact package fix', exact: true }).click();
    const remediationPayload = await (await remediationResponse).json();
    assert(remediationPayload.result.mutation_performed === true, 'The approved one-package fix was not performed');
    assert(['VERIFIED', 'PENDING_RESCAN'].includes(remediationPayload.result.verification_status), 'The follow-up status was not truthful');
    assert(!JSON.stringify(remediationPayload).match(/arn:|i-[0-9a-f]{8,17}/), 'A private AWS identifier was exposed after remediation');
    await focusedShot(page.locator('.result-card').last(), 'SecCop-Live-After.png');
    await saveJson('live-state.json', {
      status: remediationPayload.result.status,
      reason_code: remediationPayload.result.reason_code,
      change_state: remediationPayload.result.change_state,
      verification_status: remediationPayload.result.verification_status,
      approval_bypass: bypassResult.reason_code,
      binding_denial: bindingResult.reason_code,
    });
  } else {

  const cveReviewResponsePromise = page.waitForResponse(
    (item) => item.url().endsWith('/api/cve-review') && item.request().method() === 'POST',
    { timeout: 10_000 },
  );
  await page.locator('#prompt').fill('CVE-2099-0001');
  await page.locator('#run').click();
  const cveReviewResponse = await cveReviewResponsePromise;
  assert(cveReviewResponse.ok(), 'The CVE review endpoint did not return HTTP success');
  const cveReviewPayload = await cveReviewResponse.json();
  assert(cveReviewPayload.result.status === 'READY', 'The pasted CVE review was not READY');
  assert(cveReviewPayload.result.match_count === 3, 'The pasted CVE did not check all three demo sources');
  assert(cveReviewPayload.result.source_results.length === 3, 'The pasted CVE review did not return three sources');
  assert(!JSON.stringify(cveReviewPayload).match(/arn:|i-[0-9a-f]{8,17}/), 'A private AWS identifier was exposed in CVE review');
  await page.locator('.cve-source').nth(0).waitFor({ state: 'visible', timeout: 10_000 });
  assert(await page.locator('.cve-source').count() === 3, 'Three CVE source rows were not rendered');
  await saveJson('cve-review-state.json', {
    status: cveReviewPayload.result.status,
    reason_code: cveReviewPayload.result.reason_code,
    cve_id: cveReviewPayload.result.cve_id,
    match_count: cveReviewPayload.result.match_count,
    source_results: cveReviewPayload.result.source_results.map((item) => ({
      source_type: item.source_type,
      resource_alias: item.resource_alias,
      status: item.status,
      reason_code: item.reason_code,
    })),
  });
  await shot('SecCop-CVE-01.png', { fullPage: true });
  await focusedShot(page.locator('.result-card').last(), 'SecCop-CVE-01-slide.png');

  await page.locator('#new-chat').click();
  const cveReviewCallsBeforeReject = browserRequests.filter((item) => item.url.endsWith('/api/cve-review')).length;
  await page.locator('#prompt').fill('CVE-2099-0001 and CVE-2099-0002');
  await page.locator('#run').click();
  await page.getByText('Please paste one CVE at a time so each check stays clear and exact.', { exact: true }).waitFor({ timeout: 10_000 });
  const cveReviewCallsAfterReject = browserRequests.filter((item) => item.url.endsWith('/api/cve-review')).length;
  assert(cveReviewCallsAfterReject === cveReviewCallsBeforeReject, 'Multiple CVEs reached the review endpoint');
  await page.locator('#new-chat').click();

  const scanResponsePromise = page.waitForResponse(
    (item) => item.url().endsWith('/api/scan') && item.request().method() === 'POST',
    { timeout: 10_000 },
  );
  await page.locator('#scan-environment').click();
  const scanResponse = await scanResponsePromise;
  assert(scanResponse.ok(), 'The scan endpoint did not return HTTP success');
  const scanPayload = await scanResponse.json();
  const scanResult = scanPayload.result;
  assert(scanResult.status === 'READY', 'The demo scan was not READY');
  assert(scanResult.findings.length === 3, 'The demo scan did not return three findings');
  assert(scanResult.source_status.length === 3, 'The demo scan did not check three sources');
  assert(!JSON.stringify(scanPayload).match(/arn:|i-[0-9a-f]{8,17}/), 'A private AWS identifier was exposed');
  await page.locator('.scan-finding').nth(0).waitFor({ state: 'visible', timeout: 10_000 });
  assert(await page.locator('.scan-finding').count() === 3, 'Three finding cards were not rendered');
  await saveJson('scan-state.json', {
    status: scanResult.status,
    reason_code: scanResult.reason_code,
    source_status: scanResult.source_status,
    findings: scanResult.findings.map((item) => ({
      source_type: item.source_type,
      resource_alias: item.resource_alias,
      reference: item.reference,
      remediation_mode: item.remediation_mode,
    })),
  });
  await shot('SecCop-Scan-02.png', { fullPage: true });

  await page.getByRole('button', { name: 'Review live fix', exact: true }).click();
  await page.getByText('The real server fix still needs a live advisory check.', { exact: false }).waitFor({ timeout: 10_000 });
  await shot('SecCop-Scan-02-live-review.png', { fullPage: true });

  await page.locator('#new-chat').click();
  await page.locator('#input-mode').selectOption('SYNTHETIC_LAB');
  await page.locator('#prompt').fill('Inspect CVE-2099-0001 in my synthetic lab.');
  const runResponsePromise = page.waitForResponse(
    (item) => item.url().endsWith('/api/run') && item.request().method() === 'POST',
    { timeout: 10_000 },
  );
  await page.locator('#run').click();
  const runResponse = await runResponsePromise;
  assert(runResponse.ok(), 'The synthetic run endpoint did not return HTTP success');
  const runPayload = await runResponse.json();
  assert(runPayload.result.status === 'AWAITING_APPROVAL', 'The proposal did not stop for approval');
  await page.getByRole('button', { name: 'Approve mock remediation', exact: true }).waitFor({ timeout: 10_000 });
  await page.setViewportSize({ width: 1920, height: 1800 });
  await focusedShot(page.locator('.result-card').last(), 'SecCop-Approval-01-slide.png');
  await page.setViewportSize({ width: 1920, height: 1080 });
  await saveJson('positive-state.json', {
    status: runPayload.result.status,
    reason_code: runPayload.result.reason_code,
    mutation_performed: runPayload.result.proposal.mutation_performed,
    executed_calls: runPayload.result.executed_calls,
  });
  await shot('SecCop-Scan-03.png', { fullPage: true });

  const decisionResponsePromise = page.waitForResponse(
    (item) => item.url().endsWith('/api/decision') && item.request().method() === 'POST',
    { timeout: 10_000 },
  );
  await page.getByRole('button', { name: 'Approve mock remediation', exact: true }).click();
  const decisionResponse = await decisionResponsePromise;
  assert(decisionResponse.ok(), 'The approval endpoint did not return HTTP success');
  const decisionPayload = await decisionResponse.json();
  assert(decisionPayload.result.reason_code === 'MOCK_REMEDIATION_NOOP', 'The approved demo did not remain a no-op');
  assert(decisionPayload.result.proposal.mutation_performed === false, 'The demo reported a mutation');
  await page.getByText('Approved demo action recorded; no mutation was performed.', { exact: true }).first().waitFor({ timeout: 10_000 });
  await saveJson('approval-state.json', {
    status: decisionPayload.result.status,
    reason_code: decisionPayload.result.reason_code,
    mutation_performed: decisionPayload.result.proposal.mutation_performed,
  });
  await shot('SecCop-Scan-04.png', { fullPage: true });

  await page.locator('#new-chat').click();
  await page.locator('#input-mode').selectOption('SYNTHETIC_LAB');
  await page.locator('#prompt').fill('Inspect CVE-2099-0002 in my synthetic lab.');
  const blockedResponsePromise = page.waitForResponse(
    (item) => item.url().endsWith('/api/run') && item.request().method() === 'POST',
    { timeout: 10_000 },
  );
  await page.locator('#run').click();
  const blockedResponse = await blockedResponsePromise;
  assert(blockedResponse.ok(), 'The blocked-path endpoint did not return HTTP success');
  const blockedPayload = await blockedResponse.json();
  assert(blockedPayload.result.status === 'BLOCKED', 'Unknown CVE did not block');
  assert(blockedPayload.result.reason_code === 'CVE_NOT_FOUND', 'Blocked reason code was not stable');
  assert(blockedPayload.result.executed_calls.length === 0, 'Blocked path executed a tool');
  await page.getByText('CVE_NOT_FOUND', { exact: true }).first().waitFor({ timeout: 10_000 });
  await saveJson('negative-state.json', {
    status: blockedPayload.result.status,
    reason_code: blockedPayload.result.reason_code,
    executed_calls: blockedPayload.result.executed_calls,
  });
  await shot('SecCop-Scan-05-blocked.png', { fullPage: true });
  }

  await saveJson('browser-network.json', browserRequests);
  await saveJson('console-errors.json', consoleErrors);
  assert(externalRequests.length === 0, 'The local POC made an external request');
  assert(consoleErrors.length === 0, 'Browser console or page errors were detected');
  await saveJson('result.json', {
    status: 'PASS',
    appUrl,
    viewport: { width: 1920, height: 1080 },
    screenshots: ec2Rnd ? [
      'SecCop-Scan-01.png',
      'SecCop-RND-DEV_EC2_LAB_01.png',
      'SecCop-RND-DEV_EC2_LAB_02.png',
    ] : unifiedEc2 ? [
      'SecCop-Scan-01.png',
      'SecCop-Unified-EC2-Compliant.png',
    ] : codexPreflight ? [
      'SecCop-Codex-Preflight.png',
      'SecCop-Codex-Preflight-card.png',
    ] : liveScanOnly ? [
      'SecCop-Live-Workspace.png',
      'SecCop-Live-Finding.png',
      'SecCop-Live-Approval.png',
    ] : liveAdvisory ? [
      'SecCop-Live-Finding.png',
      'SecCop-Live-Approval.png',
      'SecCop-Live-After.png',
    ] : [
      'SecCop-Scan-01.png',
      'SecCop-CVE-01.png',
      'SecCop-CVE-01-slide.png',
      'SecCop-Scan-02.png',
      'SecCop-Scan-02-live-review.png',
      'SecCop-Scan-03.png',
      'SecCop-Approval-01-slide.png',
      'SecCop-Scan-04.png',
      'SecCop-Scan-05-blocked.png',
    ],
    externalRequests: externalRequests.length,
    consoleErrors: consoleErrors.length,
  });
} catch (error) {
  await saveJson('result.json', { status: 'FAIL', appUrl, error: error instanceof Error ? error.message : String(error) });
  throw error;
} finally {
  if (page) await page.close().catch(() => {});
  if (browser) await browser.close().catch(() => {});
}

console.log(JSON.stringify({ status: 'PASS', reviewDir }, null, 2));
