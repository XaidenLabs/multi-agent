import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);

test('ships Dadieng product and SDK content without legacy product claims', async () => {
  const files = await Promise.all([
    'src/pages/Home.tsx', 'src/pages/Docs.tsx', 'src/pages/Proof.tsx', 'src/components/DocsOperations.tsx', 'src/pages/Commander.tsx', 'src/components/Navbar.tsx',
    'src/components/Footer.tsx', 'index.html',
  ].map((path) => readFile(new URL(path, root), 'utf8')));
  const content = files.join('\n');
  assert.match(content, /One agent learns/);
  assert.match(content, /verification and distribution protocol/);
  assert.match(content, /Proof, not/);
  assert.match(content, /@dadieng\/sdk/);
  assert.match(content, /live on the public npm registry/);
  assert.match(content, /npm install @dadieng\/sdk @dadieng\/adapters/);
  assert.match(content, /Monad/);
  assert.doesNotMatch(content, /Universal Solana Orchestrator|@xaidenlabs\/uso|uso init/i);
  await assert.rejects(access(new URL('public/.well-known/ory-verify.txt', root)));
});

test('dissolves operations into the documentation experience', async () => {
  const files = await Promise.all([
    'src/App.tsx', 'src/pages/Docs.tsx', 'src/components/DocsOperations.tsx', 'src/pages/Commander.tsx', 'src/components/Navbar.tsx',
    'src/components/Footer.tsx', 'worker/index.js',
  ].map((path) => readFile(new URL(path, root), 'utf8')));
  const content = files.join('\n');
  assert.match(content, /path="\/console"/);
  assert.match(content, /Navigate to="\/docs#operations"/);
  assert.match(content, /path="\/proof"/);
  assert.match(content, /Defense graph/);
  assert.match(content, /Threat receipts/);
  assert.match(content, /Replay lab/);
  assert.match(content, /GitHub/);
  assert.match(content, /Slack/);
  assert.match(content, /Notion/);
  assert.match(content, /Run support-agent scenario/);
  assert.match(content, /Incoming support ticket/);
  assert.match(content, /Blocked before execution/);
  assert.match(content, /raw secrets exposed 0/);
  assert.match(content, /Preview-safe mode/);
  assert.match(content, /multi-app-agent-demo live/);
  assert.match(content, /\/api\/console/);
  assert.doesNotMatch(content, /label: 'Console'/);
  assert.doesNotMatch(content, /dadieng-console\.dadiengalfred\.chatgpt\.site/);
});

test('build contains a Cloudflare worker and both branded assets', async () => {
  await Promise.all([
    'dist/server/index.js', 'dist/client/index.html', 'dist/client/dadieng-logo.png',
    'dist/client/dadieng-banner.png',
  ].map((path) => readFile(new URL(path, root))));
  const wrangler = JSON.parse((await readFile(new URL('wrangler.jsonc', root), 'utf8')).replace(/^\s*\/\/.*$/gm, ''));
  assert.equal(wrangler.assets.binding, 'ASSETS');
  assert.equal(wrangler.assets.not_found_handling, 'single-page-application');
  assert.deepEqual(wrangler.assets.run_worker_first, ['/api/*']);
});

test('console API labels fallback data honestly and rejects writes', async () => {
  const { default: worker } = await import(new URL('worker/index.js', root));
  const env = { ASSETS: { fetch: async () => new Response('missing', { status: 404 }) } };
  const response = await worker.fetch(new Request('https://dadieng.test/api/console'), env);
  const data = await response.json();
  assert.equal(response.status, 200);
  assert.equal(data.freshness.status, 'demo');
  assert.match(data.freshness.label, /Demo data/);

  const rejected = await worker.fetch(new Request('https://dadieng.test/api/console', { method: 'POST' }), env);
  assert.equal(rejected.status, 405);

  const integrations = await worker.fetch(new Request('https://dadieng.test/api/integrations'), env);
  const readiness = await integrations.json();
  assert.deepEqual(readiness.configured, { github: false, slack: false, notion: false });
  assert.equal(readiness.mode, 'preview-safe');
  assert.match(readiness.meaning, /does not claim/);
});

test('docs use a readable, responsive operational type scale', async () => {
  const styles = await readFile(new URL('src/pages/docs.css', root), 'utf8');
  assert.match(styles, /\.docs-hero>p\{[^}]*font-size:17px/);
  assert.match(styles, /\.docs-section>p[^}]*font-size:14px/);
  assert.match(styles, /\.ops-card-head h3\{font-size:20px/);
  assert.match(styles, /@media\(max-width:760px\)/);
});

test('console uses Envio sync metadata and the exact Monad lifecycle mapping', async () => {
  const [worker, operations] = await Promise.all([
    readFile(new URL('worker/index.js', root), 'utf8'),
    readFile(new URL('src/components/DocsOperations.tsx', root), 'utf8'),
  ]);
  assert.match(worker, /_meta \{ chainId progressBlock sourceBlock eventsProcessed isReady \}/);
  assert.match(worker, /ThreatReceipt\(order_by/);
  assert.match(worker, /UsageCommitment\(order_by/);
  assert.match(operations, /\['None', 'Draft', 'Candidate', 'Stable', 'Rejected', 'Quarantined', 'Revoked'\]/);
});

test('Vercel adapter serves the console API and keeps SPA routes addressable', async () => {
  const [{ default: handler }, vercelConfig] = await Promise.all([
    import(new URL('api/console.js', root)),
    readFile(new URL('vercel.json', root), 'utf8').then(JSON.parse),
  ]);
  const headers = new Map();
  let body = Buffer.alloc(0);
  const response = {
    statusCode: 0,
    setHeader: (key, value) => headers.set(key, value),
    end: (value) => { body = Buffer.from(value); },
  };
  await handler({ method: 'GET', url: '/api/console', headers: { host: 'localhost' } }, response);
  assert.equal(response.statusCode, 200);
  assert.equal(JSON.parse(body.toString()).freshness.status, 'demo');
  assert.deepEqual(vercelConfig.rewrites.map(({ source }) => source), ['/docs', '/console', '/commander', '/proof']);
});

test('integration readiness endpoint exposes booleans but never credential values', async () => {
  const { default: handler } = await import(new URL('api/integrations.js', root));
  const previous = process.env.GITHUB_TOKEN;
  process.env.GITHUB_TOKEN = 'must-not-leak';
  let payload;
  const response = {
    headers: new Map(),
    setHeader(key, value) { this.headers.set(key, value); },
    statusCode: 0,
    status(code) { this.statusCode = code; return this; },
    json(value) { payload = value; },
  };
  try {
    handler({ method: 'GET' }, response);
    assert.equal(response.statusCode, 200);
    assert.equal(typeof payload.configured.github, 'boolean');
    assert.doesNotMatch(JSON.stringify(payload), /must-not-leak/);
  } finally {
    if (previous === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = previous;
  }
});

test('landing page wires protocol state and participant app readiness', async () => {
  const source = await readFile(new URL('src/components/HomeIntegrations.tsx', root), 'utf8');
  assert.match(source, /fetch\('\/api\/console'/);
  assert.match(source, /fetch\('\/api\/integrations'/);
  assert.match(source, /GitHub/);
  assert.match(source, /Slack/);
  assert.match(source, /Notion/);
  assert.match(source, /Demo available/);
  assert.match(source, /unavailable/);
  assert.match(source, /Credentials are never exposed/);
});
