import { useState } from 'react';
import { CheckCircle2, CircleHelp, Code2, Copy, Github, KeyRound, LifeBuoy, MessageSquare, Network, ReceiptText, Search, ShieldAlert, ShieldCheck, Workflow } from 'lucide-react';
import Footer from '../components/Footer';
import Navbar from '../components/Navbar';
import DocsOperations from '../components/DocsOperations';
import './docs.css';

type NavItem = { id: string; label: string };

const navigation: Array<{ group: string; items: NavItem[] }> = [
  { group: 'GETTING STARTED', items: [{ id: 'overview', label: 'Overview' }, { id: 'install', label: 'Install the SDK' }, { id: 'architecture', label: 'How it works' }] },
  { group: 'BUILD', items: [{ id: 'core-sdk', label: 'Core SDK' }, { id: 'mcp', label: 'MCP adapter' }, { id: 'vercel-ai', label: 'Vercel AI SDK' }, { id: 'multi-app', label: 'Multi-app coordinator' }] },
  { group: 'OPERATE', items: [{ id: 'operations', label: 'Operations' }, { id: 'receipts', label: 'Threat receipts' }, { id: 'stable-sync', label: 'Stable sync' }, { id: 'evaluation', label: 'Reliability & evaluation' }] },
  { group: 'REFERENCE', items: [{ id: 'api', label: 'API reference' }, { id: 'troubleshooting', label: 'Troubleshooting' }, { id: 'faq', label: 'FAQ' }] },
];

function Code({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard.writeText(children).then(() => setCopied(true));
  };
  return <div className="docs-code"><pre><code>{children}</code></pre><button type="button" onClick={copy} aria-label="Copy code to clipboard">{copied ? <CheckCircle2 /> : <Copy />}<span>{copied ? 'Copied' : 'Copy'}</span></button></div>;
}

const lifecycleRows = [
  ['beforeModel(input)', 'Before untrusted context reaches the model', 'Allow, sanitize, or block'],
  ['afterModel(output)', 'Before model output reaches an app or person', 'Allow, sanitize, or block'],
  ['beforeToolCall(name, args)', 'Before a tool can take action', 'Allow, require approval, or block'],
  ['afterToolResult(name, result)', 'Before a tool result returns to the model', 'Allow, sanitize, or block'],
];

export default function Docs() {
  const [query, setQuery] = useState('');
  const normalizedQuery = query.trim().toLowerCase();
  const filteredNavigation = navigation.map((section) => ({ ...section, items: section.items.filter((item) => item.label.toLowerCase().includes(normalizedQuery)) })).filter((section) => section.items.length > 0);

  return (
    <div className="docs-page">
      <Navbar />
      <main className="docs-layout">
        <aside className="docs-sidebar" aria-label="Documentation navigation">
          <div className="docs-sidebar-brand"><span>D</span><div><strong>Dadieng Docs</strong><small>SDK · v0.1.0</small></div></div>
          <label className="docs-search"><Search /><span className="sr-only">Search documentation</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search docs…" /></label>
          <nav>{filteredNavigation.map((section) => <div className="docs-nav-group" key={section.group}><p>{section.group}</p>{section.items.map((item) => <a key={item.id} href={`#${item.id}`}>{item.label}<span>→</span></a>)}</div>)}</nav>
          {filteredNavigation.length === 0 ? <p className="docs-no-results">No matching section.</p> : null}
          <div className="docs-sidebar-help"><LifeBuoy /><div><strong>Need help?</strong><a href="mailto:hello@dadieng.dev">Talk to the team →</a></div></div>
        </aside>

        <article className="docs-main">
          <section id="overview" className="docs-hero">
            <div className="docs-breadcrumb"><span>Documentation</span><i>/</i><span>Overview</span></div>
            <div className="docs-version"><i /> SDK v0.1.0 live on npm</div>
            <h1>Build agents that learn<br /><em>without repeating failures.</em></h1>
            <p>Dadieng is a local-first TypeScript safety SDK for agent boundaries. It converts incidents into privacy-safe receipts, independently validated defenses, and versioned protection every connected agent can adopt.</p>
            <div className="docs-hero-actions"><a href="#install">Start building →</a><a href="#operations">View live operations</a></div>
          </section>

          <section className="docs-start-grid" aria-label="Documentation shortcuts">
            <a href="#install"><Code2 /><span><strong>Install in minutes</strong><small>Add the SDK and your framework adapter.</small></span><b>01</b></a>
            <a href="#multi-app"><Network /><span><strong>Connect external apps</strong><small>Coordinate GitHub, Slack, and Notion safely.</small></span><b>02</b></a>
            <a href="#evaluation"><ShieldCheck /><span><strong>Prove reliability</strong><small>Run clean controls and injected failures.</small></span><b>03</b></a>
          </section>

          <section id="install" className="docs-section">
            <span className="section-number">01 · INSTALL</span><h2>Protect your first agent boundary.</h2><p className="section-lead"><code>@dadieng/sdk</code> and <code>@dadieng/adapters</code> are live on the public npm registry. Create one client per agent process.</p>
            <div className="docs-alert"><ShieldAlert /><div><strong>Start in observe mode</strong><p>Collect decisions without blocking actions. Move to enforce mode after your clean-control suite passes.</p></div></div>
            <h3>Install from npm</h3><Code>npm install @dadieng/sdk @dadieng/adapters</Code>
            <h3>Create the client</h3><Code>{`import { createDadieng } from '@dadieng/sdk'\n\nconst dadieng = createDadieng({\n  agentId: 'incident-commander',\n  framework: 'custom',\n  mode: 'observe',\n  failMode: 'last-known-good'\n})`}</Code>
          </section>

          <section id="architecture" className="docs-section">
            <span className="section-number">02 · ARCHITECTURE</span><h2>One local decision path. Verifiable shared learning.</h2><p className="section-lead">The latency-sensitive decision stays inside the agent. Only sanitized receipts and encrypted evidence leave the process.</p>
            <div className="architecture-flow"><div><span>01</span><strong>Agent boundary</strong><small>Input, output, tool call, or result</small></div><i>→</i><div><span>02</span><strong>Local defense</strong><small>Synchronous policy decision</small></div><i>→</i><div><span>03</span><strong>Private receipt</strong><small>Hash + sanitized metadata</small></div><i>→</i><div><span>04</span><strong>Stable update</strong><small>Validated and versioned defense</small></div></div>
          </section>

          <section id="core-sdk" className="docs-section">
            <span className="section-number">03 · CORE SDK</span><h2>Call the lifecycle hook at every boundary.</h2><div className="docs-table-wrap"><table><thead><tr><th>Hook</th><th>Use it</th><th>Possible decision</th></tr></thead><tbody>{lifecycleRows.map(([hook, use, decision]) => <tr key={hook}><td><code>{hook}</code></td><td>{use}</td><td>{decision}</td></tr>)}</tbody></table></div>
            <Code>{`const decision = dadieng.beforeToolCall('github.createIssue', args)\n\nif (decision.action === 'block') {\n  throw new Error(\`Blocked by Dadieng: \${decision.reasonCode}\`)\n}\n\nconst safeArgs = decision.value`}</Code>
          </section>

          <section id="mcp" className="docs-section split-section"><div><span className="section-number">04 · MCP</span><h2>Wrap the client once.</h2><p>The proxy checks tool arguments before execution and the complete result before the model sees it. Blocked errors contain sanitized IDs, never hostile content.</p></div><Code>{`import { protectMcpClient } from '@dadieng/adapters'\n\nconst client = protectMcpClient(rawMcpClient, dadieng)\nawait client.callTool({\n  name: 'calendar.search',\n  arguments: {}\n})`}</Code></section>

          <section id="vercel-ai" className="docs-section split-section"><div><span className="section-number">05 · VERCEL AI SDK</span><h2>Protect the model and every tool.</h2><p>The adapter targets the AI SDK v4 middleware contract in AI SDK 7. Tool wrappers remain necessary because model middleware does not authorize side effects.</p></div><Code>{`const safeModel = wrapLanguageModel({\n  model,\n  middleware: createDadiengLanguageModelMiddleware(dadieng)\n})\n\nconst safeSearch = protectAiSdkTool(\n  dadieng, 'search', searchTool\n)`}</Code></section>

          <section id="multi-app" className="docs-section">
            <span className="section-number">06 · MULTI-APP COORDINATION</span><h2>One incident, three accountable actions.</h2><p className="section-lead">The incident commander creates a GitHub issue, alerts responders in Slack, and records the durable runbook in Notion. Every step is idempotent, retries transient failures, and returns a receipt.</p>
            <div className="app-doc-grid"><article><Github /><h3>GitHub</h3><p>Create or update the remediation issue with the incident fingerprint as the idempotency key.</p><code>GITHUB_TOKEN</code></article><article><MessageSquare /><h3>Slack</h3><p>Notify the incident channel with severity, owner, links, and approval state—never raw evidence.</p><code>SLACK_BOT_TOKEN</code></article><article><ReceiptText /><h3>Notion</h3><p>Create the incident page and preserve the timeline, decisions, receipts, and final resolution.</p><code>NOTION_TOKEN</code></article></div>
            <Code>{`const result = await commander.coordinate({\n  incident,\n  apps: ['github', 'slack', 'notion'],\n  approval: 'required-for-write'\n})\n\nconsole.log(result.receipts)`}</Code>
            <div className="docs-callout"><KeyRound /><div><strong>Authentication belongs to the participant.</strong><p>Each user connects their own GitHub, Slack, and Notion workspace. Store OAuth tokens encrypted, request the smallest scopes, and support disconnect/revocation.</p></div></div>
          </section>

          <section id="operations" className="docs-section docs-operation-section"><DocsOperations /></section>

          <section id="receipts" className="docs-section split-section"><div><span className="section-number">07 · THREAT RECEIPTS</span><h2>Share proof, not private content.</h2><p>Public fields contain a receipt ID, defense version, decision code, evidence hash, timestamp, and agent pseudonym. Raw prompts, tool output, credentials, and customer data stay encrypted.</p></div><Code>{`dadieng.onIncident((receipt, decision, encryptedEvidence) => {\n  queue.publish({ receipt, encryptedEvidence })\n})`}</Code></section>

          <section id="stable-sync" className="docs-section"><span className="section-number">08 · STABLE SYNC</span><h2>Promote carefully. Roll back safely.</h2><p className="section-lead">Production agents verify the manifest signer, expiry, chain, lineage, artifact hashes, compatibility, Monad state, and shadow suite before swapping the active set.</p><div className="check-grid"><span><CheckCircle2 /> Verify signature and expiry</span><span><CheckCircle2 /> Match target chain and agent</span><span><CheckCircle2 /> Run attack and clean controls</span><span><CheckCircle2 /> Keep previous known-good set</span></div><Code>{`await dadieng.refreshDefenses()\n// Current + previous verified sets remain available for rollback.`}</Code></section>

          <section id="evaluation" className="docs-section"><span className="section-number">09 · RELIABILITY</span><h2>Show how you know it works.</h2><p className="section-lead">A credible evaluation includes the happy path, injected app failures, retries, deduplication, partial success, approval denial, secret redaction, and recovery.</p><div className="evaluation-grid"><article><strong>Attack suite</strong><span>Known prompt and tool-poisoning cases are blocked.</span></article><article><strong>Clean controls</strong><span>Legitimate work completes without utility loss.</span></article><article><strong>Failure injection</strong><span>429s, 500s, timeouts, and invalid credentials are classified.</span></article><article><strong>Replay proof</strong><span>The same incident cannot duplicate external writes.</span></article></div><Code>{`npm test\nnpm run test:e2e\nnpm run build\n\n# Mini-project failure lab\nnpm --prefix examples/incident-commander-e2e test`}</Code></section>

          <section id="api" className="docs-section"><span className="section-number">10 · API REFERENCE</span><h2>Essential client surface.</h2><div className="docs-table-wrap"><table><thead><tr><th>Method</th><th>Returns</th><th>Notes</th></tr></thead><tbody><tr><td><code>createDadieng(config)</code></td><td>Dadieng client</td><td>One instance per agent process</td></tr><tr><td><code>refreshDefenses()</code></td><td>Sync result</td><td>Keeps last-known-good on failure</td></tr><tr><td><code>onIncident(handler)</code></td><td>Unsubscribe function</td><td>Handler receives sanitized receipt and encrypted evidence</td></tr><tr><td><code>getHealth()</code></td><td>Health snapshot</td><td>Safe for readiness endpoints</td></tr></tbody></table></div></section>

          <section id="troubleshooting" className="docs-section"><span className="section-number">11 · TROUBLESHOOTING</span><h2>Diagnose by failure class.</h2><div className="trouble-grid"><article><strong>Authentication rejected</strong><p>Reconnect the affected app, verify scopes, rotate the token, then rerun only that failed step.</p></article><article><strong>Rate limited</strong><p>Honor <code>Retry-After</code>, apply bounded exponential backoff, and keep the idempotency key stable.</p></article><article><strong>Indexer offline</strong><p>Continue local enforcement with the last verified defense set. Label derived analytics as stale or demo.</p></article><article><strong>Partial app failure</strong><p>Preserve successful receipts, report the failed app, and resume without duplicating completed writes.</p></article></div></section>

          <section id="faq" className="docs-section docs-faq"><span className="section-number">12 · FAQ</span><h2>Frequently asked questions.</h2><details><summary>Does Dadieng send prompts or tool results on-chain?<CircleHelp /></summary><p>No. Public records contain hashes and sanitized metadata. Private evidence is encrypted and remains under operator control.</p></details><details><summary>What happens when the network is unavailable?<CircleHelp /></summary><p>Local protection continues with the last-known-good verified bundle. The configured fail mode controls behavior when no valid bundle exists.</p></details><details><summary>Why do users authenticate GitHub, Slack, and Notion?<CircleHelp /></summary><p>The agent acts inside their accounts and workspaces, so each participant grants scoped access through OAuth. Dadieng should never share one global credential across users.</p></details><details><summary>Can I use only one adapter?<CircleHelp /></summary><p>Yes. Install the core SDK and only the adapter required by your agent framework. The multi-app demo uses three external apps to show coordinated action.</p></details></section>

          <section className="docs-support"><div><LifeBuoy /><span><strong>Implementation help</strong><p>Architecture, adapters, and production hardening.</p><a href="mailto:hello@dadieng.dev">Email the team →</a></span></div><div><Workflow /><span><strong>Run the proof</strong><p>See one incident coordinate all three external apps.</p><a href="/commander">Open Incident Commander →</a></span></div></section>
        </article>
      </main>
      <Footer />
    </div>
  );
}
