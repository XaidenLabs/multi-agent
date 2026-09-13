import { ArrowUpRight, CheckCircle2, FlaskConical, Github, Network, PackageCheck, ShieldCheck } from 'lucide-react';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import './proof.css';

const contracts = [
  ['DadiengRegistry', '0x449a547105a5b006277fafd7ec1425c1c7428be5'],
  ['DadiengValidation', '0x022b489deb764a438a57bb70d1363cb884c516bf'],
  ['DadiengRewards', '0xb573d400a3476e05fcb5b518665f142605613305'],
];

const transactions = [
  ['Registry deployment', '0xe3a54fb9f0187f0d5ffeff0071d100b409f0c3534d61840c5be0ac41b32a341b'],
  ['Validation deployment', '0xcc6431b048169f2aea31cea6f7c27eb1b0e4090ed8c399f9dcbc139344410d69'],
  ['Rewards deployment', '0x209d27e784f38e6d2b2746e99db133d2c498a94f3b0201525511cf2a22f707b3'],
];

export default function Proof() {
  return <div className="proof-page"><Navbar /><main className="proof-shell">
    <header className="proof-hero"><p className="proof-kicker"><span /> Independently checkable evidence</p><h1>Proof, not<br /><em>product theatre.</em></h1><p>Every claim below is labelled by evidence class. Local reference tests, deployed contracts, public packages, and external-app runs are never presented as the same thing.</p><div className="proof-legend"><span><i className="live" /> Deployed</span><span><i className="local" /> Local reference</span><span><i className="verified" /> Verified external run</span></div></header>

    <section className="proof-section"><div className="proof-section-title"><Network /><div><small>DEPLOYED · MONAD TESTNET · CHAIN 10143</small><h2>Canonical lifecycle contracts</h2></div></div><div className="evidence-list">{contracts.map(([name,address])=><a key={name} href={`https://testnet.monadexplorer.com/address/${address}`} target="_blank" rel="noreferrer"><span><b>{name}</b><code>{address}</code></span><ArrowUpRight /></a>)}</div><div className="transaction-grid">{transactions.map(([name,hash])=><a key={name} href={`https://testnet.monadexplorer.com/tx/${hash}`} target="_blank" rel="noreferrer"><small>{name}</small><code>{hash.slice(0,12)}…{hash.slice(-8)}</code></a>)}</div><p className="proof-caveat">Initial administration is privileged and documented for transfer to multisig/timelock control; this deployment is not described as permissionless governance.</p></section>

    <section className="proof-section"><div className="proof-section-title"><FlaskConical /><div><small>LOCAL REFERENCE · DETERMINISTIC</small><h2>Reproduction before distribution</h2></div></div><div className="proof-stat-grid"><article><strong>100×</strong><span>byte-identical replay executions</span></article><article><strong>32/32</strong><span>adversarial attacks blocked</span></article><article><strong>28/28</strong><span>clean controls allowed</span></article><article><strong>0</strong><span>raw evidence bytes in receipts</span></article></div><p>The suite covers direct, Unicode-obfuscated, split-field, nested JSON, multilingual, and encoded instruction variants. Release eligibility fails on attack regression, utility regression, environment drift, excessive latency, or bundle-hash mismatch.</p><a className="proof-link" href="https://github.com/XaidenLabs/Dadieng/tree/main/defenses/mcp-boundary" target="_blank" rel="noreferrer">Inspect the defense bundle <ArrowUpRight /></a></section>

    <section className="proof-section proof-columns"><div><div className="proof-section-title"><PackageCheck /><div><small>PUBLIC DISTRIBUTION</small><h2>Installable SDK surface</h2></div></div><a className="package-card" href="https://www.npmjs.com/package/@dadieng/sdk" target="_blank" rel="noreferrer"><code>@dadieng/sdk</code><span>Core local enforcement</span><ArrowUpRight /></a><a className="package-card" href="https://www.npmjs.com/package/@dadieng/adapters" target="_blank" rel="noreferrer"><code>@dadieng/adapters</code><span>MCP + Vercel AI boundaries</span><ArrowUpRight /></a></div><div><div className="proof-section-title"><Github /><div><small>PUBLIC SOURCE</small><h2>Auditable implementation</h2></div></div><a className="source-card" href="https://github.com/XaidenLabs/Dadieng" target="_blank" rel="noreferrer"><Github /><span><b>XaidenLabs/Dadieng</b><small>SDK, replay engine, contracts, validators, indexer, app adapters, and tests</small></span><ArrowUpRight /></a></div></section>

    <section className="proof-section"><div className="proof-section-title"><ShieldCheck /><div><small>VERIFIED LIVE · 13 SEPTEMBER 2026</small><h2>One receipt, three accountable actions</h2></div></div><div className="proof-app-flow"><span><b>GitHub</b> remediation issue</span><i>→</i><span><b>Slack</b> responder alert</span><i>→</i><span><b>Notion</b> incident memory</span></div><p>The live operator runner uses scoped participant credentials, fixed ordering, bounded retries, durable checkpoints, and stable idempotency keys. A second run returned the same external IDs without duplicating any write.</p><div className="verified-run-grid"><a href="https://github.com/XaidenLabs/dadieng-hackathon-incidents/issues/2" target="_blank" rel="noreferrer"><b>GitHub issue #2</b><small>Public remediation evidence</small><ArrowUpRight /></a><a href="https://xaidenlabs.slack.com/archives/C0C1B1HJD6F/p1789325771300689" target="_blank" rel="noreferrer"><b>Slack alert</b><small>Private workspace evidence</small><ArrowUpRight /></a><a href="https://app.notion.com/p/tool_poisoning-support-ticket-4821-live-20260913-verified-3da170bd92a681698aded56cf0bae625" target="_blank" rel="noreferrer"><b>Notion record</b><small>Private workspace evidence</small><ArrowUpRight /></a></div><a className="proof-link" href="/commander">Run the public rehearsal <ArrowUpRight /></a></section>

    <section className="proof-final"><CheckCircle2 /><div><small>THE TECHNICAL CLAIM</small><h2>Dadieng is an open verification and distribution protocol for portable AI-agent defenses.</h2><p>A discovered incident does not become policy by assertion. It becomes inheritable only after sanitization, deterministic reproduction, clean-control testing, independent validation, canonical lifecycle finalization, and signed distribution.</p></div></section>
  </main><Footer /></div>;
}
