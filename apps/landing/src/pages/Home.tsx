import { motion } from 'framer-motion';
import { ArrowRight, Check, Fingerprint, GitBranch, Orbit, Radio, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import Footer from '../components/Footer';
import Navbar from '../components/Navbar';
import HomeIntegrations from '../components/HomeIntegrations';

const stages = [
  ['01', 'Detect', 'A local SDK intercepts model and tool boundaries before an unsafe action executes.'],
  ['02', 'Sanitize', 'A privacy-safe receipt commits the incident without publishing raw prompts or secrets.'],
  ['03', 'Reproduce', 'Qwen proposes synthetic variants; deterministic replay tests attacks and legitimate controls.'],
  ['04', 'Validate', 'Independent validators reproduce the report while Chainlink CRE coordinates the workflow.'],
  ['05', 'Distribute', 'Monad finalizes lifecycle state; signed manifests update every connected agent.'],
];

export default function Home() {
  return (
    <div>
      <Navbar />
      <main>
        <section className="hero">
          <div className="hero-grid" aria-hidden="true" /><div className="hero-orbit orbit-a" /><div className="hero-orbit orbit-b" />
          <div className="container hero-inner">
            <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7 }}>
              <div className="eyebrow"><span /> Open defense protocol · Monad testnet</div>
              <h1>One agent learns.<br /><em>Every agent hardens.</em></h1>
              <p className="hero-copy">Turn one agent incident into a reproducible, independently validated defense that every compatible agent can verify and inherit.</p>
              <div className="hero-actions"><Link className="button primary" to="/commander">Run the attack <ArrowRight size={17} /></Link><Link className="button secondary" to="/proof">Inspect the proof</Link><Link className="button secondary" to="/docs">Integrate the SDK</Link></div>
              <div className="trust-row"><span><Check /> Local enforcement</span><span><Check /> No raw evidence onchain</span><span><Check /> Independent validation</span></div>
            </motion.div>
            <motion.div className="terminal" initial={{ opacity: 0, scale: .97 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: .15, duration: .7 }}>
              <div className="terminal-bar"><i /><i /><i /><span>agent-boundary.ts</span></div>
              <pre><code><b>import</b> {'{ createDadieng }'} <b>from</b> <s>'@dadieng/sdk'</s>{'\n'}<b>import</b> {'{ protectMcpClient }'} <b>from</b> <s>'@dadieng/adapters'</s>{'\n\n'}<span>const</span> defense = createDadieng({'{'}{'\n'}  agentId: <s>'agent-b'</s>,{'\n'}  framework: <s>'mcp'</s>,{'\n'}  mode: <s>'enforce'</s>{'\n'}{'}'}){'\n\n'}<span>const</span> client = protectMcpClient(rawClient, defense)</code></pre>
              <div className="terminal-result"><ShieldCheck size={18} /><div><strong>Threat contained locally</strong><small>mcp-boundary@0.2.0 · signed receipt created</small></div></div>
            </motion.div>
          </div>
        </section>

        <section className="signal-strip"><div className="container signal-grid"><div><small>REFERENCE SUITE</small><strong>32/32</strong><span>adversarial attacks blocked</span></div><div><small>REFERENCE SUITE</small><strong>28/28</strong><span>legitimate controls preserved</span></div><div><small>PROTOCOL RULE</small><strong>2+</strong><span>independent validators required</span></div><div><small>LOCAL TARGET</small><strong>&lt; 5 ms</strong><span>enforcement decision</span></div></div></section>

        <section className="section inheritance" id="inheritance"><div className="container"><div className="section-kicker red">The technical proof</div><div className="section-head"><h2>One unknown incident.<br />A defense another agent inherits.</h2><p>Dadieng does not distribute an unreviewed threat signature. It distributes a content-addressed defense only after attack tests, clean controls, independent reproduction, and canonical lifecycle finalization.</p></div><div className="inheritance-flow">{['Agent A receives unknown attack','Local SDK blocks the unsafe tool path','Sanitized receipt commits evidence','Replay runs 100× without network access','Two validators reproduce the result','Monad marks the version Stable','Agent B verifies and syncs the manifest','Same attack blocked · clean request allowed'].map((label,index)=><article key={label}><span>{String(index+1).padStart(2,'0')}</span><strong>{label}</strong>{index<7?<i>→</i>:null}</article>)}</div><div className="moat-line"><b>Threat intelligence tells agents what happened.</b><span>Dadieng proves which defense works, preserves utility, and can be safely inherited.</span></div></div></section>

        <section id="protocol" className="section protocol"><div className="container"><div className="section-kicker">The protocol loop</div><div className="section-head"><h2>From one incident to<br />network-wide protection.</h2><p>Every transition is observable. Every release is reproducible. No central operator can silently promote a defense.</p></div><div className="stage-grid">{stages.map(([number, title, copy], index) => <motion.article key={title} initial={{ opacity: 0, y: 18 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: index * .06 }}><span>{number}</span><h3>{title}</h3><p>{copy}</p></motion.article>)}</div></div></section>

        <section className="section contrast"><div className="container split"><div><div className="section-kicker red">Portable defenses</div><h2>Security that lives<br />outside the agent.</h2><p>Dadieng separates detection, evidence, replay, validation, and distribution into verifiable layers. Agents can change models or frameworks without losing the protection they already earned.</p><ul><li><Fingerprint /> Content-addressed defense bundles and evidence</li><li><GitBranch /> Signed stable manifests with rollback lineage</li><li><Radio /> Offline last-known-good protection</li></ul></div><div className="defense-card"><div className="card-top"><Orbit /><span>dadieng.mcp-boundary</span><b>LOCAL REFERENCE</b></div><div className="version">v0.2.0</div><div className="card-metrics"><span><small>REFERENCE SUITE</small><b>100%</b> attack effectiveness</span><span><small>REFERENCE SUITE</small><b>100%</b> control utility</span><span><small>SIMULATED QUORUM</small><b>2/2</b> validators</span></div><div className="manifest-line"><i style={{ width: '100%' }} /><small>Deterministic local artifact · not a live adoption metric</small></div></div></div></section>

        <HomeIntegrations />

        <section className="section developer"><div className="container developer-inner"><div><div className="section-kicker red">For developers</div><h2>Two wrappers.<br />One protected call.</h2><p>Start with the SDK, then add the adapter for your framework. Dadieng evaluates locally and emits sanitized incidents through listeners you control.</p><Link to="/docs" className="text-link">Read the integration guide <ArrowRight /></Link></div><div className="install-card"><div><span>core SDK · v0.1.0</span><code>npm install @dadieng/sdk</code></div><div><span>framework adapters · v0.1.0</span><code>npm install @dadieng/adapters</code></div><small>Published by the official Dadieng organization on npm.</small></div></div></section>

        <section className="cta"><div className="container"><div className="cta-mark">D</div><h2>Agents should inherit immunity,<br />not repeat incidents.</h2><p>Build with the shared defense layer.</p><div className="hero-actions"><Link className="button primary" to="/docs">Start integrating <ArrowRight size={17} /></Link><Link className="button secondary" to="/docs#operations">View operations &amp; docs</Link></div></div></section>
      </main>
      <Footer />
    </div>
  );
}
