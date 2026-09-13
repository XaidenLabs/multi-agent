import { useEffect, useState } from 'react';
import { Activity, Database, ShieldCheck } from 'lucide-react';

type FreshnessStatus = 'loading' | 'live' | 'stale' | 'offline' | 'demo';
type ConsoleData = {
  freshness: { status: FreshnessStatus; label: string; block: number };
  metrics: { receipts: number; protectedEvents: number; stableVersions: number; validators: number; p95LatencyMs: number | null; attackEffectiveness: number | null; utility: number | null; validatorAgreement: number | null; adoption: number | null };
  versions: Array<{ id: string; name: string; version: string; status: number; attestations: number; threshold: number; adoption: number; updated: string }>;
  receipts: Array<{ id: string; attackClass: string; surface: string; severity: 'critical' | 'high' | 'medium'; resolution: string; time: string }>;
  integrations: Array<{ name: string; short: string; role: string; status: 'live' | 'configured' | 'demo' | 'degraded' | 'unavailable' }>;
};

const fallbackData: ConsoleData = {
  freshness: { status: 'demo', label: 'Demo fixture · Envio not connected', block: 0 },
  metrics: { receipts: 2, protectedEvents: 60, stableVersions: 1, validators: 2, p95LatencyMs: null, attackEffectiveness: 100, utility: 100, validatorAgreement: 100, adoption: null },
  versions: [
    { id: 'mcp-020', name: 'MCP Instruction Boundary', version: 'dadieng.mcp-boundary@0.2.0', status: 3, attestations: 2, threshold: 2, adoption: 0, updated: 'local fixture' },
    { id: 'mcp-030', name: 'MCP Instruction Boundary', version: 'dadieng.mcp-boundary@0.3.0', status: 5, attestations: 2, threshold: 2, adoption: 0, updated: 'local fixture' },
  ],
  receipts: [
    { id: 'r1', attackClass: 'Tool poisoning', surface: 'MCP tool result', severity: 'critical', resolution: 'Contained', time: 'demo fixture' },
    { id: 'r2', attackClass: 'Prompt injection', surface: 'Document input', severity: 'high', resolution: 'Linked', time: 'demo fixture' },
  ],
  integrations: [
    { name: 'Envio', short: 'EN', role: 'Protocol read model', status: 'demo' },
    { name: 'Chainlink CRE', short: 'CR', role: 'Validation workflow', status: 'demo' },
    { name: 'Qwen', short: 'QW', role: 'Red-team planning', status: 'demo' },
    { name: 'Dynamic', short: 'DY', role: 'Participant signing', status: 'demo' },
    { name: 'Mera', short: 'ME', role: 'Evidence key derivation', status: 'demo' },
    { name: 'GitHub', short: 'GH', role: 'Remediation issue creation', status: 'unavailable' },
    { name: 'Slack', short: 'SL', role: 'Responder alerting', status: 'unavailable' },
    { name: 'Notion', short: 'NO', role: 'Incident knowledge base', status: 'unavailable' },
  ],
};

const statusName = (status: number) => ['None', 'Draft', 'Candidate', 'Stable', 'Rejected', 'Quarantined', 'Revoked'][status] ?? 'Unknown';

export default function DocsOperations() {
  const [data, setData] = useState<ConsoleData>(fallbackData);

  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/console', { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error('Operational data unavailable');
        return response.json() as Promise<ConsoleData>;
      })
      .then(setData)
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError') return;
        setData((current) => ({ ...current, freshness: { ...current.freshness, status: 'offline', label: 'Indexer offline · demo data' } }));
      });
    return () => controller.abort();
  }, []);

  const percentage = (value: number | null) => value === null ? '—' : `${value}%`;
  const warning = data.freshness.status !== 'live';

  return (
    <div className="docs-operations">
      <div className="ops-title-row">
        <div><span className="eyebrow">LIVE OPERATIONS</span><h2>Protocol health inside the docs.</h2></div>
        <span className={`ops-freshness ${data.freshness.status}`}><i />{data.freshness.label}{data.freshness.block ? ` · block ${data.freshness.block.toLocaleString()}` : ''}</span>
      </div>

      {warning ? <div className="docs-alert" role="status"><Database /><div><strong>Live indexed analytics are unavailable.</strong><p>The view remains useful with labelled demo data. Monad—not this read model—authorizes protocol actions.</p></div></div> : null}

      <div className="ops-metrics" aria-label="Protocol metrics">
        <article><span>Threat receipts</span><strong>{data.metrics.receipts}</strong><small>{warning ? 'DEMO · sanitized incident records' : 'LIVE · sanitized incident records'}</small></article>
        <article><span>Protected events</span><strong>{data.metrics.protectedEvents.toLocaleString()}</strong><small>{warning ? 'DEMO · local reference cases' : 'LIVE · agent boundaries evaluated'}</small></article>
        <article><span>Validator agreement</span><strong>{percentage(data.metrics.validatorAgreement)}</strong><small>{warning ? `DEMO · ${data.metrics.validators} reference identities` : `LIVE · ${data.metrics.validators} eligible identities`}</small></article>
        <article><span>P95 decision</span><strong>{data.metrics.p95LatencyMs === null ? '—' : `${data.metrics.p95LatencyMs} ms`}</strong><small>{warning ? 'DEMO · no latency claim' : 'LIVE · local enforcement path'}</small></article>
      </div>

      <div className="ops-grid">
        <section className="ops-card ops-defense">
          <div className="ops-card-head"><div><span className="eyebrow">Defense graph{warning ? ' · demo fixture' : ' · live'}</span><h3>Active versions</h3></div><ShieldCheck /></div>
          <div className="ops-table-wrap"><table><thead><tr><th>Defense</th><th>Status</th><th>Validation</th><th>Adoption</th></tr></thead><tbody>{data.versions.map((version) => <tr key={version.id}><td><strong>{version.name}</strong><small>{version.version} · {version.updated}</small></td><td><span className={`ops-status ${statusName(version.status).toLowerCase()}`}>{statusName(version.status)}</span></td><td>{version.attestations}/{version.threshold} passed</td><td>{version.adoption}%</td></tr>)}</tbody></table></div>
        </section>

        <section className="ops-card">
          <div className="ops-card-head"><div><span className="eyebrow">Threat receipts{warning ? ' · demo fixture' : ' · live'}</span><h3>Recent activity</h3></div><Activity /></div>
          <div className="ops-receipts">{data.receipts.map((receipt) => <article key={receipt.id}><i className={receipt.severity} /><div><strong>{receipt.attackClass}</strong><small>{receipt.surface} · {receipt.time}</small></div><span>{receipt.resolution}</span></article>)}</div>
        </section>
      </div>

      <section className="ops-card ops-connections">
        <div className="ops-card-head"><div><span className="eyebrow">System connections</span><h3>Core-loop integrations</h3></div><small>Derived state · {data.freshness.label}</small></div>
        <div className="ops-apps">{data.integrations.map((integration) => <article key={integration.name}><span>{integration.short}</span><div><strong>{integration.name}</strong><small>{integration.role}</small></div><i className={integration.status}>{integration.status}</i></article>)}</div>
      </section>

      <section className="ops-proof"><div><span className="eyebrow">Replay lab · local reference suite</span><h3>Canonical validation suite</h3><p>Attack cases, clean controls, decision drift, and evidence exposure are checked before a defense can be promoted.</p></div><div className="ops-proof-stats"><span><strong>32/32</strong>attacks blocked</span><span><strong>28/28</strong>controls preserved</span><span><strong>0</strong>decision drift</span><span><strong>0</strong>evidence exposed</span></div></section>
    </div>
  );
}
