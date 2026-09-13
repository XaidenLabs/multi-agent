import { useEffect, useState } from 'react';
import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

type Connection = { name: string; short: string; role: string; status: 'live' | 'verified' | 'configured' | 'demo' | 'degraded' | 'unavailable' };

const baseConnections: Connection[] = [
  { name: 'Envio', short: 'EN', role: 'Protocol read model', status: 'demo' },
  { name: 'Chainlink CRE', short: 'CR', role: 'Validation workflow', status: 'demo' },
  { name: 'Qwen', short: 'QW', role: 'Red-team planning', status: 'demo' },
  { name: 'Dynamic', short: 'DY', role: 'Participant signing', status: 'demo' },
  { name: 'Mera', short: 'ME', role: 'Evidence key derivation', status: 'demo' },
  { name: 'GitHub', short: 'GH', role: 'Remediation issue creation', status: 'unavailable' },
  { name: 'Slack', short: 'SL', role: 'Responder alerting', status: 'unavailable' },
  { name: 'Notion', short: 'NO', role: 'Incident knowledge base', status: 'unavailable' },
];

export default function HomeIntegrations() {
  const [connections, setConnections] = useState(baseConnections);
  const [freshness, setFreshness] = useState('Checking connections…');

  useEffect(() => {
    const controller = new AbortController();
    Promise.allSettled([
      fetch('/api/console', { signal: controller.signal }).then((response) => response.ok ? response.json() : Promise.reject(new Error('Console unavailable'))),
      fetch('/api/integrations', { signal: controller.signal }).then((response) => response.ok ? response.json() : Promise.reject(new Error('Readiness unavailable'))),
    ]).then(([consoleResult, readinessResult]) => {
      if (controller.signal.aborted) return;
      setConnections((current) => current.map((connection) => {
        const credentialKey = connection.name.toLowerCase() as 'github' | 'slack' | 'notion';
        if (readinessResult.status === 'fulfilled' && credentialKey in readinessResult.value.configured) {
          return { ...connection, status: readinessResult.value.configured[credentialKey] ? 'configured' : 'unavailable' };
        }
        if (consoleResult.status === 'fulfilled') {
          const live = consoleResult.value.integrations?.find((item: Connection) => item.name === connection.name);
          if (live) return { ...connection, status: live.status };
        }
        return connection;
      }));
      if (consoleResult.status === 'fulfilled') setFreshness(consoleResult.value.freshness?.label ?? 'Operational state loaded');
      else setFreshness('Preview-safe status');
    });
    return () => controller.abort();
  }, []);

  return (
    <section id="integrations" className="section integrations home-connections">
      <div className="container">
        <div className="connections-head"><div><div className="section-kicker">System connections</div><h2>Core-loop integrations.</h2></div><span><i /> Derived state · {freshness}</span></div>
        <div className="connection-grid">{connections.map((connection) => <article key={connection.name}><div className="connection-main"><span className="connection-mark">{connection.short}</span><div><h3>{connection.name}</h3><p>{connection.role}</p></div></div><div className={`connection-status ${connection.status}`}><i />{connection.status === 'demo' ? 'Demo available' : connection.status}</div></article>)}</div>
        <div className="connections-actions"><p>GitHub, Slack, and Notion use participant-scoped authentication. Credentials are never exposed in this public status view.</p><div><Link to="/commander">Connect and run proof <ArrowRight /></Link><Link to="/docs#operations">Open operations in docs</Link></div></div>
      </div>
    </section>
  );
}
