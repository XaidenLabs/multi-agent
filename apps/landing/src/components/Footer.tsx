import { Link } from 'react-router-dom';

export default function Footer() {
  return (
    <footer>
      <div className="container footer-grid">
        <div><img src="/dadieng-logo.png" alt="Dadieng" /><p>The verification and distribution protocol for portable AI-agent defenses.</p></div>
        <nav aria-label="Footer navigation"><Link to="/docs">Documentation</Link><Link to="/proof">Proof</Link><Link to="/docs#operations">Operations</Link><a href="mailto:hello@dadieng.dev">Contact</a></nav>
      </div>
      <div className="container footer-wordmark">DADIENG.</div>
      <div className="container footer-bottom"><span>© {new Date().getFullYear()} Dadieng</span><span>Private evidence stays private. Monad state stays verifiable.</span></div>
    </footer>
  );
}
