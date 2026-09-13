import { useEffect, useState } from 'react';
import { Menu, X } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Navbar() {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const update = () => setScrolled(window.scrollY > 24);
    window.addEventListener('scroll', update, { passive: true });
    return () => window.removeEventListener('scroll', update);
  }, []);
  const links = [
    { label: 'Protocol', href: '/#protocol', route: false },
    { label: 'Integrations', href: '/#integrations', route: false },
    { label: 'Documentation', href: '/docs', route: true },
    { label: 'Proof', href: '/proof', route: true },
    { label: 'Example app', href: '/commander', route: true },
  ];
  return (
    <header className={`navbar ${scrolled ? 'scrolled' : ''}`}>
      <div className="container nav-inner">
        <Link to="/" className="brand" aria-label="Dadieng home"><img src="/dadieng-logo.png" alt="Dadieng" /></Link>
        <nav className={`nav-links ${open ? 'open' : ''}`} aria-label="Main navigation">
          {links.map((link) => link.route
            ? <Link key={link.label} to={link.href} onClick={() => setOpen(false)}>{link.label}</Link>
            : <a key={link.label} href={link.href} onClick={() => setOpen(false)}>{link.label}</a>)}
          <Link to="/commander" onClick={() => setOpen(false)} className="nav-console">Run proof →</Link>
        </nav>
        <button className="menu" onClick={() => setOpen(!open)} aria-label={open ? 'Close menu' : 'Open menu'}>{open ? <X /> : <Menu />}</button>
      </div>
    </header>
  );
}
