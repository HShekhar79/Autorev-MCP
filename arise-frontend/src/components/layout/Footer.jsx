import { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import TechDetailModal from './TechDetailModal';
import { TECH_GROUPS, TECH_DETAILS } from './techDetails';

const PLATFORM_LINKS = [
  { label: 'Analyze File',   to: '/analyze' },
  { label: 'How It Works',   to: '/how-it-works' },
  { label: 'About',          to: '/about' },
  { label: 'FAQ',            to: '/faq' },
];

const HEADING_STYLE = { fontFamily: 'Space Mono', fontSize: 10, color: '#00f0ff', letterSpacing: 2, textTransform: 'uppercase', marginBottom: '1rem' };

export default function Footer() {
  const [activeTech, setActiveTech] = useState(null);
  const closeTech = useCallback(() => setActiveTech(null), []);

  return (
    <footer
      aria-label="Site footer"
      style={{
        borderTop: '1px solid rgba(0,240,255,0.08)',
        padding: 'clamp(2rem,5vw,3rem) clamp(1rem,4vw,2rem)',
        background: 'rgba(2,8,16,0.97)',
        position: 'relative', zIndex: 1,
      }}
    >
      <div style={{ maxWidth: 'var(--max-w)', margin: '0 auto' }}>
        {/* Responsive grid: see .arise-footer-grid in index.css */}
        <div className="arise-footer-grid" style={{ marginBottom: '2rem' }}>
          {/* Brand */}
          <div className="arise-footer-brand">
            <div style={{
              fontFamily: 'Orbitron, monospace', fontSize: 18, fontWeight: 700,
              color: '#fff', marginBottom: '0.75rem', letterSpacing: '0.12em',
            }}>
              <span style={{ color: '#00f0ff' }}>A</span>RISE
            </div>
            <p style={{
              fontFamily: 'Inter', fontSize: 13, color: '#6b8fa8',
              lineHeight: 1.7, maxWidth: 260,
            }}>
              Advanced Real-Time Intelligence for Security Evaluation. Next-generation binary analysis powered by multi-engine decompilation and AI.
            </p>
          </div>

          {/* Platform */}
          <nav aria-label="Footer platform links">
            <div style={HEADING_STYLE}>
              Platform
            </div>
            <ul style={{ listStyle: 'none' }}>
              {PLATFORM_LINKS.map(item => (
                <li key={item.to} style={{ marginBottom: '0.5rem' }}>
                  <Link
                    to={item.to}
                    style={{
                      fontFamily: 'Inter', fontSize: 13, color: '#6b8fa8',
                      textDecoration: 'none', transition: 'color 0.2s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.color = '#a0c4d8'}
                    onMouseLeave={e => e.currentTarget.style.color = '#6b8fa8'}
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>

          {/* Technologies — each item opens a details dialog */}
          {TECH_GROUPS.map(group => (
            <nav key={group.heading} aria-label={group.heading}>
              <div style={HEADING_STYLE}>{group.heading}</div>
              <ul style={{ listStyle: 'none' }}>
                {group.keys.map(key => (
                  <li key={key} style={{ marginBottom: '0.25rem' }}>
                    <button
                      type="button"
                      className="arise-tech-link"
                      aria-haspopup="dialog"
                      onClick={() => setActiveTech(key)}
                    >
                      {TECH_DETAILS[key].name}
                      <span className="arise-tech-link-arrow" aria-hidden="true">›</span>
                    </button>
                  </li>
                ))}
              </ul>
            </nav>
          ))}

          {/* System status */}
          <div>
            <div style={HEADING_STYLE}>
              System
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '0.75rem' }}>
              <div role="status" aria-label="API Online" style={{
                width: 7, height: 7, borderRadius: '50%',
                background: '#00ff88', boxShadow: '0 0 8px #00ff88',
                flexShrink: 0,
              }} />
              <span style={{ fontFamily: 'Space Mono', fontSize: 10, color: '#00ff88' }}>API Online</span>
            </div>
            <dl style={{ fontFamily: 'Space Mono', fontSize: 10, color: '#6b8fa8', lineHeight: 2 }}>
              <div><dt style={{ display: 'inline' }}>Version </dt><dd style={{ display: 'inline' }}>v2.0.0</dd></div>
              <div><dt style={{ display: 'inline' }}>Pipeline </dt><dd style={{ display: 'inline' }}>Active</dd></div>
            </dl>
          </div>
        </div>

        {/* Bottom bar */}
        <div style={{
          borderTop: '1px solid rgba(0,240,255,0.08)',
          paddingTop: '1.25rem',
          display: 'flex', justifyContent: 'space-between',
          alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem',
        }}>
          <small style={{ fontFamily: 'Space Mono', fontSize: 10, color: 'rgba(107,143,168,0.5)', letterSpacing: 1 }}>
            © 2025 ARISE PLATFORM — ADVANCED THREAT INTELLIGENCE
          </small>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {['RADARE2', 'GHIDRA', 'CAPA', 'MITRE'].map(tag => (
              <span key={tag} style={{
                fontFamily: 'Space Mono', fontSize: 9,
                color: 'rgba(107,143,168,0.5)',
                border: '1px solid rgba(0,240,255,0.08)',
                borderRadius: 3, padding: '2px 6px', letterSpacing: 1,
              }}>
                {tag}
              </span>
            ))}
          </div>
        </div>
      </div>

      {activeTech && <TechDetailModal techKey={activeTech} onClose={closeTech} />}
    </footer>
  );
}
