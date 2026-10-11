import { useState, useEffect, useRef, useCallback } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';

const LINKS = [
  { to: '/',             label: 'Home' },
  { to: '/analyze',      label: 'Analyze' },
  { to: '/how-it-works', label: 'How It Works' },
  { to: '/about',        label: 'About' },
  { to: '/faq',          label: 'FAQ' },
];

export default function Navbar() {
  const [scrolled,  setScrolled]  = useState(false);
  const [menuOpen,  setMenuOpen]  = useState(false);
  const location = useLocation();
  const menuRef  = useRef(null);
  const btnRef   = useRef(null);

  /* Scroll detection */
  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 40);
    window.addEventListener('scroll', fn, { passive: true });
    return () => window.removeEventListener('scroll', fn);
  }, []);

  /* Close mobile menu on route change */
  useEffect(() => { setMenuOpen(false); }, [location.pathname]);

  /* Close on outside click */
  useEffect(() => {
    if (!menuOpen) return;
    const handler = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target) &&
          btnRef.current  && !btnRef.current.contains(e.target)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [menuOpen]);

  /* Keyboard: Escape closes menu */
  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Escape' && menuOpen) {
      setMenuOpen(false);
      btnRef.current?.focus();
    }
  }, [menuOpen]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return (
    <motion.nav
      role="navigation"
      aria-label="Main navigation"
      initial={{ y: -60, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.55, ease: 'easeOut' }}
      style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
        height: 64,
        background: scrolled ? 'rgba(2,8,16,0.97)' : 'rgba(2,8,16,0.65)',
        backdropFilter: 'blur(18px)',
        WebkitBackdropFilter: 'blur(18px)',
        borderBottom: `1px solid ${scrolled ? 'rgba(0,240,255,0.12)' : 'transparent'}`,
        transition: 'background 0.35s, border-color 0.35s',
        display: 'flex', alignItems: 'center',
        padding: '0 clamp(1rem, 4vw, 2rem)',
      }}
    >
      {/* Logo */}
      <Link
        to="/"
        aria-label="ARISE — Home"
        style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}
      >
        <div style={{
          width: 32, height: 32,
          border: '1px solid rgba(0,240,255,0.5)',
          borderRadius: 6,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'rgba(0,240,255,0.08)',
        }}>
          <div className="pulse" style={{
            width: 10, height: 10,
            background: '#00f0ff',
            borderRadius: '50%',
          }} />
        </div>
        <span style={{
          fontFamily: 'Orbitron, monospace',
          fontWeight: 700, fontSize: 18,
          letterSpacing: '0.15em',
          color: '#fff',
        }}>
          <span style={{ color: '#00f0ff' }}>A</span>RISE
        </span>
      </Link>

      {/* Desktop nav links */}
      <div
        role="list"
        style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
        className="arise-desktop-nav"
      >
        {LINKS.map(link => {
          const active = location.pathname === link.to;
          return (
            <Link
              key={link.to}
              to={link.to}
              role="listitem"
              aria-current={active ? 'page' : undefined}
              style={{
                textDecoration: 'none',
                fontFamily: 'Space Mono, monospace',
                fontSize: 11, letterSpacing: '1.5px',
                textTransform: 'uppercase',
                padding: '6px 14px',
                borderRadius: 4,
                color: active ? '#00f0ff' : '#6b8fa8',
                background: active ? 'rgba(0,240,255,0.08)' : 'none',
                border: `1px solid ${active ? 'rgba(0,240,255,0.2)' : 'transparent'}`,
                transition: 'all 0.2s',
                whiteSpace: 'nowrap',
              }}
              onMouseEnter={e => { if (!active) { e.currentTarget.style.color = '#a0c4d8'; e.currentTarget.style.borderColor = 'rgba(0,240,255,0.1)'; }}}
              onMouseLeave={e => { if (!active) { e.currentTarget.style.color = '#6b8fa8'; e.currentTarget.style.borderColor = 'transparent'; }}}
            >
              {link.label}
            </Link>
          );
        })}
        <Link
          to="/analyze"
          style={{
            marginLeft: '1rem',
            fontFamily: 'Space Mono, monospace',
            fontSize: 11,
            letterSpacing: '2px',
            textTransform: 'uppercase',
            padding: '8px 20px',
            borderRadius: 4,
            textDecoration: 'none',
            color: '#020810',
            background: 'linear-gradient(135deg, #00f0ff, #0099cc)',
            boxShadow: '0 0 16px rgba(0,240,255,0.5), 0 0 32px rgba(0,240,255,0.2)',
            fontWeight: 700,
            transition: 'all 0.25s',
            display: 'inline-block',
            whiteSpace: 'nowrap',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.boxShadow = '0 0 28px rgba(0,240,255,0.8), 0 0 56px rgba(0,240,255,0.35)';
            e.currentTarget.style.transform = 'translateY(-1px)';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.boxShadow = '0 0 16px rgba(0,240,255,0.5), 0 0 32px rgba(0,240,255,0.2)';
            e.currentTarget.style.transform = 'translateY(0)';
          }}
        >
          Analyze File
        </Link>
      </div>

      {/* Mobile hamburger */}
      <button
        ref={btnRef}
        onClick={() => setMenuOpen(x => !x)}
        aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'}
        aria-expanded={menuOpen}
        aria-controls="mobile-menu"
        style={{
          marginLeft: 'auto',
          background: 'none', border: '1px solid rgba(0,240,255,0.2)',
          color: '#00f0ff', cursor: 'pointer', padding: '7px',
          borderRadius: 4,
          display: 'none',
          flexDirection: 'column', justifyContent: 'center', alignItems: 'center',
          width: 36, height: 36, gap: 5,
        }}
        className="arise-mobile-btn"
      >
        <motion.span
          animate={menuOpen
            ? { rotate: 45, y: 6, width: 20 }
            : { rotate: 0,  y: 0, width: 20 }
          }
          transition={{ duration: 0.22 }}
          style={{ display: 'block', height: 2, background: '#00f0ff', borderRadius: 1, transformOrigin: 'center' }}
        />
        <motion.span
          animate={{ opacity: menuOpen ? 0 : 1, scaleX: menuOpen ? 0 : 1 }}
          transition={{ duration: 0.18 }}
          style={{ display: 'block', height: 2, width: 20, background: '#00f0ff', borderRadius: 1 }}
        />
        <motion.span
          animate={menuOpen
            ? { rotate: -45, y: -6, width: 20 }
            : { rotate: 0,   y: 0,  width: 20 }
          }
          transition={{ duration: 0.22 }}
          style={{ display: 'block', height: 2, background: '#00f0ff', borderRadius: 1, transformOrigin: 'center' }}
        />
      </button>

      {/* Mobile dropdown menu */}
      <AnimatePresence>
        {menuOpen && (
          <motion.div
            id="mobile-menu"
            ref={menuRef}
            role="menu"
            aria-label="Mobile navigation"
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.22 }}
            style={{
              position: 'absolute', top: 64, left: 0, right: 0,
              background: 'rgba(2,8,16,0.99)',
              borderBottom: '1px solid rgba(0,240,255,0.15)',
              padding: '0.75rem clamp(1rem, 4vw, 2rem) 1rem',
              display: 'flex', flexDirection: 'column', gap: '0.25rem',
            }}
          >
            {LINKS.map(link => {
              const active = location.pathname === link.to;
              return (
                <Link
                  key={link.to}
                  to={link.to}
                  role="menuitem"
                  aria-current={active ? 'page' : undefined}
                  style={{
                    fontFamily: 'Space Mono', fontSize: 12,
                    color: active ? '#00f0ff' : '#a0c4d8',
                    textDecoration: 'none',
                    padding: '0.6rem 0.75rem',
                    borderRadius: 4,
                    background: active ? 'rgba(0,240,255,0.06)' : 'none',
                    letterSpacing: 1,
                    transition: 'background 0.15s, color 0.15s',
                  }}
                >
                  {link.label}
                </Link>
              );
            })}
            <Link
              to="/analyze"
              className="btn-primary"
              style={{ marginTop: '0.5rem', textAlign: 'center', fontSize: 11 }}
            >
              Analyze File
            </Link>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Responsive breakpoint styles */}
      <style>{`
        @media (max-width: 820px) {
          .arise-desktop-nav { display: none !important; }
          .arise-mobile-btn  { display: flex !important; }
        }
      `}</style>
    </motion.nav>
  );
}
