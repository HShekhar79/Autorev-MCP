import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { TECH_DETAILS } from './techDetails';

const FOCUSABLE = 'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])';

const SECTIONS = [
  { key: 'what',    label: 'What it is' },
  { key: 'role',    label: 'Role & public reference' },
  { key: 'usefulFor', label: 'Useful for', list: true },
  { key: 'benefit', label: 'Benefit to analysts' },
  { key: 'arise',   label: 'In ARISE', accent: true },
];

/**
 * Accessible modal dialog for a footer technology.
 * - Rendered in a portal so it is not clipped by the footer's stacking context
 * - Escape / backdrop / close button dismiss; Tab is trapped inside
 * - Focus returns to the element that opened it
 * - Page scroll locked without shifting layout
 */
export default function TechDetailModal({ techKey, onClose }) {
  const tech = TECH_DETAILS[techKey];
  const dialogRef = useRef(null);
  const closeRef = useRef(null);

  useEffect(() => {
    const opener = document.activeElement;
    const { body } = document;
    const prevOverflow = body.style.overflow;
    const prevPad = body.style.paddingRight;
    const scrollbar = window.innerWidth - document.documentElement.clientWidth;
    body.style.overflow = 'hidden';
    if (scrollbar > 0) body.style.paddingRight = scrollbar + 'px';
    if (closeRef.current) closeRef.current.focus();

    const onKey = (e) => {
      if (e.key === 'Escape') { e.stopPropagation(); onClose(); return; }
      if (e.key !== 'Tab' || !dialogRef.current) return;
      const items = dialogRef.current.querySelectorAll(FOCUSABLE);
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKey);

    return () => {
      document.removeEventListener('keydown', onKey);
      body.style.overflow = prevOverflow;
      body.style.paddingRight = prevPad;
      if (opener && typeof opener.focus === 'function') opener.focus();
    };
  }, [onClose]);

  if (!tech) return null;
  const titleId = 'arise-tech-title-' + techKey;

  return createPortal(
    <div className="arise-tech-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div
        ref={dialogRef}
        className="arise-tech-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <div className="arise-tech-head">
          <div style={{ minWidth: 0 }}>
            <span className="arise-tech-kind">{tech.kind}</span>
            <h2 id={titleId} className="arise-tech-title">{tech.name}</h2>
            <p className="arise-tech-summary">{tech.summary}</p>
          </div>
          <button ref={closeRef} type="button" className="arise-tech-close" onClick={onClose} aria-label={'Close ' + tech.name + ' details'}>
            ✕
          </button>
        </div>

        <div className="arise-tech-body">
          {SECTIONS.map(s => (
            <section key={s.key} className="arise-tech-section">
              <h3 className={'arise-tech-label' + (s.accent ? ' is-accent' : '')}>{s.label}</h3>
              {s.list ? (
                <ul className="arise-tech-list">
                  {tech[s.key].map(item => <li key={item}>{item}</li>)}
                </ul>
              ) : (
                <p className="arise-tech-text">{tech[s.key]}</p>
              )}
            </section>
          ))}
          {tech.note && <p className="arise-tech-note">{tech.note}</p>}
        </div>

        <div className="arise-tech-foot">
          <a href={tech.link.href} target="_blank" rel="noopener noreferrer" className="arise-tech-ext">
            {tech.link.label} ↗<span className="arise-sr-only"> (opens in a new tab)</span>
          </a>
          <span className="arise-tech-disclaimer">
            Third-party names belong to their respective owners. ARISE is not affiliated with or endorsed by them.
          </span>
        </div>
      </div>
    </div>,
    document.body
  );
}
