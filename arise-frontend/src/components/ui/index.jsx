import { motion } from 'framer-motion';

/* ── GlassCard ──────────────────────────────────────────────────────────────── */
export function GlassCard({ children, style = {}, hover = true, glow = false, color = '#00f0ff', onClick, role, 'aria-label': ariaLabel }) {
  return (
    <motion.div
      className="glass"
      onClick={onClick}
      role={role}
      aria-label={ariaLabel}
      whileHover={hover ? { borderColor: 'rgba(0,240,255,0.28)', y: -2 } : {}}
      style={{
        padding: '1.5rem',
        boxShadow: glow ? `0 0 28px ${color}18, inset 0 0 18px ${color}05` : 'none',
        cursor: onClick ? 'pointer' : 'default',
        transition: 'box-shadow 0.3s',
        ...style,
      }}
    >
      {children}
    </motion.div>
  );
}

/* ── NeonButton ─────────────────────────────────────────────────────────────── */
export function NeonButton({ children, onClick, href, variant = 'primary', style = {}, disabled = false, 'aria-label': ariaLabel }) {
  const cls = variant === 'primary' ? 'btn-primary' : 'btn-ghost';
  const Tag = href ? 'a' : 'button';
  return (
    <Tag
      className={cls}
      onClick={onClick}
      href={href}
      disabled={disabled}
      aria-label={ariaLabel}
      style={{ ...style, opacity: disabled ? 0.5 : 1, cursor: disabled ? 'not-allowed' : 'pointer' }}
    >
      {children}
    </Tag>
  );
}

/* ── SectionContainer ───────────────────────────────────────────────────────── */
/* Uses CSS variables for consistent responsive padding */
export function SectionContainer({ children, style = {}, maxWidth = 1200, as: Tag = 'section' }) {
  return (
    <Tag style={{
      padding: 'var(--section-py) var(--section-px)',
      position: 'relative', zIndex: 1,
      ...style,
    }}>
      <div style={{ maxWidth, margin: '0 auto' }}>
        {children}
      </div>
    </Tag>
  );
}

/* ── AnimatedHeading ────────────────────────────────────────────────────────── */
export function AnimatedHeading({ children, subtitle, center = false, style = {}, level = 2 }) {
  const Tag = `h${level}`;
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.6 }}
      style={{ textAlign: center ? 'center' : 'left', marginBottom: '2.5rem', ...style }}
    >
      <Tag className="section-title">{children}</Tag>
      {subtitle && (
        <p style={{
          fontFamily: 'Inter', fontSize: 15, color: '#6b8fa8',
          marginTop: '0.75rem', lineHeight: 1.7,
          maxWidth: center ? 560 : '100%',
          margin: center ? '0.75rem auto 0' : '0.75rem 0 0',
        }}>
          {subtitle}
        </p>
      )}
    </motion.div>
  );
}

/* ── StatBadge ──────────────────────────────────────────────────────────────── */
export function StatBadge({ label, value, color = '#00f0ff' }) {
  return (
    <GlassCard style={{ padding: '1.25rem', textAlign: 'center', minWidth: 0 }} glow color={color}>
      {/* minWidth:0 prevents grid blowout */}
      <div style={{
        fontFamily: 'Orbitron', fontWeight: 700,
        fontSize: 'clamp(1.4rem, 3vw, 2rem)',
        color, textShadow: `0 0 18px ${color}60`,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>
        {value}
      </div>
      <div style={{
        fontFamily: 'Space Mono', fontSize: 10, color: '#6b8fa8',
        letterSpacing: 1.5, textTransform: 'uppercase', marginTop: '0.4rem',
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>
        {label}
      </div>
    </GlassCard>
  );
}

/* ── TechTag ────────────────────────────────────────────────────────────────── */
export function TechTag({ children }) {
  return (
    <span style={{
      fontFamily: 'Space Mono', fontSize: 10, color: '#00f0ff',
      border: '1px solid rgba(0,240,255,0.25)', borderRadius: 4,
      padding: '5px 12px', letterSpacing: 1,
      background: 'rgba(0,240,255,0.05)',
      display: 'inline-block',
    }}>
      {children}
    </span>
  );
}
