import { useEffect, useRef, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { SectionContainer, AnimatedHeading, GlassCard, StatBadge, TechTag } from '../components/ui';

/* ── Pipeline Visualization ─────────────────────────────────────────────────── */
const PIPELINE_STAGES = [
  { id: 'binary',   label: 'Binary Input', icon: '⬡', desc: 'ELF / PE / Mach-O / APK',   color: '#6b8fa8' },
  { id: 'extract',  label: 'Extraction',   icon: '◈', desc: 'Radare2 + Ghidra',           color: '#00f0ff' },
  { id: 'behav',    label: 'Behaviour',    icon: '◎', desc: 'Dynamic signatures',          color: '#00c8ff' },
  { id: 'cap',      label: 'Capability',   icon: '◆', desc: 'CAPA rule engine',            color: '#009fcc' },
  { id: 'mitre',    label: 'MITRE',        icon: '◉', desc: 'ATT&CK mapping',             color: '#ff8c42' },
  { id: 'risk',     label: 'Risk Score',   icon: '▲', desc: 'ML scoring model',            color: '#ffb347' },
  { id: 'cvss',     label: 'CVSS',         icon: '◐', desc: 'Severity v3.1',              color: '#ff6b6b' },
  { id: 'verdict',  label: 'Verdict',      icon: '★', desc: 'Final classification',        color: '#ff3c6e' },
];

function PipelineViz() {
  const [active, setActive] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setActive(a => (a + 1) % PIPELINE_STAGES.length), 1400);
    return () => clearInterval(t);
  }, []);

  return (
    <div style={{ position: 'relative', padding: '1.5rem 0' }}>
      {/* Connection line — hidden when items wrap */}
      <div aria-hidden="true" style={{
        position: 'absolute', top: '42%', left: '3%', right: '3%', height: 1,
        background: 'linear-gradient(90deg, transparent, rgba(0,240,255,0.18), transparent)',
        pointerEvents: 'none',
      }} />

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '0.75rem 0.5rem',
      }}>
        {PIPELINE_STAGES.map((stage, i) => (
          <motion.div
            key={stage.id}
            animate={{
              scale:   active === i ? 1.06 : 1,
              opacity: active === i ? 1 : active > i ? 0.75 : 0.38,
            }}
            transition={{ duration: 0.3 }}
            style={{ textAlign: 'center' }}
          >
            <div style={{
              width: 44, height: 44, borderRadius: 8, margin: '0 auto 0.4rem',
              border: `1px solid ${active === i ? stage.color : 'rgba(0,240,255,0.12)'}`,
              background: active === i ? `${stage.color}15` : 'rgba(6,18,36,0.6)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 18, color: active === i ? stage.color : '#6b8fa8',
              boxShadow: active === i ? `0 0 18px ${stage.color}35` : 'none',
              transition: 'all 0.3s',
            }}>
              {stage.icon}
            </div>
            <div style={{
              fontFamily: 'Space Mono', fontSize: 8,
              color: active === i ? stage.color : '#6b8fa8',
              letterSpacing: 0.8, textTransform: 'uppercase', lineHeight: 1.3,
            }}>
              {stage.label}
            </div>
          </motion.div>
        ))}
      </div>

      <motion.div
        key={active}
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          textAlign: 'center', marginTop: '1.25rem',
          fontFamily: 'Space Mono', fontSize: 10,
          color: PIPELINE_STAGES[active].color, letterSpacing: 1,
        }}
      >
        ▸ {PIPELINE_STAGES[active].desc}
      </motion.div>
    </div>
  );
}

/* ── Feature Card ───────────────────────────────────────────────────────────── */
function FeatureCard({ icon, title, desc, color = '#00f0ff', delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 36 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.55, delay }}
      style={{ height: '100%' }}
    >
      <GlassCard hover glow color={color} style={{ height: '100%' }}>
        <div style={{
          width: 48, height: 48, borderRadius: 10, flexShrink: 0,
          background: `${color}12`, border: `1px solid ${color}30`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 22, marginBottom: '1rem',
          boxShadow: `0 0 14px ${color}18`,
        }}>
          <span aria-hidden="true">{icon}</span>
        </div>
        <h3 style={{ fontFamily: 'Rajdhani', fontWeight: 700, fontSize: 17, color: '#e0f4ff', letterSpacing: 0.4, marginBottom: '0.5rem' }}>
          {title}
        </h3>
        <p style={{ fontFamily: 'Inter', fontSize: 13, color: '#6b8fa8', lineHeight: 1.7 }}>
          {desc}
        </p>
      </GlassCard>
    </motion.div>
  );
}

/* ── Testimonial Carousel ───────────────────────────────────────────────────── */
const TESTIMONIALS = [
  { name: 'Ethan Nakamura', role: 'SOC Analyst, FinTech Corp',       text: 'ARISE cut our triage time from hours to minutes. The MITRE mapping alone is worth the switch.', rating: 5 },
  { name: 'Priya Sharma',   role: 'Malware Researcher, CyberLab',    text: 'The multi-engine decompilation is elite. Ghidra + Radare2 in one platform, with AI verdict scoring on top.', rating: 5 },
  { name: 'Marcus Webb',    role: 'IR Lead, Defense Contractor',      text: 'We caught a sophisticated APT campaign in 4 minutes flat. The capability clustering is insanely accurate.', rating: 5 },
  { name: 'Lena Fischer',   role: 'Security Engineer, Cloud Co.',     text: 'CVSS auto-scoring is a game changer. No more manual scoring for every sample that crosses our gate.', rating: 5 },
  { name: 'Jin Park',       role: 'Threat Intel, MSSP',               text: "Best malware analysis platform I have touched. The UI is just chef's kiss — everything makes sense.", rating: 5 },
];

function TestimonialCarousel() {
  const [current, setCurrent] = useState(0);
  const totalRef = useRef(TESTIMONIALS.length);

  /* Auto-advance */
  useEffect(() => {
    const t = setInterval(() => setCurrent(c => (c + 1) % totalRef.current), 4500);
    return () => clearInterval(t);
  }, []);

  /* Keyboard navigation */
  const handleKeyDown = useCallback((e) => {
    if (e.key === 'ArrowLeft')  setCurrent(c => (c - 1 + totalRef.current) % totalRef.current);
    if (e.key === 'ArrowRight') setCurrent(c => (c + 1) % totalRef.current);
  }, []);

  return (
    <div
      role="region"
      aria-label="Customer testimonials"
      aria-live="polite"
      aria-roledescription="carousel"
      onKeyDown={handleKeyDown}
    >
      {/* Single-card display — no overflow issue */}
      <div style={{ position: 'relative', minHeight: 200 }}>
        <AnimatePresence mode="wait">
          <motion.div
            key={current}
            initial={{ opacity: 0, x: 24 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -24 }}
            transition={{ duration: 0.4 }}
          >
            <GlassCard style={{ padding: '2rem' }}>
              <div style={{ display: 'flex', gap: 3, marginBottom: '0.75rem' }} aria-label={`${TESTIMONIALS[current].rating} stars`}>
                {[...Array(TESTIMONIALS[current].rating)].map((_, s) => (
                  <span key={s} aria-hidden="true" style={{ color: '#ffb347', fontSize: 13 }}>★</span>
                ))}
              </div>
              <blockquote>
                <p style={{ fontFamily: 'Inter', fontSize: 15, color: '#a0c4d8', lineHeight: 1.75, marginBottom: '1.25rem', fontStyle: 'italic' }}>
                  "{TESTIMONIALS[current].text}"
                </p>
                <footer>
                  <cite style={{ fontStyle: 'normal' }}>
                    <div style={{ fontFamily: 'Rajdhani', fontWeight: 600, fontSize: 15, color: '#e0f4ff' }}>
                      {TESTIMONIALS[current].name}
                    </div>
                    <div style={{ fontFamily: 'Space Mono', fontSize: 10, color: '#6b8fa8', letterSpacing: 0.5, marginTop: 2 }}>
                      {TESTIMONIALS[current].role}
                    </div>
                  </cite>
                </footer>
              </blockquote>
            </GlassCard>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Dot controls */}
      <div
        role="tablist"
        aria-label="Testimonial navigation"
        style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: '1.25rem' }}
      >
        {TESTIMONIALS.map((t, i) => (
          <button
            key={i}
            role="tab"
            aria-selected={i === current}
            aria-label={`Testimonial from ${t.name}`}
            onClick={() => setCurrent(i)}
            style={{
              width: i === current ? 28 : 8, height: 8,
              borderRadius: 4, border: 'none',
              background: i === current ? '#00f0ff' : 'rgba(0,240,255,0.2)',
              cursor: 'pointer', transition: 'all 0.3s',
              padding: 0,
            }}
          />
        ))}
      </div>
    </div>
  );
}

/* ── Landing Page ───────────────────────────────────────────────────────────── */
export default function LandingPage() {
  return (
    <div className="page-wrapper">

      {/* ── Hero ── */}
      <section
        aria-label="Hero"
        style={{
          minHeight: '100vh', display: 'flex', alignItems: 'center',
          padding: 'clamp(5rem,10vh,7rem) clamp(1rem,4vw,2rem) 4rem',
          position: 'relative', overflow: 'hidden',
        }}
      >
        {/* Background radial glow */}
        <div aria-hidden="true" style={{
          position: 'absolute', top: '50%', left: '50%',
          transform: 'translate(-50%,-50%)',
          width: 'min(900px,100vw)', height: 'min(900px,100vh)',
          background: 'radial-gradient(ellipse, rgba(0,240,255,0.045) 0%, transparent 65%)',
          pointerEvents: 'none',
        }} />

        <div style={{ maxWidth: 1200, margin: '0 auto', width: '100%', position: 'relative', zIndex: 1 }}>
          {/* Two-column hero: stacks on mobile */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)',
            gap: 'clamp(2rem,5vw,4rem)',
            alignItems: 'center',
          }}
            className="arise-hero-grid"
          >
            {/* Left: copy */}
            <div>
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5 }}
                style={{
                  fontFamily: 'Space Mono', fontSize: 10, color: '#00f0ff',
                  letterSpacing: 3, textTransform: 'uppercase',
                  marginBottom: '1.5rem',
                  display: 'flex', alignItems: 'center', gap: 8,
                }}
              >
                <span aria-hidden="true" style={{ width: 28, height: 1, background: '#00f0ff', display: 'inline-block', flexShrink: 0 }} />
                Advanced Threat Intelligence
              </motion.div>

              <motion.h1
                initial={{ opacity: 0, y: 36 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.75, delay: 0.1 }}
                style={{
                  fontFamily: 'Orbitron, monospace',
                  fontSize: 'clamp(2rem, 4.5vw, 3.75rem)',
                  fontWeight: 900, lineHeight: 1.08,
                  letterSpacing: '0.04em', marginBottom: '1.5rem',
                }}
              >
                <span style={{ color: '#e0f4ff' }}>NEXT-GEN</span><br />
                <span style={{
                  color: '#00f0ff',
                  textShadow: '0 0 36px rgba(0,240,255,0.5), 0 0 72px rgba(0,240,255,0.2)',
                  animation: 'flicker 8s infinite',
                }}>MALWARE</span><br />
                <span style={{ color: '#e0f4ff' }}>ANALYSIS</span>
              </motion.h1>

              <motion.p
                initial={{ opacity: 0, y: 18 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.65, delay: 0.3 }}
                style={{ fontFamily: 'Inter', fontSize: 15, color: '#6b8fa8', lineHeight: 1.8, marginBottom: '2.25rem', maxWidth: 440 }}
              >
                Upload any binary — ELF, PE, Mach-O, APK — and get a complete threat profile in seconds. Powered by Radare2, Ghidra, CAPA, and MITRE ATT&CK mapping.
              </motion.p>

              <motion.div
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.55, delay: 0.5 }}
                style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}
              >
                <Link to="/analyze" className="btn-primary" style={{ fontSize: 12, padding: '11px 28px' }}>
                  ▸ Analyze File
                </Link>
                <Link to="/how-it-works" className="btn-ghost" style={{ fontSize: 11, padding: '11px 20px' }}>
                  How It Works
                </Link>
              </motion.div>

              {/* Stat row */}
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.8 }}
                style={{ display: 'flex', gap: 'clamp(1rem,3vw,2rem)', marginTop: '2.5rem', flexWrap: 'wrap' }}
              >
                {[
                  { value: '7-Stage', label: 'Pipeline'  },
                  { value: 'CVSS 3.1', label: 'Scoring'   },
                  { value: 'Real-time', label: 'Analysis' },
                ].map(s => (
                  <div key={s.label}>
                    <div style={{ fontFamily: 'Orbitron', fontWeight: 700, fontSize: 'clamp(14px,2vw,18px)', color: '#00f0ff' }}>{s.value}</div>
                    <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', letterSpacing: 1, textTransform: 'uppercase' }}>{s.label}</div>
                  </div>
                ))}
              </motion.div>
            </div>

            {/* Right: pipeline viz */}
            <motion.div
              initial={{ opacity: 0, x: 36 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.85, delay: 0.4 }}
            >
              <GlassCard glow style={{ padding: 'clamp(1.25rem,3vw,2rem)' }}>
                <div style={{
                  fontFamily: 'Space Mono', fontSize: 10, color: '#6b8fa8',
                  letterSpacing: 2, textTransform: 'uppercase',
                  marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <div className="pulse" style={{
                    width: 6, height: 6, borderRadius: '50%',
                    background: '#00ff88', flexShrink: 0,
                  }} />
                  ARISE Pipeline — Live
                </div>
                <PipelineViz />
              </GlassCard>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── Stats ── */}
      <SectionContainer style={{ paddingTop: '1.5rem', paddingBottom: '2.5rem' }}>
        <div className="grid-4" style={{ gap: '1rem' }}>
          <StatBadge value="7"       label="Analysis Stages" color="#00f0ff" />
          <StatBadge value="256MB"   label="Max File Size"   color="#00c8ff" />
          <StatBadge value="CVSS 3.1" label="Severity Scale" color="#ffb347" />
          <StatBadge value="100%"    label="Local Processing" color="#00ff88" />
        </div>
      </SectionContainer>

      {/* ── Features ── */}
      <SectionContainer as="section" aria-labelledby="features-heading">
        <AnimatedHeading
          center
          subtitle="Every analysis goes through a complete multi-engine pipeline — no shortcuts, no approximations."
          level={2}
        >
          <span id="features-heading" style={{ color: '#e0f4ff' }}>Platform </span>
          <span className="neon-text">Capabilities</span>
        </AnimatedHeading>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, minmax(0,1fr))',
          gap: '1.25rem',
          alignItems: 'stretch',
        }}
          className="arise-features-grid"
        >
          <FeatureCard icon="⬡" title="Multi-Engine Decompilation" desc="Combines Radare2 and Ghidra for deep function and import analysis with symbol recovery." color="#00f0ff" delay={0} />
          <FeatureCard icon="◆" title="CAPA Capability Mapping"    desc="FireEye CAPA rules identify behavioral capabilities like process injection, persistence, and anti-analysis." color="#00c8ff" delay={0.08} />
          <FeatureCard icon="◉" title="MITRE ATT&CK Mapping"       desc="Every capability automatically mapped to MITRE ATT&CK technique IDs with confidence scoring." color="#ff8c42" delay={0.16} />
          <FeatureCard icon="▲" title="ML Risk Scoring"            desc="Machine learning model produces a 0–100 risk score calibrated against real-world malware families." color="#ffb347" delay={0.24} />
          <FeatureCard icon="◐" title="CVSS 3.1 Scoring"           desc="Automatic CVSS severity calculation following NVD guidelines for standardized vulnerability disclosure." color="#ff6b6b" delay={0.32} />
          <FeatureCard icon="★" title="Verdict Engine"             desc="Final classification with confidence percentage — MALICIOUS, SUSPICIOUS, or CLEAN — with threat category." color="#ff3c6e" delay={0.4} />
        </div>
      </SectionContainer>

      {/* ── Tech Stack ── */}
      <SectionContainer
        as="section"
        aria-labelledby="tech-heading"
        style={{ background: 'rgba(0,240,255,0.015)', borderTop: '1px solid rgba(0,240,255,0.06)', borderBottom: '1px solid rgba(0,240,255,0.06)' }}
      >
        <AnimatedHeading center subtitle="Built on industry-standard open-source security tools with a proprietary ML layer." level={2}>
          <span id="tech-heading" style={{ color: '#e0f4ff' }}>Powered By </span>
          <span className="neon-text">Elite Tooling</span>
        </AnimatedHeading>
        <div style={{ display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          {['Radare2', 'Ghidra NSA', 'CAPA FireEye', 'MITRE ATT&CK', 'CVSS 3.1 NVD', 'Python FastAPI', 'Celery Redis', 'React Framer'].map(t => (
            <TechTag key={t}>{t}</TechTag>
          ))}
        </div>
      </SectionContainer>

      {/* ── Testimonials ── */}
      <SectionContainer as="section" aria-labelledby="testimonials-heading">
        <AnimatedHeading center subtitle="What security professionals say about ARISE." level={2}>
          <span id="testimonials-heading" className="neon-text">Trusted By</span>
          <span style={{ color: '#e0f4ff' }}> Analysts</span>
        </AnimatedHeading>
        <div style={{ maxWidth: 680, margin: '0 auto' }}>
          <TestimonialCarousel />
        </div>
      </SectionContainer>

      {/* ── CTA ── */}
      <SectionContainer as="section" aria-labelledby="cta-heading">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <GlassCard glow style={{ textAlign: 'center', padding: 'clamp(2.5rem,6vw,4rem) clamp(1.5rem,5vw,3rem)' }}>
            <div style={{ fontFamily: 'Space Mono', fontSize: 10, color: '#6b8fa8', letterSpacing: 3, textTransform: 'uppercase', marginBottom: '1rem' }}>
              Ready to analyze?
            </div>
            <h2
              id="cta-heading"
              style={{ fontFamily: 'Orbitron', fontSize: 'clamp(1.75rem,4vw,2.75rem)', fontWeight: 900, color: '#e0f4ff', marginBottom: '1rem', letterSpacing: '0.04em', lineHeight: 1.15 }}
            >
              DROP A BINARY.<br />
              <span style={{ color: '#00f0ff', textShadow: '0 0 28px rgba(0,240,255,0.5)' }}>GET THE TRUTH.</span>
            </h2>
            <p style={{ fontFamily: 'Inter', fontSize: 15, color: '#6b8fa8', maxWidth: 480, margin: '0 auto 2.5rem', lineHeight: 1.7 }}>
              Upload any malware sample and receive a complete threat intelligence report in under 60 seconds.
            </p>
            <Link to="/analyze" className="btn-primary" style={{ fontSize: 13, padding: '13px 44px' }}>
              ▸ Start Analysis
            </Link>
          </GlassCard>
        </motion.div>
      </SectionContainer>

      {/* Responsive styles */}
      <style>{`
        @media (max-width: 860px) {
          .arise-hero-grid     { grid-template-columns: 1fr !important; }
          .arise-features-grid { grid-template-columns: repeat(2, minmax(0,1fr)) !important; }
        }
        @media (max-width: 540px) {
          .arise-features-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
}
