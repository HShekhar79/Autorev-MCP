import { motion } from 'framer-motion';
import { SectionContainer, AnimatedHeading, GlassCard, TechTag } from '../components/ui';

const TECH = [
  {
    name: 'Radare2', icon: '◈', color: '#00f0ff',
    desc: 'Open-source reverse engineering framework. Provides rapid binary analysis, function detection, and cross-reference graph traversal. Used as the primary extraction engine.',
    features: ['Function detection', 'String extraction', 'Import/export parsing', 'Cross-reference analysis'],
  },
  {
    name: 'Ghidra', icon: '⬡', color: '#00c8ff',
    desc: 'NSA-developed open-source decompiler. When available, Ghidra provides deep decompilation with symbol recovery and high-level pseudocode generation.',
    features: ['Full decompilation', 'Symbol recovery', 'Pseudocode output', 'NSA-grade accuracy'],
  },
  {
    name: 'CAPA', icon: '◆', color: '#ff8c42',
    desc: "FireEye/Mandiant's capability analysis tool. Applies over 1,000 YAML rules to identify behavioral capabilities in PE and ELF binaries.",
    features: ['1,000+ behavioral rules', 'Namespace taxonomy', 'Multi-format support', 'Continuously updated'],
  },
  {
    name: 'MITRE ATT&CK', icon: '◉', color: '#ffb347',
    desc: 'The industry-standard adversarial tactics and techniques framework. ARISE maps every detected capability to ATT&CK technique IDs across Enterprise, Mobile, and ICS matrices.',
    features: ['Enterprise matrix v14', 'Mobile & ICS coverage', 'Technique + sub-technique', 'Tactic phase labeling'],
  },
];

function TechCard({ tech, delay }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ delay }}
      style={{ height: '100%' }}
    >
      <GlassCard glow color={tech.color} style={{ padding: '2rem', height: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.9rem', marginBottom: '1rem' }}>
          <div style={{
            width: 46, height: 46, borderRadius: 10, flexShrink: 0,
            background: `${tech.color}15`, border: `1px solid ${tech.color}30`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 20, color: tech.color,
          }} aria-hidden="true">
            {tech.icon}
          </div>
          <h3 style={{ fontFamily: 'Orbitron', fontSize: 'clamp(14px,2vw,18px)', fontWeight: 700, color: tech.color, letterSpacing: '0.04em' }}>
            {tech.name}
          </h3>
        </div>
        <p style={{ fontFamily: 'Inter', fontSize: 13, color: '#6b8fa8', lineHeight: 1.7, marginBottom: '1rem' }}>
          {tech.desc}
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
          {tech.features.map(f => (
            <span key={f} style={{
              fontFamily: 'Space Mono', fontSize: 9, color: tech.color,
              border: `1px solid ${tech.color}25`, borderRadius: 3,
              padding: '3px 8px', letterSpacing: 0.5,
              background: `${tech.color}06`,
            }}>
              {f}
            </span>
          ))}
        </div>
      </GlassCard>
    </motion.div>
  );
}

export default function AboutPage() {
  return (
    <div className="page-wrapper" style={{ paddingTop: 64 }}>
      <SectionContainer as="section">
        <AnimatedHeading
          center
          subtitle="ARISE (Advanced Real-Time Intelligence for Security Evaluation) is a next-generation malware analysis platform designed for security professionals."
          level={1}
        >
          <span style={{ color: '#e0f4ff' }}>About </span>
          <span className="neon-text">ARISE</span>
        </AnimatedHeading>

        {/* Mission */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <GlassCard glow style={{ padding: 'clamp(1.75rem,4vw,3rem)', marginBottom: '3.5rem', textAlign: 'center' }}>
            <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', letterSpacing: 3, textTransform: 'uppercase', marginBottom: '1rem' }}>
              Mission
            </div>
            <h2 style={{ fontFamily: 'Orbitron', fontSize: 'clamp(1.25rem,3vw,2.25rem)', fontWeight: 700, color: '#e0f4ff', lineHeight: 1.2, marginBottom: '1.25rem', letterSpacing: '0.04em' }}>
              Make elite-grade malware analysis<br />
              <span style={{ color: '#00f0ff', textShadow: '0 0 28px rgba(0,240,255,0.38)' }}>accessible to every analyst.</span>
            </h2>
            <p style={{ fontFamily: 'Inter', fontSize: 14, color: '#6b8fa8', lineHeight: 1.8, maxWidth: 660, margin: '0 auto' }}>
              Traditional malware analysis requires deep expertise across multiple tools — Radare2, Ghidra, CAPA, and MITRE frameworks —
              each with its own learning curve. ARISE unifies them into a single pipeline with AI-powered interpretation,
              so analysts can focus on decisions, not tooling.
            </p>
          </GlassCard>
        </motion.div>

        {/* Architecture */}
        <AnimatedHeading subtitle="How the platform components connect and communicate." level={2}>
          <span style={{ color: '#e0f4ff' }}>System </span>
          <span className="neon-text">Architecture</span>
        </AnimatedHeading>

        <GlassCard style={{ padding: 'clamp(1.5rem,3vw,2.5rem)', marginBottom: '3.5rem' }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, minmax(0,1fr))',
            gap: 'clamp(1rem,3vw,2rem)',
            alignItems: 'start',
          }}
            className="arise-arch-grid"
          >
            {/* Frontend */}
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', letterSpacing: 2, textTransform: 'uppercase', marginBottom: '1rem' }}>
                Frontend
              </div>
              {['React 18', 'Framer Motion', 'Recharts', 'React Router'].map(t => (
                <div key={t} style={{ fontFamily: 'Inter', fontSize: 13, color: '#a0c4d8', padding: '6px 0', borderBottom: '1px solid rgba(0,240,255,0.06)' }}>
                  {t}
                </div>
              ))}
            </div>

            {/* API layer */}
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', letterSpacing: 2, textTransform: 'uppercase', marginBottom: '1rem' }}>
                API Layer
              </div>
              <GlassCard glow style={{ padding: '1.25rem', textAlign: 'center', marginBottom: '0.75rem' }}>
                <div style={{ fontFamily: 'Rajdhani', fontWeight: 700, fontSize: 15, color: '#00f0ff', letterSpacing: 1, marginBottom: '0.4rem' }}>
                  FastAPI
                </div>
                <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', lineHeight: 1.8 }}>
                  POST /upload-analyze<br />
                  GET /task-status/:id<br />
                  DELETE /task/:id<br />
                  GET /health
                </div>
              </GlassCard>
              <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', letterSpacing: 1, textTransform: 'uppercase', marginBottom: '0.5rem' }}>
                ↕ Redis / Celery
              </div>
              <GlassCard style={{ padding: '0.9rem' }}>
                <div style={{ fontFamily: 'Rajdhani', fontWeight: 600, fontSize: 13, color: '#a0c4d8', textAlign: 'center' }}>
                  Celery Worker
                </div>
                <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', textAlign: 'center', marginTop: '0.2rem' }}>
                  Background tasks
                </div>
              </GlassCard>
            </div>

            {/* Analysis */}
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', letterSpacing: 2, textTransform: 'uppercase', marginBottom: '1rem' }}>
                Analysis
              </div>
              {['Radare2', 'Ghidra', 'CAPA Rules', 'MITRE ATT&CK', 'ML Model'].map(t => (
                <div key={t} style={{ fontFamily: 'Inter', fontSize: 13, color: '#a0c4d8', padding: '6px 0', borderBottom: '1px solid rgba(0,240,255,0.06)' }}>
                  {t}
                </div>
              ))}
            </div>
          </div>
        </GlassCard>

        {/* Tech stack */}
        <AnimatedHeading subtitle="The open-source security tools powering every analysis." level={2}>
          <span style={{ color: '#e0f4ff' }}>Technology </span>
          <span className="neon-text">Stack</span>
        </AnimatedHeading>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0,1fr))',
          gap: '1.25rem',
          alignItems: 'stretch',
        }}
          className="arise-tech-grid"
        >
          {TECH.map((t, i) => (
            <TechCard key={t.name} tech={t} delay={i * 0.08} />
          ))}
        </div>
      </SectionContainer>

      <style>{`
        @media (max-width: 680px) {
          .arise-arch-grid { grid-template-columns: 1fr !important; }
          .arise-tech-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
}
