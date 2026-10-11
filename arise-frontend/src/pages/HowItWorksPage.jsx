import { useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { SectionContainer, AnimatedHeading, GlassCard } from '../components/ui';

const STAGES = [
  {
    num: '01', id: 'binary', label: 'Binary Input', icon: '⬡', color: '#a0c4d8',
    desc: 'Upload any executable binary — Windows PE (.exe, .dll), Linux ELF, macOS Mach-O, or Android APK. The file is saved to a secure temporary location and queued for analysis.',
    details: ['Supports PE32, PE32+, ELF32/64, Mach-O, APK', 'File validated for format integrity', 'Queued via Redis + Celery', 'Max 256MB per sample'],
    tool: 'FastAPI Upload',
  },
  {
    num: '02', id: 'extraction', label: 'Extraction', icon: '◈', color: '#00f0ff',
    desc: 'Multi-engine decompilation extracts functions, imports, exports, strings, and API call sequences. Radare2 provides rapid analysis; Ghidra adds deep decompilation when available.',
    details: ['Function list with addresses and sizes', 'Import/export table parsing', 'String extraction (ASCII + Unicode)', 'API call sequence reconstruction'],
    tool: 'Radare2 + Ghidra',
  },
  {
    num: '03', id: 'behaviour', label: 'Behaviour', icon: '◎', color: '#00c8ff',
    desc: 'Static behavioral signatures are applied to identify malicious patterns: network callbacks, process spawning, file system writes, registry modifications, and anti-analysis tricks.',
    details: ['Network communication patterns', 'Persistence mechanisms', 'Code injection techniques', 'Anti-VM / anti-debug heuristics'],
    tool: 'Custom Signature Engine',
  },
  {
    num: '04', id: 'capability', label: 'Capability', icon: '◆', color: '#009fcc',
    desc: 'FireEye CAPA rules are applied to identify atomic malware capabilities. Over 1,000 rules cover techniques like shellcode injection, credential dumping, lateral movement, and more.',
    details: ['1,000+ CAPA rules applied', 'Namespace-organized results', 'Attack phase classification', 'Platform-specific capability detection'],
    tool: 'FireEye CAPA',
  },
  {
    num: '05', id: 'mitre', label: 'MITRE ATT&CK', icon: '◉', color: '#ff8c42',
    desc: 'Every detected capability is mapped to MITRE ATT&CK technique IDs. The mapping covers Enterprise, Mobile, and ICS matrices, providing standardized threat intelligence.',
    details: ['Enterprise / Mobile / ICS matrices', 'Technique + sub-technique IDs', 'Tactic phase labeling', 'Confidence scoring per technique'],
    tool: 'MITRE ATT&CK v14',
  },
  {
    num: '06', id: 'risk', label: 'Risk Score', icon: '▲', color: '#ffb347',
    desc: 'A machine learning model produces a normalized 0–100 risk score. Trained on thousands of malware samples and clean binaries, it weighs capability severity, technique count, and behavioral indicators.',
    details: ['0–100 normalized risk scale', 'ML model trained on real samples', 'Weighted capability scoring', 'Family-based calibration'],
    tool: 'ML Scoring Model',
  },
  {
    num: '07', id: 'cvss', label: 'CVSS', icon: '◐', color: '#ff6b6b',
    desc: 'Common Vulnerability Scoring System v3.1 severity is calculated following NVD guidelines. Attack vector, complexity, privileges, and impact are derived from the behavioral analysis.',
    details: ['CVSS Base Score 0.0–10.0', 'Attack vector classification', 'Impact metrics: C/I/A', 'NVD-compliant calculation'],
    tool: 'CVSS v3.1 NVD',
  },
  {
    num: '08', id: 'verdict', label: 'Verdict', icon: '★', color: '#ff3c6e',
    desc: 'The analysis pipeline concludes with a final verdict: MALICIOUS, SUSPICIOUS, or CLEAN. Confidence percentage, malware category, and a human-readable summary are generated.',
    details: ['MALICIOUS / SUSPICIOUS / CLEAN', 'Confidence percentage 0–100%', 'Threat category classification', 'Natural language summary'],
    tool: 'Verdict Engine',
  },
];

export default function HowItWorksPage() {
  const [activeStage, setActiveStage] = useState(0);
  const tabListRef = useRef(null);

  /* Arrow key navigation on the tab row */
  const handleTabKeyDown = useCallback((e, i) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      const next = (i + 1) % STAGES.length;
      setActiveStage(next);
      tabListRef.current?.querySelectorAll('[role="tab"]')[next]?.focus();
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      const prev = (i - 1 + STAGES.length) % STAGES.length;
      setActiveStage(prev);
      tabListRef.current?.querySelectorAll('[role="tab"]')[prev]?.focus();
    } else if (e.key === 'Home') {
      e.preventDefault();
      setActiveStage(0);
      tabListRef.current?.querySelectorAll('[role="tab"]')[0]?.focus();
    } else if (e.key === 'End') {
      e.preventDefault();
      const last = STAGES.length - 1;
      setActiveStage(last);
      tabListRef.current?.querySelectorAll('[role="tab"]')[last]?.focus();
    }
  }, []);

  const s = STAGES[activeStage];

  return (
    <div className="page-wrapper" style={{ paddingTop: 64 }}>
      <SectionContainer as="section">
        <AnimatedHeading
          center
          subtitle="Every binary goes through an 8-stage pipeline that combines open-source tooling, machine learning, and threat intelligence frameworks."
          level={1}
        >
          <span style={{ color: '#e0f4ff' }}>The </span>
          <span className="neon-text">ARISE Pipeline</span>
        </AnimatedHeading>

        {/* Stage selector — accessible tab list */}
        <div
          role="tablist"
          aria-label="Pipeline stages"
          ref={tabListRef}
          style={{ display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: '0.4rem', marginBottom: '2.5rem' }}
        >
          {STAGES.map((st, i) => (
            <motion.button
              key={st.id}
              role="tab"
              id={`tab-${st.id}`}
              aria-selected={activeStage === i}
              aria-controls={`panel-${st.id}`}
              tabIndex={activeStage === i ? 0 : -1}
              onClick={() => setActiveStage(i)}
              onKeyDown={(e) => handleTabKeyDown(e, i)}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              style={{
                background: activeStage === i ? `${st.color}15` : 'rgba(6,18,36,0.6)',
                border: `1px solid ${activeStage === i ? st.color : 'rgba(0,240,255,0.12)'}`,
                color: activeStage === i ? st.color : '#6b8fa8',
                fontFamily: 'Space Mono', fontSize: 9,
                letterSpacing: 1, textTransform: 'uppercase',
                padding: '5px 12px', borderRadius: 4,
                cursor: 'pointer', transition: 'all 0.2s',
                boxShadow: activeStage === i ? `0 0 14px ${st.color}28` : 'none',
              }}
            >
              {st.num} {st.label}
            </motion.button>
          ))}
        </div>

        {/* Active stage detail panel */}
        <AnimatePresence mode="wait">
          <motion.div
            key={activeStage}
            role="tabpanel"
            id={`panel-${s.id}`}
            aria-labelledby={`tab-${s.id}`}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -16 }}
            transition={{ duration: 0.35 }}
          >
            <GlassCard style={{ padding: 'clamp(1.5rem,4vw,2.5rem)' }} glow color={s.color}>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)',
                gap: 'clamp(1.5rem,4vw,3rem)',
                alignItems: 'start',
              }}
                className="arise-hiw-detail"
              >
                {/* Left: description */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
                    <div style={{
                      width: 60, height: 60, borderRadius: 12, flexShrink: 0,
                      background: `${s.color}15`, border: `1px solid ${s.color}40`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 26, color: s.color,
                      boxShadow: `0 0 22px ${s.color}28`,
                    }} aria-hidden="true">
                      {s.icon}
                    </div>
                    <div>
                      <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', letterSpacing: 2, textTransform: 'uppercase' }}>
                        Stage {s.num}
                      </div>
                      <h2 style={{ fontFamily: 'Orbitron', fontSize: 'clamp(1.1rem,2.5vw,1.5rem)', fontWeight: 700, color: s.color, letterSpacing: '0.04em', textShadow: `0 0 18px ${s.color}38` }}>
                        {s.label}
                      </h2>
                    </div>
                  </div>
                  <p style={{ fontFamily: 'Inter', fontSize: 14, color: '#a0c4d8', lineHeight: 1.8, marginBottom: '1.5rem' }}>
                    {s.desc}
                  </p>
                  <div style={{
                    display: 'inline-flex', alignItems: 'center', gap: 8,
                    border: `1px solid ${s.color}30`, borderRadius: 4,
                    padding: '5px 12px', background: `${s.color}08`,
                  }}>
                    <span style={{ fontFamily: 'Space Mono', fontSize: 9, color: s.color, letterSpacing: 1 }}>
                      ENGINE: {s.tool}
                    </span>
                  </div>
                </div>

                {/* Right: extraction list */}
                <div>
                  <div style={{ fontFamily: 'Space Mono', fontSize: 9, color: '#6b8fa8', letterSpacing: 2, textTransform: 'uppercase', marginBottom: '0.75rem' }}>
                    What gets extracted
                  </div>
                  <ul style={{ listStyle: 'none' }}>
                    {s.details.map((d, i) => (
                      <motion.li
                        key={i}
                        initial={{ opacity: 0, x: 16 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.07 }}
                        style={{
                          display: 'flex', alignItems: 'flex-start', gap: 10,
                          padding: '0.65rem 0.9rem', borderRadius: 6,
                          background: 'rgba(0,240,255,0.03)',
                          border: '1px solid rgba(0,240,255,0.07)',
                          marginBottom: '0.4rem',
                        }}
                      >
                        <span aria-hidden="true" style={{ color: s.color, fontSize: 11, marginTop: 2, flexShrink: 0 }}>▸</span>
                        <span style={{ fontFamily: 'Inter', fontSize: 13, color: '#a0c4d8', lineHeight: 1.5 }}>{d}</span>
                      </motion.li>
                    ))}
                  </ul>
                </div>
              </div>
            </GlassCard>
          </motion.div>
        </AnimatePresence>

        {/* Dot pagination */}
        <div
          role="group"
          aria-label="Stage pagination"
          style={{ display: 'flex', justifyContent: 'center', gap: '0.45rem', marginTop: '1.5rem' }}
        >
          {STAGES.map((st, i) => (
            <button
              key={i}
              onClick={() => setActiveStage(i)}
              aria-label={`Go to stage ${st.num}: ${st.label}`}
              aria-current={i === activeStage ? 'true' : undefined}
              style={{
                width: i === activeStage ? 30 : 8, height: 8,
                borderRadius: 4, border: 'none',
                background: i === activeStage ? st.color : 'rgba(0,240,255,0.15)',
                cursor: 'pointer', transition: 'all 0.3s', padding: 0,
              }}
            />
          ))}
        </div>

        {/* Full pipeline timeline */}
        <div style={{ marginTop: '4rem' }}>
          <AnimatedHeading center level={2}>
            <span style={{ color: '#e0f4ff' }}>Full </span>
            <span className="neon-text">Pipeline Flow</span>
          </AnimatedHeading>

          <div style={{ position: 'relative', maxWidth: 800, margin: '0 auto' }}>
            {/* Center vertical rule */}
            <div aria-hidden="true" style={{
              position: 'absolute', left: '50%', top: 0, bottom: 0,
              width: 1, background: 'linear-gradient(180deg, transparent, rgba(0,240,255,0.2), transparent)',
              transform: 'translateX(-50%)',
            }} />

            {STAGES.map((stage, i) => (
              <motion.div
                key={stage.id}
                initial={{ opacity: 0, x: i % 2 === 0 ? -32 : 32 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: i * 0.04 }}
                style={{
                  display: 'flex',
                  justifyContent: i % 2 === 0 ? 'flex-end' : 'flex-start',
                  marginBottom: '1.25rem',
                  paddingLeft:  i % 2 === 0 ? 0 : '52%',
                  paddingRight: i % 2 === 0 ? '52%' : 0,
                  position: 'relative',
                }}
              >
                <button
                  onClick={() => { setActiveStage(i); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
                  aria-label={`Jump to stage ${stage.num}: ${stage.label}`}
                  style={{
                    padding: '0.85rem 1.1rem', borderRadius: 8, cursor: 'pointer',
                    border: `1px solid ${activeStage === i ? stage.color : 'rgba(0,240,255,0.1)'}`,
                    background: activeStage === i ? `${stage.color}10` : 'rgba(6,18,36,0.8)',
                    transition: 'all 0.2s', maxWidth: 260, textAlign: 'left',
                    boxShadow: activeStage === i ? `0 0 18px ${stage.color}18` : 'none',
                    width: '100%',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span aria-hidden="true" style={{ fontSize: 16, color: stage.color }}>{stage.icon}</span>
                    <div>
                      <div style={{ fontFamily: 'Space Mono', fontSize: 8, color: '#6b8fa8', letterSpacing: 1 }}>
                        STAGE {stage.num}
                      </div>
                      <div style={{ fontFamily: 'Rajdhani', fontWeight: 700, fontSize: 15, color: activeStage === i ? stage.color : '#e0f4ff' }}>
                        {stage.label}
                      </div>
                    </div>
                  </div>
                </button>

                {/* Center dot */}
                <div aria-hidden="true" style={{
                  position: 'absolute', left: '50%', top: '50%',
                  transform: 'translate(-50%,-50%)',
                  width: 9, height: 9, borderRadius: '50%',
                  background: stage.color, boxShadow: `0 0 10px ${stage.color}`,
                  flexShrink: 0,
                }} />
              </motion.div>
            ))}
          </div>
        </div>
      </SectionContainer>

      <style>{`
        @media (max-width: 680px) {
          .arise-hiw-detail { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
}
