import { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { SectionContainer, AnimatedHeading, GlassCard } from '../components/ui';
import { Link } from 'react-router-dom';

const FAQS = [
  { q: 'What file formats does ARISE support?', a: 'ARISE supports Windows PE executables (.exe, .dll, .sys), Linux ELF binaries (32-bit and 64-bit), macOS Mach-O binaries, and Android APK packages. The maximum file size is 256 MB per upload.' },
  { q: 'Is my uploaded binary stored permanently?', a: 'No. Uploaded files are stored in a temporary directory and automatically deleted after analysis completes (or if the analysis fails). Files are not retained beyond the analysis session.' },
  { q: 'How long does analysis take?', a: 'Typical analysis completes in 30–120 seconds depending on binary size, complexity, and available engines. You can watch the 7-stage pipeline progress in real time on the dashboard.' },
  { q: 'What is CAPA and why is it important?', a: 'CAPA is an open-source tool developed by Mandiant/FireEye that identifies behavioral capabilities in executables using a library of over 1,000 YAML rules. It answers questions like "can this binary spawn new processes?" or "does it use process injection?" — without executing the file.' },
  { q: 'How does the MITRE ATT&CK mapping work?', a: 'CAPA rules are annotated with MITRE ATT&CK technique IDs. When CAPA fires a rule, ARISE extracts the associated technique IDs and maps them to the ATT&CK framework. This provides standardized, vendor-neutral threat intelligence that integrates with your existing SIEM or threat intel platform.' },
  { q: 'What is the difference between Risk Score and CVSS?', a: "The Risk Score (0–100) is a proprietary ML-based metric calibrated against real malware families — it reflects how dangerous this specific sample is relative to other malware. CVSS (0–10) follows the NVD's Common Vulnerability Scoring System standard, measuring severity in terms of attack vector, complexity, and impact." },
  { q: 'Does ARISE execute the malware?', a: 'No. ARISE performs entirely static analysis — the binary is never executed. All behavioral signals are derived from static code analysis, import tables, strings, and CAPA rule matching. This makes analysis safe to run on production infrastructure.' },
  { q: 'Can I use ARISE on a private/internal network?', a: 'Yes. ARISE is self-hosted. All processing occurs locally on your infrastructure. There are no external API calls for the analysis pipeline itself. You can deploy it on air-gapped networks by pre-installing the required tools (Radare2, Ghidra, CAPA).' },
  { q: 'What is Ghidra and when is it used?', a: 'Ghidra is an open-source reverse engineering framework developed by the NSA. When available, ARISE uses it as a secondary decompilation engine alongside Radare2, enabling deeper analysis including high-level pseudocode generation and improved function boundary detection.' },
  { q: 'How do I interpret a SUSPICIOUS verdict?', a: 'A SUSPICIOUS verdict means the binary exhibits some behaviors associated with malware (e.g., network communication, registry writes) but the confidence threshold for MALICIOUS classification was not met. It warrants further investigation — check the MITRE techniques and capabilities for specific concerns.' },
  { q: 'Can ARISE detect packed or obfuscated binaries?', a: 'ARISE will analyze packed binaries but may have reduced capability extraction since the actual code is encrypted or compressed. The analysis will indicate reduced extraction confidence. For packed samples, we recommend dynamic analysis as a complementary step.' },
  { q: 'What backend infrastructure is required?', a: 'ARISE requires Python 3.9+, FastAPI, Celery, Redis, and optionally Radare2 and Ghidra installed on the system. See the SETUP.md for complete installation instructions and environment variable configuration.' },
];

function FAQItem({ question, answer, isOpen, onToggle, index, id }) {
  const headingId = `faq-heading-${id}`;
  const bodyId    = `faq-body-${id}`;

  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onToggle();
    }
  }, [onToggle]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ delay: Math.min(index * 0.04, 0.3) }}
      style={{ marginBottom: '0.6rem' }}
    >
      <div
        className="glass"
        style={{
          borderColor: isOpen ? 'rgba(0,240,255,0.25)' : 'rgba(0,240,255,0.1)',
          background:   isOpen ? 'rgba(0,240,255,0.035)' : 'rgba(6,18,36,0.8)',
          transition: 'all 0.22s',
          overflow: 'hidden',
        }}
      >
        {/* Accordion trigger — semantically a button */}
        <button
          id={headingId}
          aria-expanded={isOpen}
          aria-controls={bodyId}
          onClick={onToggle}
          onKeyDown={handleKeyDown}
          style={{
            width: '100%', background: 'none', border: 'none',
            cursor: 'pointer', padding: '1.1rem 1.4rem',
            display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', textAlign: 'left', gap: '1rem',
          }}
        >
          <span style={{
            fontFamily: 'Rajdhani', fontWeight: 600, fontSize: 15,
            color: isOpen ? '#00f0ff' : '#e0f4ff',
            letterSpacing: 0.3, lineHeight: 1.35,
            transition: 'color 0.2s', flex: 1,
          }}>
            {question}
          </span>
          <motion.span
            animate={{ rotate: isOpen ? 45 : 0 }}
            transition={{ duration: 0.2 }}
            aria-hidden="true"
            style={{
              width: 20, height: 20, flexShrink: 0,
              border: `1px solid ${isOpen ? '#00f0ff' : 'rgba(0,240,255,0.3)'}`,
              borderRadius: 4,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: isOpen ? '#00f0ff' : '#6b8fa8',
              fontSize: 14, fontFamily: 'monospace',
              transition: 'border-color 0.2s, color 0.2s',
            }}
          >
            +
          </motion.span>
        </button>

        {/* Answer panel */}
        <AnimatePresence initial={false}>
          {isOpen && (
            <motion.div
              id={bodyId}
              role="region"
              aria-labelledby={headingId}
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.28, ease: 'easeInOut' }}
              style={{ overflow: 'hidden' }}
            >
              <p style={{
                fontFamily: 'Inter', fontSize: 14, color: '#6b8fa8',
                lineHeight: 1.8, margin: 0,
                padding: '0 1.4rem 1.1rem',
                borderTop: '1px solid rgba(0,240,255,0.08)',
                paddingTop: '0.9rem',
              }}>
                {answer}
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

export default function FAQPage() {
  const [openIndex, setOpenIndex] = useState(0);

  return (
    <div className="page-wrapper" style={{ paddingTop: 64 }}>
      <SectionContainer as="section">
        <AnimatedHeading
          center
          subtitle="Everything you need to know about ARISE, its pipeline, and how to interpret results."
          level={1}
        >
          <span style={{ color: '#e0f4ff' }}>Frequently Asked </span>
          <span className="neon-text">Questions</span>
        </AnimatedHeading>

        <div style={{ maxWidth: 820, margin: '0 auto' }}>
          {FAQS.map((faq, i) => (
            <FAQItem
              key={i}
              id={i}
              index={i}
              question={faq.q}
              answer={faq.a}
              isOpen={openIndex === i}
              onToggle={() => setOpenIndex(openIndex === i ? -1 : i)}
            />
          ))}
        </div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          style={{ textAlign: 'center', marginTop: '3.5rem' }}
        >
          <GlassCard style={{ padding: 'clamp(1.75rem,4vw,2.5rem)', maxWidth: 540, margin: '0 auto' }}>
            <p style={{ fontFamily: 'Rajdhani', fontWeight: 700, fontSize: 20, color: '#e0f4ff', marginBottom: '0.6rem' }}>
              Still have questions?
            </p>
            <p style={{ fontFamily: 'Inter', fontSize: 14, color: '#6b8fa8', marginBottom: '1.5rem', lineHeight: 1.6 }}>
              Try the live analysis — upload any binary and see how ARISE works in practice.
            </p>
            <Link to="/analyze" className="btn-primary">▸ Try ARISE Now</Link>
          </GlassCard>
        </motion.div>
      </SectionContainer>
    </div>
  );
}
