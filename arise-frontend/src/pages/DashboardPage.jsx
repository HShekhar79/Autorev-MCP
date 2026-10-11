import { useState, useRef, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
} from "recharts";
import { useAnalysis } from "../hooks/useAnalysis";
import { downloadReport } from "../services/api";

const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const STAGE_ORDER  = ["extraction","behaviour","capability","mitre","risk","cvss","verdict"];
const STAGE_LABELS = {
  extraction:"Extraction", behaviour:"Behaviour", capability:"Capabilities",
  mitre:"MITRE", risk:"Risk Score", cvss:"CVSS", verdict:"Verdict",
};

const ACCEPTED_EXTENSIONS = [
  ".exe",".dll",".elf",".so",".apk",".msi",".sys",
  ".pdf",".docx",".doc",".xlsx",".pptx",".rtf",
  ".js",".vbs",".bat",".ps1",".py",".sh",".php",
  ".zip",".rar",".7z",".tar",".gz",
  ".txt",".csv",".json",".xml",".log",
];

const REPORT_SECTIONS = [
  { key:"cover",        label:"Cover Page",               desc:"Verdict badge and file info" },
  { key:"executive",    label:"Executive Summary",         desc:"Summary and recommended actions" },
  { key:"metadata",     label:"File Metadata and Hashes",  desc:"MD5, SHA-1, SHA-256, engine" },
  { key:"verdict",      label:"Verdict and Risk",          desc:"Verdict, confidence, CVSS, risk" },
  { key:"capabilities", label:"Capabilities",              desc:"Detected capability groups" },
  { key:"mitre",        label:"MITRE ATT&CK",              desc:"Technique table with descriptions" },
  { key:"ioc",          label:"IOC Indicators",            desc:"URLs, IPs, paths, commands" },
  { key:"strings",      label:"Strings",                   desc:"Top 100 suspicious strings" },
  { key:"imports",      label:"Imports",                   desc:"All detected imports" },
  { key:"functions",    label:"Functions",                 desc:"Top 50 functions" },
  { key:"risk",         label:"Risk Breakdown",            desc:"Detailed risk metrics" },
  { key:"json",         label:"Raw JSON Appendix",         desc:"Machine-readable JSON" },
];

function verdictColor(l) {
  if (l === "MALICIOUS")  return "#ff3c6e";
  if (l === "SUSPICIOUS") return "#ffb347";
  return "#00ff88";
}
function riskColor(s) { return s >= 70 ? "#ff3c6e" : s >= 40 ? "#ffb347" : "#00ff88"; }
function cvssColor(s) { return s >= 7  ? "#ff3c6e" : s >= 4  ? "#ffb347" : "#00ff88"; }
function fmtBytes(b) {
  if (!b) return "";
  if (b >= 1048576) return (b/1048576).toFixed(1) + " MB";
  if (b >= 1024)    return (b/1024).toFixed(0) + " KB";
  return b + " B";
}

/* ── Upload Zone ─────────────────────────────────────────────────────────── */
function UploadZone({ onAnalyze }) {
  const [dragging, setDragging] = useState(false);
  const [fileInfo, setFileInfo] = useState(null);
  const inputRef = useRef();

  const handleFile = useCallback((file) => {
    if (!file) return;
    setFileInfo({ name: file.name, size: file.size });
    setTimeout(() => onAnalyze(file, false), 500);
  }, [onAnalyze]);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  };

  return (
    <div style={{ maxWidth: 620, margin: "0 auto", textAlign: "center" }}>
      <h1 style={{
        fontFamily: "Orbitron,sans-serif", fontSize: "clamp(1.5rem,4vw,2rem)",
        fontWeight: 900, color: "#e0f4ff", letterSpacing: "0.05em", marginBottom: "0.4rem",
      }}>
        Binary{" "}
        <span style={{ color: "#00f0ff", textShadow: "0 0 24px #00f0ff80" }}>Analysis</span>
      </h1>
      <p style={{ color: "#6b8fa8", fontFamily: "Space Mono", fontSize: 10,
        letterSpacing: 1, marginBottom: "2.5rem" }}>
        EXE · DLL · ELF · APK · PDF · DOCX · PS1 · ZIP · and more — max 256 MB
      </p>

      {/* Drop zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload file — click or drag and drop"
        onClick={() => inputRef.current.click()}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inputRef.current.click(); }}}
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        style={{
          padding: "clamp(2rem,5vw,3rem) 2rem", cursor: "pointer", borderRadius: 8,
          border: "1px solid " + (dragging ? "rgba(0,240,255,0.7)" : "rgba(0,240,255,0.18)"),
          background: dragging ? "rgba(0, 30, 60, 0.99)" : "rgba(4, 12, 28, 0.85)",
          boxShadow: dragging ? "0 0 48px rgba(0,240,255,0.18)" : "none",
          transition: "all 0.2s", marginBottom: "1.5rem",
        }}
      >
        <div style={{ fontSize: 42, color: "#00f0ff80", marginBottom: "0.9rem" }}>
          {fileInfo ? "◈" : "⬡"}
        </div>
        {fileInfo ? (
          <div>
            <div style={{ fontFamily: "Space Mono", fontSize: 12, color: "#00f0ff", marginBottom: 4 }}>
              {fileInfo.name}
            </div>
            <div style={{ fontFamily: "Space Mono", fontSize: 10, color: "#6b8fa8" }}>
              {fmtBytes(fileInfo.size)} · Queuing analysis…
            </div>
          </div>
        ) : (
          <div>
            <div style={{ fontFamily: "Rajdhani", fontWeight: 600, fontSize: 17, color: "#e0f4ff", marginBottom: "0.3rem" }}>
              Drop Any File Here
            </div>
            <div style={{ fontFamily: "Space Mono", fontSize: 10, color: "#6b8fa8" }}>
              or click to browse
            </div>
          </div>
        )}
      </div>

      <input
        ref={inputRef} type="file" accept={ACCEPTED_EXTENSIONS.join(",")}
        aria-label="File input"
        style={{ display: "none" }}
        onChange={e => handleFile(e.target.files[0])}
      />

      <button
        onClick={() => onAnalyze(null, true)}
        style={{
          background: "none", border: "1px solid rgba(0,240,255,0.5)",
          color: "#6b8fa8", fontFamily: "Space Mono", fontSize: 10, letterSpacing: 1,
          padding: "8px 24px", cursor: "pointer", borderRadius: 4,
          transition: "border-color 0.2s, color 0.2s",
        }}
        onMouseEnter={e => { e.currentTarget.style.borderColor = "rgba(0,240,255,0.4)"; e.currentTarget.style.color = "#a0c4d8"; }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = "rgba(0,240,255,0.2)"; e.currentTarget.style.color = "#6b8fa8"; }}
      >
        Load Demo Analysis
      </button>
    </div>
  );
}

/* ── Progress View ───────────────────────────────────────────────────────── */
function ProgressView({ stage, pct }) {
  return (
    <div style={{ maxWidth: 480, margin: "0 auto", textAlign: "center" }}>
      <h2 style={{ fontFamily: "Orbitron,sans-serif", fontSize: "clamp(1.1rem,3vw,1.4rem)",
        color: "#e0f4ff", marginBottom: "0.5rem" }}>
        Analysing…
      </h2>
      <p style={{ fontFamily: "Space Mono", fontSize: 10, color: "#6b8fa8", marginBottom: "2rem" }}>
        ARISE pipeline running — do not close this tab
      </p>
      <div role="status" aria-live="polite" aria-label={`Analysis ${pct}% complete`}
        style={{ background: "rgba(4,12,28,0.97)", border: "1px solid rgba(0,240,255,0.18)",
          borderRadius: 8, padding: "1.75rem" }}>
        {/* Progress bar */}
        <div style={{ height: 3, background: "rgba(0,240,255,0.1)", borderRadius: 2,
          marginBottom: "1.5rem", overflow: "hidden" }}>
          <motion.div
            animate={{ width: pct + "%" }}
            transition={{ duration: 0.4 }}
            style={{ height: "100%", background: "linear-gradient(90deg,#00f0ff,#00c8ff)",
              borderRadius: 2, boxShadow: "0 0 8px #00f0ff" }}
          />
        </div>
        {STAGE_ORDER.map((s, i) => {
          const ci = STAGE_ORDER.indexOf(stage);
          const done = i < ci; const active = i === ci;
          return (
            <div key={s} style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "0.3rem 0.6rem", borderRadius: 4,
              background: active ? "rgba(0,240,255,0.06)" : "transparent",
            }}>
              <div style={{
                width: 15, height: 15, borderRadius: "50%", flexShrink: 0,
                border: "1px solid " + (done ? "#00ff88" : active ? "#00f0ff" : "rgba(0,240,255,0.2)"),
                background: done ? "#00ff8820" : active ? "rgba(0,240,255,0.15)" : "transparent",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 8, color: done ? "#00ff88" : active ? "#00f0ff" : "#6b8fa8",
              }}>
                {done ? "✓" : ""}
              </div>
              <span style={{ fontFamily: "Space Mono", fontSize: 10,
                color: done ? "#00ff88" : active ? "#00f0ff" : "#6b8fa840" }}>
                {STAGE_LABELS[s]}
              </span>
              {active && (
                <span style={{ fontFamily: "Space Mono", fontSize: 9,
                  color: "#00f0ff", marginLeft: "auto" }}>{pct}%</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Checkbox ────────────────────────────────────────────────────────────── */
function Checkbox({ checked, indeterminate, onChange }) {
  return (
    <div
      role="checkbox"
      aria-checked={indeterminate ? "mixed" : checked}
      tabIndex={0}
      onClick={e => { e.stopPropagation(); onChange(); }}
      onKeyDown={e => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); onChange(); }}}
      style={{
        width: 15, height: 15, borderRadius: 3, flexShrink: 0, cursor: "pointer",
        border: "1.5px solid " + (checked || indeterminate ? "#00f0ff" : "rgba(0,240,255,0.25)"),
        background: checked ? "rgba(0,240,255,0.2)" : indeterminate ? "rgba(0,240,255,0.1)" : "transparent",
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: 9, color: "#00f0ff", transition: "all 0.15s",
      }}
    >
      {checked ? "✓" : indeterminate ? "−" : ""}
    </div>
  );
}

/* ── Report Modal ────────────────────────────────────────────────────────── */
function ReportModal({ result, taskId, onClose }) {
  const [selected, setSelected]  = useState(new Set(REPORT_SECTIONS.map(s => s.key)));
  const [downloading, setDl]     = useState(false);
  const [error, setError]        = useState(null);
  const [preview, setPreview]    = useState(null);

  /* Close on Escape */
  useEffect(() => {
    const fn = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', fn);
    return () => document.removeEventListener('keydown', fn);
  }, [onClose]);

  useEffect(() => {
    if (!result) return;
    const caps  = result.capabilities || [];
    const mitre = result.mitre || [];
    const imp   = result.imports || [];
    const str   = result.strings || [];
    const fn    = result.functions || [];
    const label = result.verdict?.label || result.verdict?.verdict || "UNKNOWN";
    const iocPat = /https?:\/\/|HKEY_|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|cmd\.exe|powershell/i;
    const iocCount = str.slice(0, 500).filter(s => iocPat.test(String(s))).length;
    setPreview({
      cover:        { count: 1,           note: "Verdict: " + label },
      executive:    { count: 1,           note: "Summary + actions" },
      metadata:     { count: 12,          note: "MD5, SHA-1, SHA-256" },
      verdict:      { count: 8,           note: label },
      capabilities: { count: caps.length, note: caps.length + " group(s)" },
      mitre:        { count: mitre.length,note: mitre.length + " technique(s)" },
      ioc:          { count: iocCount,    note: "~" + iocCount + " indicator(s)" },
      strings:      { count: str.length,  note: str.length + " strings" },
      imports:      { count: imp.length,  note: imp.length + " imports" },
      functions:    { count: fn.length,   note: fn.length + " functions" },
      risk:         { count: 9,           note: "Score " + ((result.risk_score||0).toFixed(0)) + "/100" },
      json:         { count: 1,           note: "Raw JSON appendix" },
    });
  }, [result]);

  const toggle    = key => setSelected(prev => {
    const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n;
  });
  const toggleAll = () => setSelected(
    selected.size === REPORT_SECTIONS.length ? new Set() : new Set(REPORT_SECTIONS.map(s => s.key))
  );

  const download = async () => {
    if (!selected.size) { setError("Select at least one section."); return; }
    setDl(true); setError(null);
    try {
      await downloadReport(taskId, [...selected]);
      setTimeout(onClose, 600);
    } catch (e) { setError("Download failed: " + e.message); }
    setDl(false);
  };

  const allChecked  = selected.size === REPORT_SECTIONS.length;
  const someChecked = selected.size > 0 && !allChecked;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Download PDF Report"
      style={{
        position: "fixed", inset: 0, background: "rgba(6,14,30,0.88)",
        backdropFilter: "blur(8px)", zIndex: 1000, display: "flex",
        alignItems: "center", justifyContent: "center",
        padding: "clamp(0.75rem,2vw,1.5rem)",
      }}
    >
      <motion.div
        initial={{ scale: 0.93, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        style={{
          width: "100%", maxWidth: 560, maxHeight: "88vh", display: "flex",
          flexDirection: "column", borderRadius: 8,
          border: "1px solid rgba(0,240,255,0.18)", background: "rgba(8,20,40,0.98)",
          overflow: "hidden",
        }}
      >
        <div style={{ padding: "1rem 1.3rem", borderBottom: "1px solid rgba(0,240,255,0.12)",
          display: "flex", alignItems: "center", gap: 10 }}>
          <span aria-hidden="true" style={{ fontSize: 14, color: "#00f0ff" }}>⬇</span>
          <div>
            <div style={{ fontWeight: 700, fontSize: 13, color: "#e0f4ff" }}>Download PDF Report</div>
            <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa8" }}>
              Tick sections to include — all ticked = Full Report
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            style={{ marginLeft: "auto", background: "none", border: "none",
              color: "#6b8fa8", cursor: "pointer", fontSize: 16, lineHeight: 1, padding: "4px" }}
          >
            ✕
          </button>
        </div>

        <div style={{ padding: "0.6rem 1.3rem", borderBottom: "1px solid rgba(0,240,255,0.08)",
          display: "flex", alignItems: "center", gap: 10 }}>
          <Checkbox checked={allChecked} indeterminate={someChecked} onChange={toggleAll} />
          <span style={{ fontFamily: "Space Mono", fontSize: 10, color: "#a0c4d8", cursor: "pointer" }}
            onClick={toggleAll}>
            {allChecked ? "Deselect All" : "Select All"}
          </span>
          <span style={{ marginLeft: "auto", fontFamily: "Space Mono", fontSize: 9,
            color: "#6b8fa8" }}>{selected.size}/{REPORT_SECTIONS.length} selected</span>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "0.6rem 1.3rem" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.35rem" }}
            className="arise-report-sections">
            {REPORT_SECTIONS.map(sec => {
              const prev = preview && preview[sec.key];
              const chk  = selected.has(sec.key);
              return (
                <div key={sec.key} onClick={() => toggle(sec.key)}
                  style={{
                    display: "flex", alignItems: "flex-start", gap: 8,
                    cursor: "pointer", padding: "0.5rem 0.65rem", borderRadius: 5,
                    background: chk ? "rgba(0,240,255,0.06)" : "rgba(255,255,255,0.02)",
                    border: "1px solid " + (chk ? "rgba(0,240,255,0.25)" : "rgba(255,255,255,0.06)"),
                    transition: "all 0.15s",
                  }}
                >
                  <Checkbox checked={chk} onChange={() => toggle(sec.key)} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 11,
                      color: chk ? "#e0f4ff" : "#6b8fa8", transition: "color 0.15s",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }}>
                      {sec.label}
                      {prev && prev.count > 0 && (
                        <span style={{ fontFamily: "Space Mono", fontSize: 8,
                          color: chk ? "#00f0ff50" : "#6b8fa830", marginLeft: 5 }}>
                          ({prev.count})
                        </span>
                      )}
                    </div>
                    <div style={{ fontFamily: "Space Mono", fontSize: 8,
                      color: "#6b8fa8", marginTop: 2, lineHeight: 1.4 }}>
                      {(prev && prev.note) || sec.desc}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ padding: "0.85rem 1.3rem", borderTop: "1px solid rgba(0,240,255,0.12)" }}>
          {error && (
            <div style={{ fontFamily: "Space Mono", fontSize: 10, color: "#ff3c6e",
              marginBottom: "0.6rem", padding: "5px 9px",
              background: "rgba(255,60,110,0.08)", borderRadius: 4,
              border: "1px solid rgba(255,60,110,0.2)" }}>
              {error}
            </div>
          )}
          <div style={{ display: "flex", gap: "0.55rem", alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa8", flex: 1 }}>
              {selected.size === 0 ? "No sections selected"
                : selected.size === REPORT_SECTIONS.length ? "Full report — all sections"
                : "Custom — " + selected.size + " of " + REPORT_SECTIONS.length + " sections"}
            </div>
            <button onClick={onClose}
              style={{ background: "none", border: "1px solid rgba(0,240,255,0.2)",
                color: "#6b8fa8", fontFamily: "Space Mono", fontSize: 10,
                padding: "7px 13px", cursor: "pointer", borderRadius: 4 }}>
              Cancel
            </button>
            <button onClick={download} disabled={downloading || !selected.size}
              style={{
                background: selected.size ? "rgba(0,240,255,0.12)" : "rgba(0,240,255,0.03)",
                border: "1px solid rgba(0,240,255,0.4)",
                color: selected.size ? "#00f0ff" : "#6b8fa8",
                fontFamily: "Space Mono", fontSize: 10, padding: "7px 17px",
                cursor: (downloading || !selected.size) ? "not-allowed" : "pointer",
                borderRadius: 4, opacity: downloading ? 0.7 : 1,
              }}>
              {downloading ? "Generating…" : "Download PDF"}
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

/* ── Verdict Badge ───────────────────────────────────────────────────────── */
function VerdictBadge({ verdict }) {
  const label   = verdict?.verdict || verdict?.label || "UNKNOWN";
  const color   = verdictColor(label);
  const conf    = verdict?.confidence ?? verdict?.confidence_pct ?? 0;
  const confPct = conf > 1 ? conf : conf * 100;
  const confLbl = verdict?.confidence_label || (confPct >= 75 ? "High" : confPct >= 45 ? "Medium" : "Low");
  return (
    <div style={{ padding: "1.5rem", textAlign: "center",
      border: "1px solid " + color + "60", borderRadius: 8,
      background: "rgba(4,12,28,0.97)", boxShadow: "0 0 26px " + color + "25" }}>
      <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa8",
        letterSpacing: 2, textTransform: "uppercase", marginBottom: "0.5rem" }}>
        ARISE Verdict
      </div>
      <div style={{
        fontFamily: "Orbitron,sans-serif", fontSize: "clamp(1.4rem,3vw,2rem)",
        fontWeight: 900, color, textShadow: "0 0 20px " + color + "80", letterSpacing: 3,
      }}>
        {label}
      </div>
      <div style={{ fontFamily: "Space Mono", fontSize: 10, color: "#6b8fa8", marginTop: "0.4rem" }}>
        Confidence: <span style={{ color }}>{confPct.toFixed(0)}%</span>
        <span style={{ marginLeft: 7, border: "1px solid " + color + "40", borderRadius: 3,
          padding: "1px 6px", fontSize: 9 }}>{confLbl}</span>
      </div>
      {verdict?.category && (
        <div style={{ marginTop: "0.5rem", display: "inline-block",
          border: "1px solid " + color + "40", borderRadius: 4, padding: "2px 12px",
          fontFamily: "Space Mono", fontSize: 9, color, letterSpacing: 1 }}>
          {verdict.category}
        </div>
      )}
      {verdict?.summary && (
        <p style={{ marginTop: "0.75rem", fontSize: 12, color: "#a0c4d8",
          lineHeight: 1.6, textAlign: "left" }}>
          {verdict.summary}
        </p>
      )}
      {verdict?.recommended_actions?.length > 0 && (
        <div style={{ marginTop: "0.75rem", textAlign: "left" }}>
          <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa8",
            letterSpacing: 1, textTransform: "uppercase", marginBottom: 5 }}>
            Recommended Actions
          </div>
          {verdict.recommended_actions.map((a, i) => (
            <div key={i} style={{ fontFamily: "Space Mono", fontSize: 9,
              color: "#a0c4d8", padding: "2px 0", display: "flex", gap: 7 }}>
              <span style={{ color }}>›</span>{a}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Score Cards ─────────────────────────────────────────────────────────── */
function ScoreCards({ riskScore, cvss }) {
  const cvssVal = typeof cvss === "number" ? cvss : (cvss && cvss.cvss_score) ? cvss.cvss_score : 0;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
      {[
        { label: "Risk Score", value: (riskScore || 0).toFixed(1), suffix: "/100",  color: riskColor(riskScore || 0) },
        { label: "CVSS Score", value: cvssVal.toFixed(1),           suffix: "/10.0", color: cvssColor(cvssVal) },
      ].map(c => (
        <div key={c.label} style={{ padding: "1.25rem", textAlign: "center",
          border: "1px solid " + c.color + "50", borderRadius: 8, background: "rgba(4,12,28,0.97)" }}>
          <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa8",
            letterSpacing: 2, textTransform: "uppercase", marginBottom: "0.4rem" }}>
            {c.label}
          </div>
          <div style={{ fontFamily: "Orbitron,sans-serif", fontSize: "clamp(1.6rem,4vw,2.25rem)",
            fontWeight: 900, color: c.color, textShadow: "0 0 16px " + c.color + "60", lineHeight: 1 }}>
            {c.value}
          </div>
          <div style={{ fontFamily: "Space Mono", fontSize: 10, color: "#6b8fa840" }}>
            {c.suffix}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ── Hashes Panel ────────────────────────────────────────────────────────── */
function HashesPanel({ hashes, fileType }) {
  const [copied, setCopied] = useState(null);
  if (!hashes) return null;
  const copy = (val, key) => {
    navigator.clipboard.writeText(val).then(() => {
      setCopied(key); setTimeout(() => setCopied(null), 1200);
    });
  };
  return (
    <div style={{ padding: "1rem 1.2rem", border: "1px solid rgba(0,240,255,0.18)",
      borderRadius: 8, background: "rgba(4,12,28,0.97)" }}>
      <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#00f0ff",
        letterSpacing: 2, textTransform: "uppercase", marginBottom: "0.55rem",
        display: "flex", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        File Info and Hashes
        {fileType && (
          <span style={{ border: "1px solid rgba(0,240,255,0.2)",
            borderRadius: 3, padding: "1px 7px", fontSize: 8, letterSpacing: 0.5 }}>
            {fileType}
          </span>
        )}
      </div>
      {[["MD5", hashes.md5], ["SHA-1", hashes.sha1], ["SHA-256", hashes.sha256]].map(([lbl, val]) => (
        <div key={lbl} style={{ display: "flex", alignItems: "flex-start", gap: 7, marginBottom: "0.35rem" }}>
          <span style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa8", width: 50, flexShrink: 0 }}>
            {lbl}
          </span>
          <span style={{ fontFamily: "Space Mono", fontSize: 9, color: "#a0c4d8",
            flex: 1, wordBreak: "break-all", lineHeight: 1.5 }}>
            {val || "N/A"}
          </span>
          {val && val !== "N/A" && (
            <button
              onClick={() => copy(val, lbl)}
              aria-label={`Copy ${lbl} hash`}
              style={{ background: "none", border: "none", cursor: "pointer",
                color: copied === lbl ? "#00ff88" : "#6b8fa840",
                fontSize: 11, padding: "1px 3px", transition: "color 0.2s", flexShrink: 0 }}>
              {copied === lbl ? "✓" : "⧉"}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

/* ── Data Table ──────────────────────────────────────────────────────────── */
function DataTable({ title, icon, items, copyable }) {
  const [expanded, setExpanded] = useState(false);
  const [search, setSearch]     = useState("");
  const [copied, setCopied]     = useState(null);

  const filtered = search
    ? items.filter(item =>
        String(typeof item === "object" ? (item.name || JSON.stringify(item)) : item)
          .toLowerCase().includes(search.toLowerCase()))
    : items;
  const display = expanded ? filtered : filtered.slice(0, 6);

  const copy = (item, i) => {
    const text = typeof item === "object" ? JSON.stringify(item) : String(item);
    navigator.clipboard.writeText(text).then(() => {
      setCopied(i); setTimeout(() => setCopied(null), 1200);
    });
  };

  return (
    <div style={{ padding: "1rem 1.2rem", border: "1px solid rgba(0,240,255,0.18)",
      borderRadius: 8, background: "rgba(4,12,28,0.97)", minWidth: 0 }}>
      <div style={{ display: "flex", justifyContent: "space-between",
        alignItems: "center", marginBottom: "0.4rem" }}>
        <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#00f0ff",
          letterSpacing: 2, textTransform: "uppercase" }}>
          <span aria-hidden="true">{icon}</span> {title}
          <span style={{ color: "#6b8fa8", marginLeft: 5 }}>({items.length})</span>
        </div>
        {items.length > 6 && (
          <button
            onClick={() => setExpanded(x => !x)}
            aria-expanded={expanded}
            aria-label={expanded ? "Show fewer items" : "Show all items"}
            style={{ background: "none", border: "none", cursor: "pointer",
              fontFamily: "Space Mono", fontSize: 8, color: "#00f0ff", letterSpacing: 1 }}>
            {expanded ? "LESS" : "MORE"}
          </button>
        )}
      </div>
      {items.length > 10 && (
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search…"
          aria-label={`Search ${title}`}
          style={{ width: "100%", background: "rgba(0,240,255,0.05)",
            border: "1px solid rgba(0,240,255,0.15)", borderRadius: 3,
            padding: "3px 7px", color: "#e0f4ff", fontFamily: "Space Mono",
            fontSize: 9, outline: "none", marginBottom: "0.35rem", boxSizing: "border-box" }}
        />
      )}
      <div style={{ maxHeight: expanded ? 360 : 180, overflowY: "auto" }}>
        {display.map((item, i) => {
          const text = typeof item === "object" ? (item.name || JSON.stringify(item)) : item;
          return (
            <div key={i} style={{ fontFamily: "Space Mono", fontSize: 9, color: "#a0c4d8",
              padding: "2px 6px", borderRadius: 2, marginBottom: 2,
              background: i % 2 === 0 ? "rgba(0,240,255,0.03)" : "transparent",
              display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ color: "#6b8fa8", flexShrink: 0, fontSize: 7 }}>
                {String(i + 1).padStart(2, "0")}
              </span>
              <span style={{ flex: 1, wordBreak: "break-all", minWidth: 0 }}>
                {String(text).slice(0, 160)}
              </span>
              {copyable && (
                <button
                  onClick={() => copy(item, i)}
                  aria-label={`Copy item ${i + 1}`}
                  style={{ background: "none", border: "none", cursor: "pointer",
                    color: copied === i ? "#00ff88" : "#6b8fa830",
                    fontSize: 9, flexShrink: 0, padding: "1px 2px", transition: "color 0.2s" }}>
                  {copied === i ? "✓" : "⧉"}
                </button>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div style={{ fontFamily: "Space Mono", fontSize: 8, color: "#6b8fa8",
            padding: "6px", textAlign: "center" }}>No results</div>
        )}
      </div>
    </div>
  );
}

/* ── MITRE Panel ─────────────────────────────────────────────────────────── */
function MitrePanel({ techniques }) {
  const [copied, setCopied] = useState(null);
  const copy = (t, i) => {
    navigator.clipboard.writeText(t).then(() => { setCopied(i); setTimeout(() => setCopied(null), 1200); });
  };
  const data = techniques.map((t, i) => ({ name: t, value: Math.max(30, 85 - i * 5) }));
  return (
    <div style={{ padding: "1rem 1.2rem", border: "1px solid rgba(0,240,255,0.18)",
      borderRadius: 8, background: "rgba(4,12,28,0.97)", minWidth: 0 }}>
      <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#00f0ff",
        letterSpacing: 2, textTransform: "uppercase", marginBottom: "0.55rem" }}>
        MITRE ATT&amp;CK ({techniques.length})
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.3rem", marginBottom: "0.7rem" }}>
        {techniques.map((t, i) => (
          <span key={t} onClick={() => copy(t, i)} title="Click to copy"
            style={{ fontFamily: "Space Mono", fontSize: 9,
              color: copied === i ? "#00ff88" : "#00f0ff",
              border: "1px solid " + (copied === i ? "rgba(0,255,136,0.4)" : "rgba(0,240,255,0.3)"),
              borderRadius: 3, padding: "2px 8px",
              background: copied === i ? "rgba(0,255,136,0.1)" : "rgba(0,240,255,0.05)",
              cursor: "pointer", transition: "all 0.15s" }}>
            {copied === i ? "✓ " + t : t}
          </span>
        ))}
      </div>
      {techniques.length > 0 && (
        <ResponsiveContainer width="100%" height={125}>
          <BarChart data={data} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
            <XAxis dataKey="name" tick={{ fill: "#6b8fa8", fontSize: 8, fontFamily: "Space Mono" }} />
            <YAxis tick={{ fill: "#6b8fa8", fontSize: 8 }} />
            <Tooltip contentStyle={{ background: "#060e1e",
              border: "1px solid rgba(0,240,255,0.2)", fontFamily: "Space Mono", fontSize: 9 }} />
            <Bar dataKey="value" radius={[2, 2, 0, 0]}>
              {data.map((_, i) => (
                <Cell key={i} fill={"hsl(" + (195 + i * 15) + ",90%," + (45 + i * 2) + "%)"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

/* ── Capability Radar ────────────────────────────────────────────────────── */
function CapabilityRadar({ capabilities }) {
  if (!capabilities || !capabilities.length) return (
    <div style={{ padding: "1rem", border: "1px solid rgba(0,240,255,0.18)",
      borderRadius: 8, display: "flex", alignItems: "center",
      justifyContent: "center", minHeight: 160, background: "rgba(4,12,28,0.97)" }}>
      <span style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa840" }}>
        No capabilities detected
      </span>
    </div>
  );
  const data = capabilities.map(c => ({
    cap: c.replace(/_/g, " ").toUpperCase().slice(0, 15),
    score: Math.min(95, 55 + capabilities.length * 4),
  }));
  return (
    <div style={{ padding: "1rem 1.2rem", border: "1px solid rgba(0,240,255,0.18)",
      borderRadius: 8, background: "rgba(4,12,28,0.97)", minWidth: 0 }}>
      <div style={{ fontFamily: "Space Mono", fontSize: 9, color: "#00f0ff",
        letterSpacing: 2, textTransform: "uppercase", marginBottom: "0.5rem" }}>
        Capabilities ({capabilities.length})
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.3rem", marginBottom: "0.5rem" }}>
        {capabilities.map(c => (
          <span key={c} style={{ fontFamily: "Space Mono", fontSize: 8, color: "#a0c4d8",
            border: "1px solid rgba(0,240,255,0.15)", borderRadius: 3,
            padding: "2px 7px", background: "rgba(0,240,255,0.03)",
            textTransform: "uppercase", letterSpacing: 0.5 }}>
            {c.replace(/_/g, " ")}
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={180}>
        <RadarChart data={data}>
          <PolarGrid stroke="rgba(0,240,255,0.15)" />
          <PolarAngleAxis dataKey="cap"
            tick={{ fill: "#6b8fa8", fontSize: 7, fontFamily: "Space Mono" }} />
          <Radar name="Score" dataKey="score" stroke="#00f0ff"
            fill="#00f0ff" fillOpacity={0.18} strokeWidth={2} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ── AI Chat ─────────────────────────────────────────────────────────────── */
function Chatbot({ analysisResult }) {
  const [messages, setMessages] = useState([{
    role: "assistant",
    text: "Analysis complete. Ask me about threat behavior, MITRE techniques, risk level, or recommended actions.",
  }]);
  const [input, setInput]  = useState("");
  const [loading, setLoad] = useState(false);
  const bottomRef = useRef();

  const QUICK = [
    "What is this malware doing?", "Is this dangerous?",
    "Explain MITRE techniques",    "What capabilities were found?",
  ];

  const send = async (text) => {
    const msg = (text || input).trim();
    if (!msg || loading) return;
    setInput("");
    setMessages(prev => [...prev, { role: "user", text: msg }]);
    setLoad(true);
    try {
      const lc = msg.toLowerCase();
      const isMitre = ["mitre","t10","t1","technique","tactic","attack"].some(k => lc.includes(k));
      const endpoint = isMitre ? BASE_URL + "/chat-mitre" : BASE_URL + "/chat-summary";
      const body = isMitre
        ? { techniques: (analysisResult && analysisResult.mitre) || [], question: msg }
        : { analysis: Object.assign({}, analysisResult, {
              imports:   ((analysisResult && analysisResult.imports)   || []).slice(0, 12),
              strings:   ((analysisResult && analysisResult.strings)   || []).slice(0, 8),
              functions: ((analysisResult && analysisResult.functions) || []).slice(0, 8),
            }), question: msg };
      const res  = await fetch(endpoint, { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json();
      setMessages(prev => [...prev, {
        role: "assistant", text: data.response || "No response.", source: data.source,
      }]);
    } catch (e) {
      setMessages(prev => [...prev, {
        role: "assistant", text: "Backend unreachable: " + e.message, isError: true,
      }]);
    }
    setLoad(false);
    setTimeout(() => bottomRef.current && bottomRef.current.scrollIntoView({ behavior: "smooth" }), 80);
  };

  return (
    <section
      aria-label="ARISE Intelligence Chat"
      style={{ display: "flex", flexDirection: "column", height: 400,
        border: "1px solid rgba(0,240,255,0.18)", borderRadius: 8, overflow: "hidden",
        background: "rgba(4,12,28,0.97)" }}
    >
      <div style={{ padding: "0.65rem 1rem", borderBottom: "1px solid rgba(0,240,255,0.1)",
        display: "flex", alignItems: "center", gap: 8 }}>
        <div aria-hidden="true" style={{ width: 7, height: 7, borderRadius: "50%",
          background: "#00f0ff", boxShadow: "0 0 8px #00f0ff", flexShrink: 0 }} />
        <h2 style={{ fontFamily: "Space Mono", fontSize: 9, color: "#00f0ff",
          letterSpacing: 2, textTransform: "uppercase", margin: 0 }}>
          ARISE Intelligence Chat
        </h2>
        <span style={{ marginLeft: "auto", fontFamily: "Space Mono", fontSize: 7,
          color: "#6b8fa8", border: "1px solid rgba(0,240,255,0.12)",
          borderRadius: 3, padding: "1px 6px" }}>MCP BACKEND</span>
      </div>

      <div role="log" aria-live="polite" aria-label="Chat messages"
        style={{ flex: 1, overflowY: "auto", padding: "0.65rem",
          display: "flex", flexDirection: "column", gap: "0.4rem" }}>
        {messages.map((m, i) => (
          <div key={i} style={{ alignSelf: m.role === "user" ? "flex-end" : "flex-start", maxWidth: "88%" }}>
            <div style={{
              fontFamily: m.role === "assistant" ? "Space Mono" : "Inter",
              fontSize: m.role === "assistant" ? 10 : 12, lineHeight: 1.6,
              padding: "0.5rem 0.75rem", borderRadius: 7,
              background: m.isError ? "rgba(255,60,110,0.08)"
                : m.role === "user" ? "rgba(0,240,255,0.1)" : "rgba(255,255,255,0.04)",
              border: "1px solid " + (m.isError ? "rgba(255,60,110,0.25)"
                : m.role === "user" ? "rgba(0,240,255,0.3)" : "rgba(255,255,255,0.08)"),
              color: m.isError ? "#ff6b6b" : m.role === "user" ? "#00f0ff" : "#a0c4d8",
              whiteSpace: "pre-wrap", wordBreak: "break-word",
            }}>
              {m.text}
            </div>
          </div>
        ))}
        {loading && (
          <div style={{ display: "flex", gap: 4, padding: "0.4rem 0.75rem",
            background: "rgba(255,255,255,0.03)", borderRadius: 7,
            border: "1px solid rgba(255,255,255,0.06)", width: "fit-content" }}>
            <span style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa8" }}>Querying…</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div style={{ padding: "0.3rem 0.65rem", display: "flex", gap: "0.3rem",
        flexWrap: "wrap", borderTop: "1px solid rgba(0,240,255,0.08)" }}>
        {QUICK.map(q => (
          <button key={q} onClick={() => send(q)} disabled={loading}
            style={{ background: "none", border: "1px solid rgba(0,240,255,0.15)",
              color: "#6b8fa8", fontFamily: "Space Mono", fontSize: 8, letterSpacing: 0.5,
              padding: "2px 7px", cursor: loading ? "not-allowed" : "pointer",
              borderRadius: 3, opacity: loading ? 0.4 : 1, transition: "color 0.2s, border-color 0.2s" }}
            onMouseEnter={e => { if (!loading) { e.currentTarget.style.color="#a0c4d8"; e.currentTarget.style.borderColor="rgba(0,240,255,0.3)"; }}}
            onMouseLeave={e => { e.currentTarget.style.color="#6b8fa8"; e.currentTarget.style.borderColor="rgba(0,240,255,0.15)"; }}
          >
            {q}
          </button>
        ))}
      </div>

      <div style={{ padding: "0.5rem 0.65rem", display: "flex", gap: "0.4rem",
        borderTop: "1px solid rgba(0,240,255,0.1)" }}>
        <label htmlFor="chat-input" className="sr-only">Chat message</label>
        <input
          id="chat-input"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !loading && send()}
          placeholder="Ask about this binary…"
          disabled={loading}
          style={{ flex: 1, background: "rgba(0,240,255,0.05)",
            border: "1px solid rgba(0,240,255,0.2)", borderRadius: 4,
            padding: "6px 9px", color: "#e0f4ff", fontFamily: "Space Mono",
            fontSize: 10, outline: "none" }}
        />
        <button
          onClick={() => send()}
          disabled={loading || !input.trim()}
          aria-label="Send message"
          style={{ background: "rgba(0,240,255,0.1)", border: "1px solid rgba(0,240,255,0.3)",
            color: "#00f0ff", fontFamily: "Space Mono", fontSize: 11,
            padding: "6px 11px", cursor: (loading || !input.trim()) ? "not-allowed" : "pointer",
            borderRadius: 4, opacity: (loading || !input.trim()) ? 0.4 : 1 }}>
          →
        </button>
      </div>
    </section>
  );
}

/* ── Results ─────────────────────────────────────────────────────────────── */
function Results({ result, taskId, onReset }) {
  const [showReport, setShowReport] = useState(false);

  const meta       = result.analysis_meta || {};
  const verdict    = result.verdict || {};
  const label      = verdict.verdict || verdict.label || "UNKNOWN";
  const vc         = verdictColor(label);
  const mitre      = result.mitre || [];
  const caps       = result.capabilities || [];
  const imports    = result.imports || [];
  const strings    = result.strings || [];
  const functions  = result.functions || [];
  const calls      = result.calls || [];
  const behaviours = result.behaviours || [];
  const hashes     = result.hashes || {};
  const fileType   = result.file_type || "";

  const chips = [
    meta.filename && ("FILE: " + meta.filename),
    "Engine: " + ((meta.extraction_engine || "RADARE2").toUpperCase()),
    "Ghidra: " + (meta.ghidra_available ? "✓" : "✗"),
    "CAPA: " + (meta.capa_enabled ? "✓" : "✗"),
    meta.total_elapsed && (parseFloat(meta.total_elapsed).toFixed(1) + "s"),
  ].filter(Boolean);

  return (
    <div>
      {/* Header row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start",
        marginBottom: "1.25rem", flexWrap: "wrap", gap: "0.75rem" }}>
        <div>
          <h1 style={{ fontFamily: "Orbitron,sans-serif", fontSize: "clamp(1.1rem,2.5vw,1.4rem)",
            fontWeight: 900, color: "#e0f4ff", letterSpacing: "0.05em", marginBottom: "0.25rem" }}>
            Analysis Results
          </h1>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem" }}>
            {chips.map((c, i) => (
              <span key={i} style={{ fontFamily: "Space Mono", fontSize: 9, color: "#6b8fa8" }}>
                {c}{i < chips.length - 1 ? " ·" : ""}
              </span>
            ))}
          </div>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button onClick={() => setShowReport(true)}
            style={{ background: "linear-gradient(135deg," + vc + "20," + vc + "10)",
              border: "1px solid " + vc + "50", color: vc,
              fontFamily: "Space Mono", fontSize: 10, letterSpacing: 1,
              padding: "8px 16px", cursor: "pointer", borderRadius: 5,
              display: "flex", alignItems: "center", gap: 6 }}>
            ⬇ Download Report
          </button>
          <button onClick={onReset}
            style={{ background: "none", border: "1px solid rgba(0,240,255,0.2)",
              color: "#6b8fa8", fontFamily: "Space Mono", fontSize: 10,
              padding: "8px 13px", cursor: "pointer", borderRadius: 5 }}>
            ← New Analysis
          </button>
        </div>
      </div>

      {/* Row 1: verdict + scores + radar */}
      <div style={{ display: "grid", gap: "0.8rem", marginBottom: "0.8rem" }}
        className="arise-results-r1">
        <VerdictBadge verdict={verdict} />
        <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem" }}>
          <ScoreCards riskScore={result.risk_score} cvss={result.cvss} />
          <CapabilityRadar capabilities={caps} />
        </div>
      </div>

      {/* Row 2: hashes + MITRE */}
      <div style={{ display: "grid", gap: "0.8rem", marginBottom: "0.8rem" }}
        className="arise-results-r2">
        <HashesPanel hashes={hashes} fileType={fileType} />
        <MitrePanel techniques={mitre} />
      </div>

      {/* Row 3: imports + strings + calls */}
      <div style={{ display: "grid", gap: "0.8rem", marginBottom: "0.8rem" }}
        className="arise-results-r3">
        <DataTable title="Imports"   icon="◈" items={imports}   copyable={true} />
        <DataTable title="Strings"   icon="◎" items={strings}   copyable={true} />
        <DataTable title="API Calls" icon="◆" items={calls}     copyable={true} />
      </div>

      {/* Row 4: functions + behaviours */}
      <div style={{ display: "grid", gap: "0.8rem", marginBottom: "0.8rem" }}
        className="arise-results-r4">
        <DataTable title="Functions" icon="⬡"
          items={functions.map(f => typeof f === "object" ? (f.name || JSON.stringify(f)) : f)}
          copyable={true} />
        {behaviours.length > 0 && (
          <DataTable title="Behaviours" icon="◉" items={behaviours} copyable={false} />
        )}
      </div>

      <Chatbot analysisResult={result} />

      {showReport && (
        <ReportModal result={result} taskId={taskId} onClose={() => setShowReport(false)} />
      )}

      {/* Responsive grid rules for results layout */}
      <style>{`
        .arise-results-r1 { grid-template-columns: minmax(0,1fr) minmax(0,1.8fr); }
        .arise-results-r2 { grid-template-columns: repeat(2, minmax(0,1fr)); }
        .arise-results-r3 { grid-template-columns: repeat(3, minmax(0,1fr)); }
        .arise-results-r4 { grid-template-columns: repeat(2, minmax(0,1fr)); }
        @media (max-width: 1024px) {
          .arise-results-r3 { grid-template-columns: repeat(2, minmax(0,1fr)); }
        }
        @media (max-width: 768px) {
          .arise-results-r1,
          .arise-results-r2,
          .arise-results-r3,
          .arise-results-r4 { grid-template-columns: 1fr; }
          .arise-report-sections { grid-template-columns: 1fr !important; }
        }
        .sr-only {
          position: absolute; width: 1px; height: 1px;
          padding: 0; margin: -1px; overflow: hidden;
          clip: rect(0,0,0,0); white-space: nowrap; border: 0;
        }
      `}</style>
    </div>
  );
}

/* ── Dashboard Page ──────────────────────────────────────────────────────── */
export default function DashboardPage() {
  const { status, result, error, stage, pct, taskId, analyze, reset } = useAnalysis();

  return (
    <div style={{
      paddingTop: 64,
      padding: "calc(64px + 1.5rem) clamp(1rem,4vw,2rem) 4rem",
      minHeight: "100vh",
      position: "relative", zIndex: 1,
    }}>
      <AnimatePresence mode="wait">
        {status === "idle" && (
          <motion.div key="upload"
            initial={{ opacity:0, y:24 }} animate={{ opacity:1, y:0 }} exit={{ opacity:0, y:-16 }}>
            <UploadZone onAnalyze={analyze} />
          </motion.div>
        )}
        {(status === "uploading" || status === "processing") && (
          <motion.div key="progress"
            initial={{ opacity:0 }} animate={{ opacity:1 }} exit={{ opacity:0 }}
            style={{ paddingTop: "3rem" }}>
            <ProgressView stage={stage} pct={pct} />
          </motion.div>
        )}
        {status === "error" && (
          <motion.div key="error"
            initial={{ opacity:0 }} animate={{ opacity:1 }}
            style={{ textAlign: "center", paddingTop: "3rem" }}>
            <div style={{ maxWidth: 420, margin: "0 auto", padding: "2rem",
              border: "1px solid rgba(255,60,110,0.4)", borderRadius: 8,
              background: "rgba(4,12,28,0.97)" }}>
              <div style={{ color: "#ff3c6e", fontFamily: "Orbitron", fontSize: 17,
                fontWeight: 700, marginBottom: "0.5rem" }}>
                Analysis Failed
              </div>
              <div style={{ color: "#6b8fa8", fontFamily: "Space Mono", fontSize: 10,
                marginBottom: "1.4rem" }}>{error}</div>
              <button onClick={reset} className="btn-primary" style={{ fontSize: 10 }}>
                Try Again
              </button>
            </div>
          </motion.div>
        )}
        {status === "done" && result && (
          <motion.div key="results"
            initial={{ opacity:0 }} animate={{ opacity:1 }}
            style={{ maxWidth: 1280, margin: "0 auto" }}>
            <Results result={result} taskId={taskId} onReset={reset} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
