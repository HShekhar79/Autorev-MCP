// arise-frontend/src/services/api.js
// Aligned with the authenticated job-based backend (main.py):
//   POST /upload -> job_id, GET /analysis/{job_id}, POST /report/generate
// Legacy /upload-analyze, /task-status/{id}, /task/{id} (Celery) are no longer used.
const BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// ── Auth token handling (minimal) ────────────────────────────────────────────
// The token is issued by POST /auth/login (Token.access_token). It is never
// hardcoded; whatever login flow the app uses should call setAccessToken().
export const TOKEN_STORAGE_KEY = 'arise_access_token';

export function getAccessToken() {
  try { return window.localStorage.getItem(TOKEN_STORAGE_KEY) || null; } catch { return null; }
}
export function setAccessToken(token) {
  try { window.localStorage.setItem(TOKEN_STORAGE_KEY, token); } catch {}
}
export function clearAccessToken() {
  try { window.localStorage.removeItem(TOKEN_STORAGE_KEY); } catch {}
}

function authHeaders(extra = {}) {
  const t = getAccessToken();
  return t ? { ...extra, Authorization: `Bearer ${t}` } : { ...extra };
}

// Backend error shapes: HTTPException -> {detail}, global handler -> {error, details},
// analysis routes -> HTTP 200 {error}. Normalise all of them to a string.
function errorText(body, fallback) {
  if (!body) return fallback;
  const d = body.detail ?? body.error ?? body.details;
  if (!d) return fallback;
  return typeof d === 'string' ? d : JSON.stringify(d);
}

async function failFromResponse(res, prefix) {
  let body = null;
  try { body = await res.json(); } catch {}
  let msg = errorText(body, res.statusText || `HTTP ${res.status}`);
  if (res.status === 401) msg = `${msg} (please log in again)`;
  throw new Error(`${prefix}: ${msg}`);
}

// ── Upload + analyse ─────────────────────────────────────────────────────────

const ANALYSIS_TIMEOUT_MS = 6 * 60 * 1000;
const activeControllers = new Map();   // job_id -> AbortController

async function uploadFile(file, signal) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${BASE_URL}/upload`, {
    method: 'POST',
    headers: authHeaders(),          // no Content-Type: browser sets multipart boundary
    body: formData,
    signal,
  });
  if (!res.ok) await failFromResponse(res, 'Upload failed');
  const data = await res.json();
  if (!data.job_id) throw new Error('Upload failed: server returned no job_id');
  return data;
}

async function fetchAnalysis(jobId, signal) {
  const res = await fetch(`${BASE_URL}/analysis/${encodeURIComponent(jobId)}`, {
    headers: authHeaders(),
    signal,
  });
  if (!res.ok) await failFromResponse(res, 'Analysis failed');
  const data = await res.json();
  if (data && data.error) throw new Error(`Analysis failed: ${errorText(data, 'unknown error')}`);
  return data;
}

/**
 * Upload a file and run analysis. Same contract as before:
 * resolves { result, taskId } where taskId is now the backend job_id.
 * onProgress(stage, pct) is called while waiting. The backend exposes no
 * progress feed, so pct is an estimate; stage stays 'extraction' until done.
 */
export async function analyzeFile(file, onProgress, options = {}) {
  const started    = Date.now();
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, ANALYSIS_TIMEOUT_MS);
  if (options.signal) {
    if (options.signal.aborted) controller.abort();
    else options.signal.addEventListener('abort', () => controller.abort(), { once: true });
  }

  let jobId = null;
  let ticker = null;
  try {
    if (onProgress) onProgress('extraction', 3);
    const upload = await uploadFile(file, controller.signal);
    jobId = upload.job_id;
    activeControllers.set(jobId, controller);

    if (onProgress) {
      onProgress('extraction', 8);
      ticker = setInterval(() => {
        const t = (Date.now() - started) / 1000;
        onProgress('extraction', Math.round(8 + 82 * (1 - Math.exp(-t / 60))));
      }, 1000);
    }

    const raw = await fetchAnalysis(jobId, controller.signal);
    const elapsed = (Date.now() - started) / 1000;
    const result = normaliseAnalysis(raw, upload, elapsed);
    if (onProgress) onProgress('verdict', 100);
    return { result, taskId: jobId };
  } catch (e) {
    if (e && e.name === 'AbortError') {
      throw new Error(timedOut ? 'Analysis timed out after 6 minutes' : 'Analysis cancelled');
    }
    throw e;
  } finally {
    if (ticker) clearInterval(ticker);
    clearTimeout(timer);
    if (jobId) activeControllers.delete(jobId);
  }
}

/** Client-side cancel only: the backend has no cancel endpoint, so a running
 *  server-side pipeline is not stopped. Kept so existing imports keep working. */
export async function cancelTask(jobId) {
  const c = activeControllers.get(jobId);
  if (c) c.abort();
}

// ── Result normalisation: backend pipeline result -> shape DashboardPage reads ──

const asArray = v => (Array.isArray(v) ? v : []);
const uniq    = arr => [...new Set(arr)];

function toMitreIds(finalMitre) {
  const list = Array.isArray(finalMitre)
    ? finalMitre
    : asArray(finalMitre && (finalMitre.mitre_techniques || finalMitre.final_mitre));
  return uniq(
    list
      .map(t => (typeof t === 'string' ? t : t && (t.technique_id || t.id || t.technique || t.mitre_id)))
      .filter(Boolean)
      .map(String)
  );
}

function toVerdict(v) {
  const o = (typeof v === 'string') ? { verdict: v } : (v && typeof v === 'object' ? { ...v } : {});
  const label = o.verdict || o.label || 'UNKNOWN';
  o.verdict = label;
  o.label   = o.label || label;
  return o;
}

export function normaliseAnalysis(raw, upload = {}, elapsedSeconds) {
  raw = raw || {};
  const analysis = raw.analysis || {};
  const fnResults = asArray(analysis.results);
  const risk = raw.risk || {};
  const cvssRes = raw.cvss_results || {};
  const meta = raw.analysis_meta || {};
  const behaviours = raw.behaviors || raw.behaviour || {};
  const verdict = toVerdict(raw.arise_verdict);

  const functions = fnResults.map(f => {
    if (typeof f === 'string') return { name: f, size: 0 };
    return {
      name: f.name || f.function || f.function_name || f.address || f.offset || 'unknown',
      size: f.size ?? f.length ?? 0,
    };
  });

  const calls = uniq(
    fnResults.flatMap(f => asArray(f && (f.calls || f.api_calls || f.apis)))
      .filter(c => typeof c === 'string')
  );

  return {
    functions,
    imports: asArray(raw.imports),
    strings: asArray(raw.strings),
    calls,
    behaviours: asArray(behaviours.behaviors),
    capabilities: asArray(raw.capabilities),
    mitre: toMitreIds(raw.final_mitre),
    risk_score: Number(risk.combined_score) || 0,
    cvss: Number(cvssRes.cvss_score) || 0,
    cvss_detail: cvssRes,
    verdict,
    // Upload response only provides sha256; md5/sha1 render as "N/A".
    hashes: upload.sha256 ? { sha256: upload.sha256 } : {},
    file_type: upload.file_type || '',
    summary: verdict.summary || '',
    analysis_meta: {
      ...meta,
      filename: upload.filename || meta.filename,
      total_elapsed: elapsedSeconds,
    },
  };
}

// ── Report download ──────────────────────────────────────────────────────────

export async function downloadReport(taskId, sections = null) {
  if (!taskId || taskId === 'demo') {
    throw new Error('Report download is not available in demo mode.');
  }
  // taskId is the job_id in the current architecture.
  const body = { job_id: taskId };
  if (sections) body.sections = sections;

  const res = await fetch(`${BASE_URL}/report/generate`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  });

  if (!res.ok) await failFromResponse(res, 'Report generation failed');

  const blob     = await res.blob();
  const cd       = res.headers.get('Content-Disposition') || '';
  const match    = cd.match(/filename="([^"]+)"/);
  const filename = match ? match[1] : 'ARISE_Report.pdf';

  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  return filename;
}

export async function getReportSections() {
  try {
    const res = await fetch(`${BASE_URL}/report/sections`, { headers: authHeaders() });
    return res.ok ? res.json() : null;
  } catch { return null; }
}

export async function healthCheck() {
  try {
    const res = await fetch(`${BASE_URL}/health`);
    return res.ok;
  } catch { return false; }
}

// ── Mock result for demo mode ────────────────────────────────────────────────

export const MOCK_RESULT = {
  functions: [
    { name: 'sub_401000', size: 128 }, { name: 'CreateRemoteThread', size: 64 },
    { name: 'VirtualAllocEx', size: 96 }, { name: 'WriteProcessMemory', size: 80 },
    { name: 'GetProcAddress', size: 48 }, { name: 'OpenProcess', size: 56 },
  ],
  imports: [
    'kernel32.dll:VirtualAllocEx', 'kernel32.dll:CreateRemoteThread',
    'ws2_32.dll:connect', 'advapi32.dll:RegSetValueEx',
    'ntdll.dll:NtUnmapViewOfSection', 'kernel32.dll:OpenProcess',
    'ws2_32.dll:send', 'ws2_32.dll:recv',
  ],
  strings: [
    'cmd.exe /c', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'http://192.168.1.100:4444', 'powershell -enc',
    '%TEMP%\\svchost.exe', 'CreateRemoteThread',
    'User-Agent: Mozilla/5.0', '/bin/sh -i',
  ],
  calls: [
    'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'OpenProcess', 'connect', 'send', 'recv', 'RegSetValueEx',
  ],
  behaviours: [
    'process_injection', 'registry_persistence',
    'network_communication', 'payload_download', 'anti_debugging',
  ],
  capabilities: [
    'process_injection', 'network_communication',
    'registry_persistence', 'anti_debugging', 'privilege_escalation',
  ],
  mitre: ['T1055', 'T1071', 'T1547', 'T1059', 'T1134'],
  risk_score: 87.4,
  cvss: 8.9,
  cvss_detail: {
    cvss_score: 8.9, risk_level: 'HIGH', technique_count: 5,
    tactic_coverage: ['Defense Evasion', 'Execution', 'Persistence', 'C2'],
  },
  verdict: {
    verdict:            'MALICIOUS',
    label:              'MALICIOUS',
    confidence:         94,
    confidence_pct:     94,
    confidence_label:   'High',
    category:           'Trojan / RAT',
    summary:            'High-confidence remote access trojan with process injection and persistent C2 communication.',
    recommended_actions: [
      'Quarantine and isolate immediately.',
      'Do not execute on any production system.',
      'Submit hash to threat intelligence feeds.',
      'Perform full endpoint scan on originating host.',
    ],
  },
  hashes: {
    md5:    'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
    sha1:   'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  },
  file_type: 'PE Executable (EXE/DLL)',
  summary: 'High-confidence remote access trojan with process injection and persistent C2.',
  analysis_meta: {
    ghidra_available:  true,
    radare2_available: true,
    extraction_engine: 'radare2+ghidra',
    capa_enabled:      true,
    total_elapsed:     12.4,
    filename:          'demo_sample.exe',
  },
};
