"""
engines/pdf_engine/pdf_engine.py — FINAL AUTHORITATIVE VERSION

Industry-grade PDF report generator. Uses ReportLab.
Supports full and custom (checkbox-selected) section output.

PLACE AT: backend/engines/pdf_engine/pdf_engine.py
Also create: backend/engines/pdf_engine/__init__.py (see pdf_engine_init.py)

Install: pip install reportlab
"""

import io
import json
import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.pdfgen import canvas
    _REPORTLAB_OK = True
except ImportError:
    _REPORTLAB_OK = False

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm

C_BG     = colors.HexColor("#060E1E")
C_CYAN   = colors.HexColor("#00F0FF")
C_GREEN  = colors.HexColor("#00FF88")
C_RED    = colors.HexColor("#FF3C6E")
C_ORANGE = colors.HexColor("#FFB347")
C_TEXT   = colors.HexColor("#1A2535")
C_MUTED  = colors.HexColor("#6B8FA8")
C_HEADBG = colors.HexColor("#0D1F35")
C_ROWALT = colors.HexColor("#F0F6FF")

VERDICT_COLORS = {
    "MALICIOUS":  C_RED,
    "SUSPICIOUS": C_ORANGE,
    "BENIGN":     C_GREEN,
    "UNKNOWN":    C_MUTED,
}

SECTION_KEYS = [
    "cover", "executive", "metadata", "verdict",
    "capabilities", "mitre", "ioc", "strings",
    "imports", "functions", "risk", "json",
]

MITRE_DESC = {
    "T1055":  "Process Injection — adversary injects code into another process",
    "T1055.012": "Process Hollowing — replaces legitimate process with malicious code",
    "T1071":  "Application Layer Protocol — uses HTTP/DNS for C2",
    "T1003":  "OS Credential Dumping — harvests credentials from OS memory",
    "T1134":  "Access Token Manipulation — abuses Windows tokens",
    "T1041":  "Exfiltration over C2 Channel",
    "T1547":  "Boot/Logon Autostart — persistence at startup",
    "T1059":  "Command and Scripting Interpreter",
    "T1059.001": "PowerShell execution",
    "T1027":  "Obfuscated Files or Information",
    "T1082":  "System Information Discovery",
    "T1057":  "Process Discovery",
    "T1083":  "File and Directory Discovery",
    "T1105":  "Ingress Tool Transfer",
    "T1056":  "Input Capture / Keylogging",
    "T1486":  "Data Encrypted for Impact — ransomware",
    "T1485":  "Data Destruction",
    "T1068":  "Exploitation for Privilege Escalation",
    "T1562":  "Impair Defenses",
    "T1497":  "Virtualization/Sandbox Evasion",
    "T1622":  "Debugger Evasion",
}

CAP_DESC = {
    "process_injection":      "Code injection into other process address spaces",
    "process_hollowing":      "Replaces legitimate process memory with malicious payload",
    "credential_dumping":     "Extracts credentials from OS memory or files",
    "keylogging":             "Captures keystrokes to harvest sensitive input",
    "payload_download":       "Downloads additional payloads from remote server",
    "command_and_control":    "Communicates with attacker-controlled C2 server",
    "registry_persistence":   "Modifies registry for persistence across reboots",
    "service_creation":       "Creates or modifies system services for persistence",
    "anti_debugging":         "Detects and evades analysis tools and debuggers",
    "anti_vm":                "Detects virtualised/sandboxed environments",
    "data_exfiltration":      "Sends collected data to external destination",
    "cryptographic_activity": "Uses encryption — possible ransomware or C2 obfuscation",
    "dynamic_loading":        "Loads libraries at runtime to evade static analysis",
    "memory_allocation":      "Allocates executable memory regions",
    "memory_protection_change": "Changes memory permissions (DEP bypass)",
    "network_communication":  "Sends or receives data over network sockets",
    "startup_persistence":    "Configured to run at system startup",
}


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _file_hashes(file_path: str) -> dict:
    hashes = {"md5": "N/A", "sha1": "N/A", "sha256": "N/A"}
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        hashes = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
    except Exception:
        pass
    return hashes


def _file_size_str(file_path: str) -> str:
    try:
        size = os.path.getsize(file_path)
        if size >= 1048576:  return f"{size/1048576:.2f} MB"
        if size >= 1024:     return f"{size/1024:.1f} KB"
        return f"{size} bytes"
    except Exception:
        return "unknown"


def _cvss_scalar(result: dict) -> float:
    cvss = result.get("cvss", result.get("cvss_score", 0))
    if isinstance(cvss, dict):
        return float(cvss.get("cvss_score", 0) or 0)
    return float(cvss or 0)


def _make_styles() -> dict:
    styles = {}
    def S(name, **kw):
        styles[name] = ParagraphStyle(name, **kw)
    S("cover_title", fontName="Helvetica-Bold",  fontSize=32, textColor=colors.white,   alignment=TA_CENTER, spaceAfter=6)
    S("cover_sub",   fontName="Helvetica",        fontSize=14, textColor=C_CYAN,         alignment=TA_CENTER, spaceAfter=4)
    S("cover_meta",  fontName="Courier",           fontSize=9,  textColor=C_MUTED,        alignment=TA_CENTER, spaceAfter=3)
    S("sec_head",    fontName="Helvetica-Bold",   fontSize=13, textColor=C_CYAN,         spaceAfter=6, spaceBefore=14)
    S("sub_head",    fontName="Helvetica-Bold",   fontSize=10, textColor=C_TEXT,         spaceAfter=4, spaceBefore=6)
    S("body",        fontName="Helvetica",         fontSize=9,  textColor=C_TEXT,         spaceAfter=3, leading=14)
    S("mono",        fontName="Courier",           fontSize=8,  textColor=C_TEXT,         spaceAfter=2, leading=11)
    S("mono_sm",     fontName="Courier",           fontSize=7,  textColor=C_MUTED,        spaceAfter=1, leading=10)
    S("verdict_txt", fontName="Helvetica-Bold",   fontSize=28, textColor=colors.white,   alignment=TA_CENTER)
    return styles


def _section(title: str, styles: dict) -> list:
    return [
        Spacer(1, 4 * mm),
        HRFlowable(width="100%", thickness=0.5, color=C_CYAN, spaceAfter=3),
        Paragraph(f"▶ {title}", styles["sec_head"]),
    ]


def _tbl(data: list, col_widths: list) -> Table:
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",  (0, 0), (-1, 0),  8),
        ("FONTNAME",  (0, 1), (-1, -1), "Courier"),
        ("FONTSIZE",  (0, 1), (-1, -1), 7.5),
        ("BACKGROUND",(0, 0), (-1, 0),  C_HEADBG),
        ("TEXTCOLOR", (0, 0), (-1, 0),  C_CYAN),
        ("TEXTCOLOR", (0, 1), (-1, -1), C_TEXT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROWALT]),
        ("GRID",      (0, 0), (-1, -1), 0.3, colors.HexColor("#DDE8F0")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",    (0, 0), (-1, -1), "MIDDLE"),
        ("WORDWRAP",  (0, 0), (-1, -1), True),
    ]))
    return t


class _ARISECanvas(canvas.Canvas):
    def __init__(self, filename, **kwargs):
        self._arise_filename = kwargs.pop("arise_filename", "")
        super().__init__(filename, **kwargs)
        self._page_count = 0

    def showPage(self):
        self._page_count += 1
        self._draw_chrome()
        super().showPage()

    def save(self):
        self._draw_chrome()
        super().save()

    def _draw_chrome(self):
        w, h = A4
        self.setFillColor(C_HEADBG)
        self.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(C_CYAN)
        self.drawString(MARGIN, h - 9*mm, "A.R.I.S.E. — Automated Reverse Engineering & Intelligent Security Evaluation")
        self.setFont("Courier", 7)
        self.setFillColor(C_MUTED)
        self.drawRightString(w - MARGIN, h - 9*mm, f"CONFIDENTIAL · {_now_str()}")
        self.setFillColor(C_HEADBG)
        self.rect(0, 0, w, 10*mm, fill=1, stroke=0)
        self.setFont("Courier", 7)
        self.setFillColor(C_MUTED)
        self.drawCentredString(w/2, 3.5*mm,
            f"AutoRev MCP Report  ·  {self._arise_filename}  ·  Page {self._page_count}")
        self.setStrokeColor(C_CYAN)
        self.setLineWidth(0.5)
        self.line(MARGIN, h - 14*mm, w - MARGIN, h - 14*mm)


def generate_pdf_report(
    result: dict,
    file_path: Optional[str] = None,
    sections: Optional[list] = None,
) -> bytes:
    """
    Generate a PDF report from an ARISE analysis result dict.

    result    : full pipeline output from celery_worker._normalise_result()
    file_path : optional path to analysed file for hash computation
    sections  : list of section keys to include; None = all sections

    Returns PDF bytes.
    """
    if not _REPORTLAB_OK:
        raise RuntimeError("reportlab not installed. Run: pip install reportlab")

    if sections is None:
        sections = SECTION_KEYS
    sec = set(sections)
    styles = _make_styles()
    buf = io.BytesIO()

    meta      = result.get("analysis_meta", {})
    filename  = meta.get("filename") or (os.path.basename(file_path) if file_path else "unknown")
    engine    = meta.get("extraction_engine", "radare2")
    elapsed   = meta.get("total_elapsed") or meta.get("extraction_elapsed") or 0
    capa_on   = meta.get("capa_enabled", False)
    ghidra_on = meta.get("ghidra_available", False)

    verdict_raw = result.get("verdict", {})
    if isinstance(verdict_raw, dict) and "verdict" in verdict_raw \
            and isinstance(verdict_raw["verdict"], dict):
        verdict_raw = verdict_raw["verdict"]
    label      = verdict_raw.get("verdict") or verdict_raw.get("label") or "UNKNOWN"
    confidence = verdict_raw.get("confidence", verdict_raw.get("confidence_pct", 0))
    category   = verdict_raw.get("category", "")
    summary    = verdict_raw.get("summary", result.get("summary", ""))
    rec_actions = verdict_raw.get("recommended_actions", [])

    risk_score = float(result.get("risk_score", 0) or 0)
    cvss_val   = _cvss_scalar(result)
    caps       = result.get("capabilities", [])
    mitre_list = result.get("mitre", [])
    imports_list = result.get("imports", [])
    strings_list = result.get("strings", [])
    funcs_list   = result.get("functions", [])
    hashes_dict  = result.get("hashes", {})
    file_type    = result.get("file_type", "Unknown")

    if file_path and (not hashes_dict or hashes_dict.get("sha256") == "N/A"):
        hashes_dict = _file_hashes(file_path)
    file_size = _file_size_str(file_path) if file_path else "N/A"

    vc = VERDICT_COLORS.get(label, C_MUTED)

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=18*mm, bottomMargin=14*mm,
        leftMargin=MARGIN, rightMargin=MARGIN,
        title=f"ARISE Report — {filename}",
        author="AutoRev MCP",
    )

    story = []

    # COVER
    if "cover" in sec:
        story += [
            Spacer(1, 20*mm),
            Paragraph("AutoRev MCP", styles["cover_title"]),
            Paragraph("A.R.I.S.E. Security Analysis Report", styles["cover_sub"]),
            Spacer(1, 8*mm),
            HRFlowable(width="60%", thickness=1, color=C_CYAN, spaceAfter=8),
            Spacer(1, 4*mm),
            Paragraph(f"File: {filename}", styles["cover_meta"]),
            Paragraph(f"Type: {file_type}", styles["cover_meta"]),
            Paragraph(f"Generated: {_now_str()}", styles["cover_meta"]),
            Paragraph(f"Engine: {engine.upper()} | CAPA: {'✓' if capa_on else '✗'} | Ghidra: {'✓' if ghidra_on else '✗'}", styles["cover_meta"]),
            Spacer(1, 16*mm),
        ]
        vt = Table([[Paragraph(label, styles["verdict_txt"])]],
                   colWidths=[PAGE_W - 2*MARGIN])
        vt.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), vc),
            ("TOPPADDING",   (0,0),(-1,-1), 10),
            ("BOTTOMPADDING",(0,0),(-1,-1), 10),
            ("ALIGN",        (0,0),(-1,-1), "CENTER"),
        ]))
        story += [vt, Spacer(1, 8*mm)]
        story += [
            Paragraph(f"Confidence: {confidence:.0f}%   ·   Risk Score: {risk_score:.0f}/100   ·   CVSS: {cvss_val:.1f}/10.0", styles["cover_meta"]),
            Spacer(1, 4*mm),
            Paragraph(f"Classification: {category}", styles["cover_meta"]),
            Spacer(1, 30*mm),
            Paragraph("CONFIDENTIAL — FOR AUTHORIZED ANALYSTS ONLY", styles["cover_meta"]),
            PageBreak(),
        ]

    # EXECUTIVE SUMMARY
    if "executive" in sec:
        story += _section("Executive Summary", styles)
        story.append(Paragraph(
            summary or
            f"This binary has been classified as <b>{label}</b> with a risk score of "
            f"{risk_score:.0f}/100 and CVSS {cvss_val:.1f}/10.0. "
            f"{len(caps)} capability group(s) and {len(mitre_list)} MITRE ATT&CK "
            f"technique(s) detected. Analysis performed using {engine.upper()} in {elapsed:.1f}s.",
            styles["body"]
        ))
        if rec_actions:
            story += [Spacer(1, 3*mm), Paragraph("Recommended Actions:", styles["sub_head"])]
            for i, action in enumerate(rec_actions, 1):
                story.append(Paragraph(f"{i}. {action}", styles["body"]))

    # METADATA
    if "metadata" in sec:
        story += _section("File Metadata & Hashes", styles)
        rows = [
            ["Property",    "Value"],
            ["Filename",    filename],
            ["File Type",   file_type],
            ["File Size",   file_size],
            ["MD5",         hashes_dict.get("md5", "N/A")],
            ["SHA-1",       hashes_dict.get("sha1", "N/A")],
            ["SHA-256",     hashes_dict.get("sha256", "N/A")],
            ["Engine",      engine.upper()],
            ["CAPA",        "Enabled" if capa_on else "Disabled"],
            ["Ghidra",      "Available" if ghidra_on else "Not available"],
            ["Analysis Time", f"{elapsed:.1f}s"],
            ["Report Date", _now_str()],
        ]
        story.append(_tbl(rows, [55*mm, PAGE_W - 2*MARGIN - 60*mm]))

    # VERDICT
    if "verdict" in sec:
        story += _section("Verdict & Risk Assessment", styles)
        rows = [
            ["Field",           "Value"],
            ["Verdict",         label],
            ["Confidence",      f"{confidence:.0f}%"],
            ["Category",        category or "N/A"],
            ["Risk Score",      f"{risk_score:.1f} / 100"],
            ["CVSS Score",      f"{cvss_val:.1f} / 10.0"],
            ["MITRE Count",     str(len(mitre_list))],
            ["Capabilities",    str(len(caps))],
        ]
        story.append(_tbl(rows, [55*mm, PAGE_W - 2*MARGIN - 60*mm]))
        if summary:
            story += [Spacer(1, 3*mm), Paragraph(f"<i>{summary}</i>", styles["body"])]

    # CAPABILITIES
    if "capabilities" in sec and caps:
        story += _section("Detected Capabilities", styles)
        rows = [["#", "Capability", "Description"]]
        for i, cap in enumerate(caps, 1):
            desc = CAP_DESC.get(cap, cap.replace("_", " ").title())
            rows.append([str(i), cap.replace("_", " ").title(), desc])
        story.append(_tbl(rows, [10*mm, 55*mm, PAGE_W - 2*MARGIN - 70*mm]))

    # MITRE
    if "mitre" in sec and mitre_list:
        story += _section("MITRE ATT&CK Mapping", styles)
        rows = [["Technique ID", "Description"]]
        for tid in mitre_list:
            desc = MITRE_DESC.get(tid, f"See attack.mitre.org/techniques/{tid}")
            rows.append([tid, desc])
        story.append(_tbl(rows, [30*mm, PAGE_W - 2*MARGIN - 35*mm]))

    # IOC
    if "ioc" in sec:
        story += _section("Indicators of Compromise (IOC)", styles)
        ioc_pats = {
            "URL/Domain":  re.compile(r"https?://\S+|[a-z0-9\-]+\.[a-z]{2,6}(/\S*)?", re.I),
            "IP Address":  re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
            "Registry":    re.compile(r"HKEY_\w+\\[^\s]+", re.I),
            "File Path":   re.compile(r"[A-Za-z]:\\[^\s]+|%\w+%\\[^\s]+", re.I),
            "Command":     re.compile(r"cmd\.exe|powershell|wscript|cscript|/bin/\w+", re.I),
        }
        iocs_found = []
        for s in strings_list[:500]:
            for ioc_type, pat in ioc_pats.items():
                if pat.search(str(s)):
                    iocs_found.append((ioc_type, str(s)[:120]))
                    break
        if iocs_found:
            rows = [["Type", "Indicator"]] + [[t, v] for t, v in iocs_found[:80]]
            story.append(_tbl(rows, [30*mm, PAGE_W - 2*MARGIN - 35*mm]))
        else:
            story.append(Paragraph("No high-confidence IOCs extracted.", styles["body"]))

    # STRINGS
    if "strings" in sec and strings_list:
        story += _section(f"Strings ({len(strings_list)} total, top 100 shown)", styles)
        rows = [["#", "String"]]
        for i, s in enumerate(strings_list[:100], 1):
            rows.append([str(i), str(s)[:120]])
        story.append(_tbl(rows, [10*mm, PAGE_W - 2*MARGIN - 15*mm]))

    # IMPORTS
    if "imports" in sec and imports_list:
        story += _section(f"Imports ({len(imports_list)} total)", styles)
        rows = [["#", "Import"]]
        for i, imp in enumerate(imports_list[:200], 1):
            rows.append([str(i), str(imp)[:120]])
        story.append(_tbl(rows, [10*mm, PAGE_W - 2*MARGIN - 15*mm]))

    # FUNCTIONS
    if "functions" in sec and funcs_list:
        story += _section(f"Functions ({len(funcs_list)} total, top 50 shown)", styles)
        rows = [["#", "Name", "Size"]]
        for i, func in enumerate(funcs_list[:50], 1):
            if isinstance(func, dict):
                name = func.get("name", "unknown")
                size = func.get("size", 0)
            else:
                name = str(func); size = 0
            rows.append([str(i), name[:80], str(size)])
        story.append(_tbl(rows, [10*mm, PAGE_W - 2*MARGIN - 30*mm, 20*mm]))

    # RISK BREAKDOWN
    if "risk" in sec:
        story += _section("Risk Score Breakdown", styles)
        cvss_detail = result.get("cvss_detail", result.get("cvss", {}))
        if isinstance(cvss_detail, dict):
            tactic_cov = cvss_detail.get("tactic_coverage", [])
            risk_level = cvss_detail.get("risk_level", "N/A")
        else:
            tactic_cov = []; risk_level = "N/A"
        rows = [
            ["Metric",              "Value"],
            ["Combined Risk Score", f"{risk_score:.1f} / 100"],
            ["CVSS Score",          f"{cvss_val:.1f} / 10.0"],
            ["Risk Level",          risk_level],
            ["MITRE Techniques",    str(len(mitre_list))],
            ["Tactic Coverage",     ", ".join(tactic_cov) if tactic_cov else "N/A"],
            ["Capabilities Found",  str(len(caps))],
            ["Imports Analysed",    str(len(imports_list))],
            ["Strings Extracted",   str(len(strings_list))],
        ]
        story.append(_tbl(rows, [65*mm, PAGE_W - 2*MARGIN - 70*mm]))

    # JSON APPENDIX
    if "json" in sec:
        story += _section("Raw Analysis JSON (Appendix)", styles)
        json_safe = {
            "verdict":       result.get("verdict"),
            "risk_score":    result.get("risk_score"),
            "cvss":          result.get("cvss"),
            "capabilities":  result.get("capabilities"),
            "mitre":         result.get("mitre"),
            "behaviours":    result.get("behaviours"),
            "hashes":        result.get("hashes"),
            "file_type":     result.get("file_type"),
            "analysis_meta": result.get("analysis_meta"),
        }
        json_text = json.dumps(json_safe, indent=2, default=str)
        for line in json_text.split("\n")[:200]:
            story.append(Paragraph(
                line.replace(" ", "&nbsp;").replace("<", "&lt;"),
                styles["mono_sm"]
            ))
        if len(json_text.split("\n")) > 200:
            story.append(Paragraph("... (truncated) ...", styles["mono_sm"]))

    # BUILD
    class _CanvasMaker(_ARISECanvas):
        def __init__(self, path, **kwargs):
            super().__init__(path, arise_filename=filename, **kwargs)

    doc.build(story, canvasmaker=_CanvasMaker)
    return buf.getvalue()
