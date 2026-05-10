"""
PDF Report Generator for Pentest Platform
Uses ReportLab to create professional security assessment PDFs.
"""

import io
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, NextPageTemplate,
    PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.platypus.flowables import KeepTogether
import urllib.request
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

FONT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fonts')
os.makedirs(FONT_DIR, exist_ok=True)
AMIRI_REG = os.path.join(FONT_DIR, 'Amiri-Regular.ttf')
AMIRI_BOLD = os.path.join(FONT_DIR, 'Amiri-Bold.ttf')

def download_font():
    """Download Amiri font if it doesn't exist."""
    os.makedirs(FONT_DIR, exist_ok=True)
    if not os.path.exists(AMIRI_REG):
        print("Downloading Amiri font...")
        try:
            # Using Google Fonts raw github link which is very stable
            url = "https://github.com/google/fonts/raw/main/ofl/amiri/Amiri-Regular.ttf"
            urllib.request.urlretrieve(url, AMIRI_REG)
            print("Font downloaded successfully.")
        except Exception as e:
            print(f"Warning: Failed to download font: {e}")

try:
    download_font()
    pdfmetrics.registerFont(TTFont('Amiri', AMIRI_REG))
    pdfmetrics.registerFont(TTFont('Amiri-Bold', AMIRI_BOLD))
    DEFAULT_FONT = 'Amiri'
    BOLD_FONT = 'Amiri-Bold'
    
    import arabic_reshaper
    try:
        from bidi.algorithm import get_display
        def format_text(text):
            if not text: return text
            reshaped_text = arabic_reshaper.reshape(str(text))
            return get_display(reshaped_text)
    except ImportError:
        # Manual fallback if python-bidi failed to install
        print("Warning: python-bidi not installed, using manual string reversal for Arabic.")
        def format_text(text):
            if not text: return text
            reshaped_text = arabic_reshaper.reshape(str(text))
            # Reverse only if it contains Arabic characters
            if any("\u0600" <= c <= "\u06FF" for c in reshaped_text):
                return reshaped_text[::-1]
            return reshaped_text
except Exception as e:
    print(f"Warning: Arabic font setup failed, falling back to Helvetica. {e}")
    DEFAULT_FONT = 'Helvetica'
    BOLD_FONT = 'Helvetica-Bold'
    def format_text(text):
        return str(text) if text else text


# ─────────────────────────────────────────────────────────────
# Color palette
# ─────────────────────────────────────────────────────────────
C_BG      = colors.HexColor('#0d1117')
C_SURFACE = colors.HexColor('#161b22')
C_BORDER  = colors.HexColor('#30363d')
C_PRIMARY = colors.HexColor('#0078d4')
C_TEXT    = colors.HexColor('#e6edf3')
C_MUTED   = colors.HexColor('#8b949e')

C_CRITICAL = colors.HexColor('#da3633')
C_HIGH     = colors.HexColor('#f85149')
C_MEDIUM   = colors.HexColor('#d29922')
C_LOW      = colors.HexColor('#3fb950')
C_INFO     = colors.HexColor('#58a6ff')

SEV_COLORS = {
    'critical': C_CRITICAL,
    'high':     C_HIGH,
    'medium':   C_MEDIUM,
    'low':      C_LOW,
    'info':     C_INFO,
}

RISK_GRADE_COLORS = {
    'A': C_LOW,
    'B': C_INFO,
    'C': C_MEDIUM,
    'D': C_HIGH,
    'F': C_CRITICAL,
}


def _sev_color(sev: str) -> colors.Color:
    return SEV_COLORS.get((sev or 'info').lower(), C_INFO)


# ─────────────────────────────────────────────────────────────
# Styles
# ─────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    styles = getSampleStyleSheet()
    base = dict(
        fontName=DEFAULT_FONT,
        textColor=C_TEXT,
        leading=14,
    )
    return {
        'h1': ParagraphStyle('H1', **{**base, 'fontSize': 22, 'fontName': BOLD_FONT,
                                      'textColor': C_TEXT, 'spaceAfter': 6}),
        'h2': ParagraphStyle('H2', **{**base, 'fontSize': 14, 'fontName': BOLD_FONT,
                                      'textColor': C_PRIMARY, 'spaceBefore': 12, 'spaceAfter': 4}),
        'h3': ParagraphStyle('H3', **{**base, 'fontSize': 11, 'fontName': BOLD_FONT,
                                      'textColor': C_TEXT, 'spaceBefore': 8, 'spaceAfter': 2}),
        'body': ParagraphStyle('Body', **{**base, 'fontSize': 10, 'alignment': TA_JUSTIFY,
                                          'spaceAfter': 4}),
        'muted': ParagraphStyle('Muted', **{**base, 'fontSize': 9, 'textColor': C_MUTED}),
        'center': ParagraphStyle('Center', **{**base, 'fontSize': 10, 'alignment': TA_CENTER}),
        'mono': ParagraphStyle('Mono', **{**base, 'fontSize': 9, 'fontName': 'Courier',
                                           'textColor': C_PRIMARY}),
    }


# ─────────────────────────────────────────────────────────────
# Main generator
# ─────────────────────────────────────────────────────────────

def generate_pdf_report(
    scan_data: Dict[str, Any],
    ai_report: Dict[str, Any],
    vulnerabilities: List[Dict],
    output_path: str
) -> str:
    """
    Generate a professional PDF security report.
    Returns the output_path on success.
    """
    S = _build_styles()

    # ── Page setup ──
    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=2.5*cm, bottomMargin=2*cm,
    )
    W, H = A4
    content_w = W - 3.6*cm

    def _dark_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)

        # Header bar
        canvas.setFillColor(C_SURFACE)
        canvas.rect(0, H - 1.8*cm, W, 1.8*cm, fill=1, stroke=0)
        canvas.setFillColor(C_PRIMARY)
        canvas.rect(0, H - 1.84*cm, W, 4, fill=1, stroke=0)

        canvas.setFillColor(C_TEXT)
        canvas.setFont(BOLD_FONT, 10)
        canvas.drawString(1.8*cm, H - 1.2*cm, format_text('🛡  Security Suite — Pentest Report'))
        canvas.setFont(DEFAULT_FONT, 8)
        canvas.setFillColor(C_MUTED)
        canvas.drawRightString(W - 1.8*cm, H - 1.2*cm,
                               format_text(f'Page {doc.page}  •  {datetime.now().strftime("%Y-%m-%d")}'))

        # Footer
        canvas.setFillColor(C_BORDER)
        canvas.rect(0, 0, W, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(C_MUTED)
        canvas.setFont(DEFAULT_FONT, 7)
        canvas.drawCentredString(
            W / 2, 0.45*cm,
            format_text('CONFIDENTIAL — For authorized use only. Generated by Security Suite Pentest Platform.')
        )
        canvas.restoreState()

    frame = Frame(1.8*cm, 1.4*cm, content_w, H - 4.5*cm, id='main')
    doc.addPageTemplates([PageTemplate(id='dark', frames=[frame], onPage=_dark_page)])

    story = []

    # ── Extract data ──
    target       = (scan_data.get('scan_metadata') or {}).get('target') or scan_data.get('target', 'Unknown')
    scan_type    = scan_data.get('scan_type', 'standard')
    scan_date    = scan_data.get('scan_metadata', {}).get('scan_date', datetime.now().isoformat())
    duration     = scan_data.get('duration', 0)
    risk_score   = ai_report.get('risk_score', 0)
    risk_grade   = ai_report.get('risk_grade', 'C')
    risk_level   = (ai_report.get('risk_level', 'info') or 'info').upper()
    exec_summary = ai_report.get('executive_summary', 'No AI summary available.')
    threat_narr  = ai_report.get('threat_narrative', '')
    sev_dist     = ai_report.get('severity_distribution', {})
    top_findings = ai_report.get('top_findings', [])
    recommends   = ai_report.get('recommendations', [])
    mitigation   = ai_report.get('mitigation_roadmap', [])
    ports        = _extract_ports(scan_data)

    grade_color  = RISK_GRADE_COLORS.get(risk_grade, C_MUTED)

    # ── Cover / header info ──
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(format_text('Security Assessment Report - تقرير الفحص الأمني'), S['h1']))
    story.append(HRFlowable(width='100%', thickness=1, color=C_PRIMARY))
    story.append(Spacer(1, 0.4*cm))

    # Meta table
    meta_data = [
        [format_text('Target'), format_text(target)],
        [format_text('Scan Type'), format_text(scan_type.upper())],
        [format_text('Scan Date'), format_text(scan_date[:19].replace('T', ' '))],
        [format_text('Duration'), format_text(f'{float(duration):.1f}s' if duration else 'N/A')],
        [format_text('Risk Grade'), format_text(f'{risk_grade}  ({risk_score}/100)')],
        [format_text('Risk Level'), format_text(risk_level)],
    ]
    meta_table = Table(meta_data, colWidths=[3.5*cm, content_w - 3.5*cm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME',    (0, 0), (-1, -1), DEFAULT_FONT),
        ('FONTNAME',    (0, 0), (0, -1),  BOLD_FONT),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',   (0, 0), (0, -1),  C_MUTED),
        ('TEXTCOLOR',   (1, 0), (1, -1),  C_TEXT),
        ('TEXTCOLOR',   (1, 4), (1, 4),   grade_color),
        ('BACKGROUND',  (0, 0), (-1, -1), C_SURFACE),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [C_SURFACE, C_BG]),
        ('GRID',        (0, 0), (-1, -1), 0.3, C_BORDER),
        ('PADDING',     (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.6*cm))

    # ── Executive Summary ──
    story.append(Paragraph(format_text('Executive Summary / الملخص التنفيذي'), S['h2']))
    story.append(Paragraph(format_text(exec_summary), S['body']))
    if threat_narr:
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(format_text(threat_narr), S['body']))
    story.append(Spacer(1, 0.4*cm))

    # ── Severity Distribution ──
    if sev_dist:
        story.append(Paragraph(format_text('Severity Distribution / توزيع الخطورة'), S['h2']))
        sev_rows = [[format_text('Severity'), format_text('Count'), format_text('Indicator')]]
        for level in ['critical', 'high', 'medium', 'low', 'info']:
            cnt = sev_dist.get(level, 0)
            bar = '█' * min(cnt * 3, 30) if cnt else '–'
            sev_rows.append([format_text(level.upper()), str(cnt), bar])

        sev_table = Table(sev_rows, colWidths=[3*cm, 2*cm, content_w - 5*cm])
        sev_style = [
            ('FONTNAME',   (0, 0), (-1, -1), DEFAULT_FONT),
            ('FONTNAME',   (0, 0), (-1, 0),  BOLD_FONT),
            ('FONTSIZE',   (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0),  C_SURFACE),
            ('TEXTCOLOR',  (0, 0), (-1, 0),  C_MUTED),
            ('GRID',       (0, 0), (-1, -1), 0.3, C_BORDER),
            ('PADDING',    (0, 0), (-1, -1), 5),
        ]
        for i, level in enumerate(['critical', 'high', 'medium', 'low', 'info'], start=1):
            clr = SEV_COLORS[level]
            sev_style.append(('TEXTCOLOR', (0, i), (0, i), clr))
            sev_style.append(('TEXTCOLOR', (2, i), (2, i), clr))
        sev_table.setStyle(TableStyle(sev_style))
        story.append(sev_table)
        story.append(Spacer(1, 0.4*cm))

    # ── Open Ports ──
    if ports:
        story.append(Paragraph(format_text(f'Open Ports & Services ({len(ports)} found) / المنافذ المفتوحة'), S['h2']))
        port_rows = [[format_text('Port'), format_text('Protocol'), format_text('State'), format_text('Service'), format_text('Version')]]
        for p in ports:
            svc = p.get('service', {})
            if isinstance(svc, dict):
                svc_name = svc.get('name', '—')
                svc_ver  = (svc.get('product', '') + ' ' + svc.get('version', '')).strip() or '—'
            else:
                svc_name = str(svc) if svc else '—'
                svc_ver  = '—'
            port_rows.append([
                format_text(str(p.get('port', '?'))),
                format_text(str(p.get('protocol', 'tcp'))),
                format_text(str(p.get('state', '?'))),
                format_text(svc_name),
                format_text(svc_ver[:40]),
            ])
        pt = Table(port_rows, colWidths=[1.5*cm, 2*cm, 1.8*cm, 3*cm, content_w - 8.3*cm])
        pt.setStyle(TableStyle([
            ('FONTNAME',   (0, 0), (-1, -1), DEFAULT_FONT),
            ('FONTNAME',   (0, 0), (-1, 0),  BOLD_FONT),
            ('FONTSIZE',   (0, 0), (-1, -1), 8),
            ('TEXTCOLOR',  (0, 0), (-1, 0),  C_MUTED),
            ('TEXTCOLOR',  (0, 1), (-1, -1), C_TEXT),
            ('TEXTCOLOR',  (0, 1), (0, -1),  C_PRIMARY),
            ('BACKGROUND', (0, 0), (-1, 0),  C_SURFACE),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [C_BG, C_SURFACE]),
            ('GRID',       (0, 0), (-1, -1), 0.3, C_BORDER),
            ('PADDING',    (0, 0), (-1, -1), 5),
        ]))
        story.append(pt)
        story.append(Spacer(1, 0.4*cm))

    # ── Top Findings ──
    if top_findings:
        story.append(PageBreak())
        story.append(Paragraph(format_text(f'Security Findings ({len(top_findings)}) / الثغرات المكتشفة'), S['h2']))
        for i, f in enumerate(top_findings, 1):
            sev   = (f.get('severity') or 'info').lower()
            clr   = _sev_color(sev)
            title = f.get('title', f'Finding {i}')
            desc  = f.get('description', '')
            impact= f.get('impact', '')
            comp  = f.get('affected_component', '')
            remed = f.get('remediation', '')

            block_data = [[
                Paragraph(format_text(f'[{sev.upper()}] {title}'), ParagraphStyle(
                    'Ftitle', fontName=BOLD_FONT, fontSize=11,
                    textColor=clr, leading=15
                )),
            ]]
            if comp:
                block_data.append([Paragraph(format_text(f'Affected: {comp}'), S['muted'])])
            if desc:
                block_data.append([Paragraph(format_text(desc), S['body'])])
            if impact:
                block_data.append([Paragraph(format_text(f'⚡ Impact: {impact}'), ParagraphStyle(
                    'Imp', fontName=DEFAULT_FONT, fontSize=10,
                    textColor=C_MEDIUM, leading=14
                ))])
            if remed:
                block_data.append([Paragraph(format_text(f'✅ Remediation: {remed}'), ParagraphStyle(
                    'Rem', fontName=DEFAULT_FONT, fontSize=10,
                    textColor=C_LOW, leading=14
                ))])

            btable = Table(block_data, colWidths=[content_w])
            btable.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), C_SURFACE),
                ('LEFTPADDING',  (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING',   (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING',(0, 0), (-1, -1), 6),
                ('BOX', (0, 0), (-1, -1), 1, C_BORDER),
                ('LINEBEFORE', (0, 0), (0, -1), 3, clr),
            ]))
            story.append(KeepTogether([btable, Spacer(1, 0.25*cm)]))

    # ── Recommendations ──
    if recommends:
        story.append(Paragraph(format_text('Recommendations / التوصيات'), S['h2']))
        for r in recommends:
            pri    = (r.get('priority') or 'low').lower()
            action = r.get('action', '')
            effort = r.get('effort', '')
            impact = r.get('impact_reduction', '')
            clr    = _sev_color(pri)
            row_data = [[
                Paragraph(format_text(f'[{pri.upper()}] {action}'), ParagraphStyle(
                    'Rec', fontName=BOLD_FONT, fontSize=10,
                    textColor=clr, leading=14
                )),
                Paragraph(format_text(f'Effort: {effort}\n{impact}'), S['muted']),
            ]]
            rt = Table(row_data, colWidths=[content_w * 0.7, content_w * 0.3])
            rt.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), C_BG),
                ('PADDING',    (0, 0), (-1, -1), 6),
                ('BOX',        (0, 0), (-1, -1), 0.3, C_BORDER),
                ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(KeepTogether([rt, Spacer(1, 0.15*cm)]))

        story.append(Spacer(1, 0.4*cm))

    # ── Mitigation Roadmap ──
    if mitigation:
        story.append(Paragraph(format_text('Mitigation Roadmap / خارطة طريق الإصلاح'), S['h2']))
        for phase_info in mitigation:
            phase   = phase_info.get('phase', '')
            actions = phase_info.get('actions', [])
            story.append(Paragraph(format_text(phase), S['h3']))
            for act in actions:
                story.append(Paragraph(format_text(f'• {act}'), S['body']))
        story.append(Spacer(1, 0.3*cm))

    # ── Compliance Notes ──
    comp_notes = ai_report.get('compliance_notes', [])
    if comp_notes:
        story.append(Paragraph(format_text('Compliance Notes / ملاحظات الامتثال'), S['h2']))
        for note in comp_notes:
            story.append(Paragraph(format_text(f'• {note}'), S['body']))

    story.append(Spacer(1, 0.4*cm))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        format_text(f'Report generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")} ') +
        format_text('by Security Suite Pentest Platform — AI-powered by Google Gemini.'),
        S['muted']
    ))

    doc.build(story)
    return output_path


# ─────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────

def _extract_ports(scan_data: Dict) -> List[Dict]:
    ports = []
    results = scan_data.get('results', {})
    if isinstance(results, dict):
        for key, val in results.items():
            if isinstance(val, dict):
                ports.extend(val.get('ports', []))
    if not ports:
        ports = scan_data.get('ports', [])
    return ports
