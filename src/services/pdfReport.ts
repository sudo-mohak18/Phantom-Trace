/**
 * PhantomTrace - Client-Side PDF Dossier & HTML Report Generator
 * Generates official cybersecurity intelligence PDF and HTML reports directly in the browser.
 */

import { jsPDF } from 'jspdf';
import { ScanResult } from '../types/scanner';

export function generatePdfReport(scan: ScanResult): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;

  // Colors
  const darkNavy = [11, 15, 25]; // #0b0f19
  const purple = [147, 51, 234]; // #9333ea
  const cyan = [6, 182, 212]; // #06b6d4
  const slateDark = [30, 41, 59];
  const slateText = [71, 85, 105];
  const redAlert = [220, 38, 38];
  const amberAlert = [217, 119, 6];
  const greenClean = [16, 185, 129];

  let y = margin;

  // Top Header Banner
  doc.setFillColor(darkNavy[0], darkNavy[1], darkNavy[2]);
  doc.rect(0, 0, pageWidth, 28, 'F');

  doc.setFillColor(purple[0], purple[1], purple[2]);
  doc.rect(0, 27, pageWidth, 1.5, 'F');

  // Title inside banner
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(255, 255, 255);
  doc.text('PHANTOMTRACE', margin, 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(cyan[0], cyan[1], cyan[2]);
  doc.text('CYBERSECURITY THREAT INTELLIGENCE DOSSIER', margin, 18);

  // Classification & Metadata
  doc.setFont('courier', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(244, 63, 94);
  doc.text('TLP:AMBER+STRICT', pageWidth - margin - 35, 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text(`ID: ${scan.id.substring(0, 24)}`, pageWidth - margin - 50, 18);
  doc.text(new Date(scan.timestamp).toUTCString(), pageWidth - margin - 60, 23);

  y = 36;

  // Section 1: Target Under Investigation & Threat Verdict
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentWidth, 26, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  doc.text('TARGET URL UNDER INVESTIGATION', margin + 4, y + 6);

  doc.setFont('courier', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  const truncatedUrl = scan.targetUrl.length > 60 ? scan.targetUrl.substring(0, 57) + '...' : scan.targetUrl;
  doc.text(truncatedUrl, margin + 4, y + 13);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  doc.text(`Category: ${scan.category} | Domain Age: ${scan.domainIntelligence.ageDays} days`, margin + 4, y + 20);

  // Score Badge
  const scoreBoxX = pageWidth - margin - 38;
  const verdictColor = scan.verdict === 'malicious' ? redAlert : scan.verdict === 'suspicious' ? amberAlert : greenClean;
  doc.setFillColor(verdictColor[0], verdictColor[1], verdictColor[2]);
  doc.roundedRect(scoreBoxX, y + 3, 34, 20, 2, 2, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(255, 255, 255);
  doc.text(`${scan.overallScore}/100`, scoreBoxX + 17, y + 11, { align: 'center' });

  doc.setFontSize(7);
  doc.text(`${scan.verdict.toUpperCase()} THREAT`, scoreBoxX + 17, y + 17, { align: 'center' });

  y += 33;

  // Section 2: Executive Summary & Analyst Assessment
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(darkNavy[0], darkNavy[1], darkNavy[2]);
  doc.text('1. EXECUTIVE SUMMARY & THREAT TRIAGE', margin, y);
  y += 4;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(51, 65, 85);
  const splitSummary = doc.splitTextToSize(scan.explanations.analyst, contentWidth);
  doc.text(splitSummary, margin, y + 2);
  y += splitSummary.length * 4.2 + 6;

  // Section 3: Forensic Indicators
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(darkNavy[0], darkNavy[1], darkNavy[2]);
  doc.text(`2. FORENSIC RISK INDICATORS (${scan.indicators.length})`, margin, y);
  y += 5;

  for (const ind of scan.indicators.slice(0, 5)) {
    doc.setFillColor(241, 245, 249);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, y, contentWidth, 10, 1.5, 1.5, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text(`[${ind.severity.toUpperCase()}] ${ind.title}`, margin + 3, y + 4.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    const detailText = ind.detail.length > 85 ? ind.detail.substring(0, 82) + '...' : ind.detail;
    doc.text(detailText, margin + 3, y + 8);

    if (ind.scoreContribution > 0) {
      doc.setFont('courier', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(redAlert[0], redAlert[1], redAlert[2]);
      doc.text(`+${ind.scoreContribution} pts`, pageWidth - margin - 15, y + 6);
    }

    y += 12;
  }

  y += 2;

  // Section 4: Infrastructure & Technical Telemetry
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(darkNavy[0], darkNavy[1], darkNavy[2]);
  doc.text('3. INFRASTRUCTURE & CRYPTOGRAPHIC PROFILE', margin, y);
  y += 5;

  const colWidth = contentWidth / 4;
  const infraItems = [
    { label: 'Host IPv4', val: scan.domainIntelligence.ipAddresses[0] || 'Unresolved' },
    { label: 'ASN Transit', val: scan.domainIntelligence.asn.split(' ')[0] || 'N/A' },
    { label: 'SSL Issuer', val: scan.domainIntelligence.ssl.issuer.split(' ')[0] || 'Let\'s Encrypt' },
    { label: 'Domain Entropy', val: `${scan.urlIntelligence.entropyDomain} bits` },
  ];

  infraItems.forEach((item, idx) => {
    const boxX = margin + idx * colWidth;
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(203, 213, 225);
    doc.roundedRect(boxX, y, colWidth - 2, 13, 1.5, 1.5, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text(item.label, boxX + 2.5, y + 4.5);

    doc.setFont('courier', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text(item.val, boxX + 2.5, y + 9.5);
  });

  y += 18;

  // Section 5: MITRE ATT&CK Mapping
  if (scan.mitreMapping.length > 0) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(darkNavy[0], darkNavy[1], darkNavy[2]);
    doc.text('4. MITRE ATT&CK FRAMEWORK ALIGNMENT', margin, y);
    y += 5;

    const mitreList = scan.mitreMapping.map(m => `${m.id} (${m.tactic}: ${m.technique})`).join('  |  ');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    const splitMitre = doc.splitTextToSize(mitreList, contentWidth);
    doc.text(splitMitre, margin, y);
    y += splitMitre.length * 4 + 4;
  }

  // Section 6: Recommended Actions
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(darkNavy[0], darkNavy[1], darkNavy[2]);
  doc.text('5. ACTIONABLE INCIDENT RESPONSE PLAYBOOK', margin, y);
  y += 5;

  scan.recommendedActions.socPlaybook.slice(0, 3).forEach((act, idx) => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(purple[0], purple[1], purple[2]);
    doc.text(`${idx + 1}.`, margin, y);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(30, 41, 59);
    const actLines = doc.splitTextToSize(act, contentWidth - 8);
    doc.text(actLines, margin + 6, y);
    y += actLines.length * 4 + 1.5;
  });

  // Footer on page
  doc.setDrawColor(226, 232, 240);
  doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text('PhantomTrace Incident Response & Threat Forensics Platform — Generated deterministically.', margin, pageHeight - 7);
  doc.text('Page 1 of 1', pageWidth - margin - 15, pageHeight - 7);

  // Download the generated PDF
  const filename = `PhantomTrace_Report_${scan.urlIntelligence.domain.replace(/[^a-zA-Z0-9.-]/g, '_')}_${Date.now()}.pdf`;
  doc.save(filename);
}

/**
 * Generates and downloads a self-contained, offline-compatible HTML report dossier.
 */
export function generateHtmlReport(scan: ScanResult): void {
  const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PhantomTrace Dossier - ${scan.urlIntelligence.domain}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #07090e; color: #f1f5f9; padding: 30px; margin: 0; }
    .container { max-width: 860px; margin: 0 auto; background: #0b0f19; border: 1px solid #1e293b; border-radius: 16px; padding: 32px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }
    .header { border-bottom: 1px solid #1e293b; padding-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-start; }
    .brand { font-size: 20px; font-weight: 800; color: #fff; }
    .brand span { color: #38bdf8; }
    .badge { padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: bold; text-transform: uppercase; font-family: monospace; }
    .badge-malicious { background: #450a0a; color: #fca5a5; border: 1px solid #991b1b; }
    .badge-suspicious { background: #451a03; color: #fcd34d; border: 1px solid #b45309; }
    .badge-clean { background: #022c22; color: #6ee7b7; border: 1px solid #047857; }
    .section { margin-top: 24px; border-bottom: 1px solid #1e293b; padding-bottom: 20px; }
    .section-title { font-size: 12px; font-weight: bold; text-transform: uppercase; color: #c084fc; font-family: monospace; margin-bottom: 12px; }
    .box { background: #0e1424; border: 1px solid #1e293b; border-radius: 10px; padding: 16px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 12px; }
    .code { font-family: monospace; background: #07090e; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-size: 12px; }
    .indicator-item { background: #0e1424; border: 1px solid #1e293b; padding: 10px 14px; border-radius: 8px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }
    .btn-print { background: #7c3aed; color: #fff; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer; font-weight: bold; }
    @media print { body { background: #fff; color: #000; } .container { border: none; box-shadow: none; padding: 0; } .btn-print { display: none; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="brand">PhantomTrace <span>AI</span> Incident Dossier</div>
        <div style="font-size: 12px; color: #94a3b8; font-family: monospace; margin-top: 4px;">ID: ${scan.id} | Generated: ${new Date(scan.timestamp).toUTCString()}</div>
      </div>
      <div>
        <button class="btn-print" onclick="window.print()">Print Document</button>
      </div>
    </div>

    <div class="section">
      <div class="section-title">1. Investigation Summary & Verdict</div>
      <div class="box" style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="font-size: 11px; color: #94a3b8;">TARGET URL</div>
          <div class="code" style="font-size: 14px; margin-top: 4px;">${scan.targetUrl}</div>
        </div>
        <div style="text-align: right;">
          <span class="badge badge-${scan.verdict}">${scan.verdict} Threat</span>
          <div style="font-size: 18px; font-weight: bold; margin-top: 4px;">${scan.overallScore} / 100</div>
        </div>
      </div>
      <p style="font-size: 13px; line-height: 1.6; color: #cbd5e1; margin-top: 14px;">
        ${scan.explanations.analyst}
      </p>
    </div>

    <div class="section">
      <div class="section-title">2. Forensic Indicators (${scan.indicators.length})</div>
      ${scan.indicators.map(ind => `
        <div class="indicator-item">
          <div>
            <strong style="color: #fff;">${ind.title}</strong>
            <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">${ind.detail}</div>
          </div>
          <span style="color: #ef4444; font-family: monospace; font-weight: bold;">+${ind.scoreContribution} pts</span>
        </div>
      `).join('')}
    </div>

    <div class="section">
      <div class="section-title">3. Infrastructure Telemetry</div>
      <div class="grid">
        <div class="box">
          <div style="font-size: 10px; color: #94a3b8;">HOST IP</div>
          <div style="font-family: monospace; font-weight: bold; margin-top: 4px;">${scan.domainIntelligence.ipAddresses[0] || 'Unresolved'}</div>
        </div>
        <div class="box">
          <div style="font-size: 10px; color: #94a3b8;">ASN / TRANSIT</div>
          <div style="font-weight: bold; margin-top: 4px;">${scan.domainIntelligence.asn}</div>
        </div>
        <div class="box">
          <div style="font-size: 10px; color: #94a3b8;">SSL ISSUER</div>
          <div style="font-weight: bold; margin-top: 4px;">${scan.domainIntelligence.ssl.issuer}</div>
        </div>
        <div class="box">
          <div style="font-size: 10px; color: #94a3b8;">DOMAIN AGE</div>
          <div style="font-weight: bold; margin-top: 4px;">${scan.domainIntelligence.ageDays} Days</div>
        </div>
      </div>
    </div>

    <div class="section" style="border: none;">
      <div class="section-title">4. Recommended Remediation Playbook</div>
      <ol style="font-size: 13px; line-height: 1.7; color: #cbd5e1; padding-left: 20px;">
        ${scan.recommendedActions.socPlaybook.map(act => `<li>${act}</li>`).join('')}
      </ol>
    </div>
  </div>
</body>
</html>`;

  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `PhantomTrace_Dossier_${scan.urlIntelligence.domain}.html`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
