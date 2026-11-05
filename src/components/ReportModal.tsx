import React, { useState } from 'react';
import {
  FileText,
  Printer,
  Download,
  Share2,
  CheckCircle2,
  AlertTriangle,
  Skull,
  Shield,
  Layers,
  Terminal,
  FileCode,
  Check,
} from 'lucide-react';
import { ScanResult } from '../types/scanner';
import { generatePdfReport, generateHtmlReport } from '../services/pdfReport';

interface ReportModalProps {
  scan: ScanResult;
  onClose?: () => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({ scan }) => {
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setDownloadSuccess(msg);
    setTimeout(() => setDownloadSuccess(null), 3500);
  };

  const handleDownloadPdf = () => {
    try {
      generatePdfReport(scan);
      showNotification('PDF Dossier downloaded successfully!');
    } catch (err) {
      console.error('PDF generation error:', err);
      // Fallback to HTML if PDF engine encountered an issue
      generateHtmlReport(scan);
      showNotification('Downloaded standalone HTML dossier.');
    }
  };

  const handleDownloadHtml = () => {
    try {
      generateHtmlReport(scan);
      showNotification('HTML Report Dossier downloaded successfully!');
    } catch (err) {
      console.error('HTML generation error:', err);
    }
  };

  const handlePrint = () => {
    try {
      window.print();
    } catch (err) {
      // If window.print is blocked by iframe security policy, download PDF directly
      console.warn('window.print() restricted in iframe, falling back to direct PDF download:', err);
      handleDownloadPdf();
    }
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scan, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `PhantomTrace_Report_${scan.urlIntelligence.domain}_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showNotification('JSON raw intelligence exported!');
  };

  const handleDownloadCsvIocs = () => {
    const rows = [
      ['Type', 'Indicator', 'Risk', 'Detail'],
      ['FQDN', scan.urlIntelligence.domain, scan.verdict, `Entropy: ${scan.urlIntelligence.entropyDomain}`],
      ['RootDomain', scan.urlIntelligence.rootDomain, scan.verdict, `TLD: .${scan.urlIntelligence.tld}`],
      ...scan.domainIntelligence.ipAddresses.map(ip => ['IPv4', ip, scan.verdict, `ASN: ${scan.domainIntelligence.asn}`]),
      ...scan.websiteInspection.suspiciousForms.map(f => ['ExfilEndpoint', f.action, 'malicious', 'Credential Form Action']),
    ];

    const csvContent = 'data:text/csv;charset=utf-8,' + rows.map(e => e.map(val => `"${val}"`).join(',')).join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `PhantomTrace_IOCs_${scan.urlIntelligence.domain}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    showNotification('CSV IOC list exported!');
  };

  return (
    <div className="bg-[#0b0f19] border border-slate-800/80 rounded-2xl p-6 sm:p-8 shadow-2xl relative max-w-4xl mx-auto print:border-none print:shadow-none print:bg-white print:text-black">
      {/* Top Report Controls (Hidden during print) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800/80 no-print">
        <div className="flex items-center space-x-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          <span className="text-sm font-bold text-white uppercase tracking-wider">
            PhantomTrace AI Incident Dossier
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Primary Direct PDF Download Button */}
          <button
            onClick={handleDownloadPdf}
            className="px-3.5 py-1.5 text-xs font-bold rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white flex items-center gap-1.5 transition-all shadow-md shadow-purple-950/50"
            title="Generate and download PDF document directly"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF</span>
          </button>

          {/* Standalone HTML Report */}
          <button
            onClick={handleDownloadHtml}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
            title="Download offline-compatible HTML dossier"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Download HTML</span>
          </button>

          {/* Print / System Dialog */}
          <button
            onClick={handlePrint}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors"
            title="Open browser print dialog"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print</span>
          </button>

          {/* JSON Export */}
          <button
            onClick={handleDownloadJson}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
          >
            <span>JSON</span>
          </button>

          {/* CSV IOC Export */}
          <button
            onClick={handleDownloadCsvIocs}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-purple-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
          >
            <Terminal className="w-3 h-3" />
            <span>CSV IOCs</span>
          </button>
        </div>
      </div>

      {/* Success Notification Banner */}
      {downloadSuccess && (
        <div className="mt-4 p-3 rounded-xl bg-emerald-950/80 border border-emerald-700/80 text-xs text-emerald-300 flex items-center gap-2 no-print">
          <Check className="w-4 h-4 text-emerald-400" />
          <span>{downloadSuccess}</span>
        </div>
      )}

      {/* Printable Report Header */}
      <div className="pt-6 pb-6 border-b border-slate-800/80 print:border-slate-300">
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-xl sm:text-2xl font-black text-white print:text-black tracking-tight">
              CYBERSECURITY THREAT INTELLIGENCE DOSSIER
            </h1>
            <p className="text-xs text-slate-400 print:text-slate-600 font-mono mt-1">
              Document ID: {scan.id} | Generated: {new Date(scan.timestamp).toUTCString()}
            </p>
          </div>
          <div className="text-right">
            <span className="text-xs font-mono font-bold text-cyan-400 print:text-purple-700">
              PhantomTrace AI SecOps
            </span>
            <span className="block text-[10px] text-slate-500">
              Classification: TLP:AMBER+STRICT
            </span>
          </div>
        </div>
      </div>

      {/* Executive Summary Card */}
      <div className="py-6 border-b border-slate-800/80 print:border-slate-300">
        <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-purple-400 print:text-purple-800 mb-3">
          1. Executive Summary & Verdict
        </h2>

        <div className="bg-[#0e1424] print:bg-slate-50 border border-slate-800 print:border-slate-300 rounded-xl p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-400 print:text-slate-600">
                Target URL Under Investigation
              </span>
              <p className="text-sm font-mono font-bold text-cyan-300 print:text-cyan-800 break-all">
                {scan.targetUrl}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className={`px-3 py-1 text-xs font-extrabold uppercase rounded-lg border ${
                scan.verdict === 'malicious'
                  ? 'bg-red-950/80 border-red-700 text-red-300 print:text-red-700 print:bg-red-100'
                  : scan.verdict === 'suspicious'
                  ? 'bg-amber-950/80 border-amber-700 text-amber-300 print:text-amber-700 print:bg-amber-100'
                  : 'bg-emerald-950/80 border-emerald-700 text-emerald-300 print:text-emerald-700 print:bg-emerald-100'
              }`}>
                {scan.verdict} Threat
              </span>
              <div className="text-right">
                <span className="text-lg font-bold text-white print:text-black">
                  {scan.overallScore}/100
                </span>
                <span className="text-[10px] text-slate-400 block font-mono">Risk Index</span>
              </div>
            </div>
          </div>

          <p className="text-xs text-slate-300 print:text-slate-800 leading-relaxed">
            {scan.explanations.analyst}
          </p>
        </div>
      </div>

      {/* Technical Evidence & Indicators */}
      <div className="py-6 border-b border-slate-800/80 print:border-slate-300">
        <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-purple-400 print:text-purple-800 mb-3">
          2. Forensic Indicators & Telemetry
        </h2>

        <div className="space-y-2">
          {scan.indicators.map((ind, i) => (
            <div
              key={i}
              className="bg-[#0e1424] print:bg-slate-50 border border-slate-800 print:border-slate-300 p-3 rounded-lg text-xs flex justify-between gap-4"
            >
              <div>
                <span className="font-bold text-white print:text-black">{ind.title}</span>
                <span className="text-slate-400 print:text-slate-600 block mt-0.5">{ind.detail}</span>
              </div>
              <span className="font-mono text-cyan-400 print:text-purple-700 font-bold flex-shrink-0">
                +{ind.scoreContribution} pts
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Infrastructure Details */}
      <div className="py-6 border-b border-slate-800/80 print:border-slate-300">
        <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-purple-400 print:text-purple-800 mb-3">
          3. Infrastructure & Cryptographic Profile
        </h2>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="bg-[#0e1424] print:bg-slate-50 p-3 rounded-lg border border-slate-800 print:border-slate-300">
            <span className="text-[10px] font-mono text-slate-400 print:text-slate-600 block">Host IPv4</span>
            <strong className="text-slate-200 print:text-slate-900 font-mono mt-0.5 block break-all">
              {scan.domainIntelligence.ipAddresses[0] || 'Unresolved'}
            </strong>
          </div>

          <div className="bg-[#0e1424] print:bg-slate-50 p-3 rounded-lg border border-slate-800 print:border-slate-300">
            <span className="text-[10px] font-mono text-slate-400 print:text-slate-600 block">ASN / Transit</span>
            <strong className="text-slate-200 print:text-slate-900 font-mono mt-0.5 block truncate">
              {scan.domainIntelligence.asn}
            </strong>
          </div>

          <div className="bg-[#0e1424] print:bg-slate-50 p-3 rounded-lg border border-slate-800 print:border-slate-300">
            <span className="text-[10px] font-mono text-slate-400 print:text-slate-600 block">SSL / TLS Issuer</span>
            <strong className="text-slate-200 print:text-slate-900 font-mono mt-0.5 block truncate">
              {scan.domainIntelligence.ssl.issuer}
            </strong>
          </div>

          <div className="bg-[#0e1424] print:bg-slate-50 p-3 rounded-lg border border-slate-800 print:border-slate-300">
            <span className="text-[10px] font-mono text-slate-400 print:text-slate-600 block">Domain Age</span>
            <strong className="text-slate-200 print:text-slate-900 font-mono mt-0.5 block">
              {scan.domainIntelligence.ageDays} Days
            </strong>
          </div>
        </div>
      </div>

      {/* Remediation & Actionable Playbook */}
      <div className="pt-6">
        <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-purple-400 print:text-purple-800 mb-3">
          4. Recommended SOC Remediation Playbook
        </h2>

        <div className="space-y-2">
          {scan.recommendedActions.socPlaybook.map((action, idx) => (
            <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-300 print:text-slate-800">
              <span className="w-5 h-5 rounded-full bg-slate-800 print:bg-slate-200 text-cyan-400 print:text-purple-700 flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0 mt-0.5">
                {idx + 1}
              </span>
              <p className="leading-relaxed">{action}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-8 pt-4 border-t border-slate-800/80 print:border-slate-300 text-[10px] text-slate-500 font-mono text-center">
        Report compiled by PhantomTrace AI Threat Intelligence Engine. All telemetry verified against deterministic baselines.
      </div>
    </div>
  );
};
