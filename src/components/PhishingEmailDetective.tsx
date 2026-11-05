import React, { useState } from 'react';
import {
  Mail,
  Upload,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Paperclip,
  FileCode,
  ShieldAlert,
  Sparkles,
  ArrowRight,
  Terminal,
} from 'lucide-react';
import { EmailScanResult } from '../types/scanner';
import { SAMPLE_PHISHING_EMAIL } from '../services/emailForensics';

interface PhishingEmailDetectiveProps {
  onScanUrlRequested?: (url: string) => void;
}

export const PhishingEmailDetective: React.FC<PhishingEmailDetectiveProps> = ({
  onScanUrlRequested,
}) => {
  const [rawText, setRawText] = useState('');
  const [scanResult, setScanResult] = useState<EmailScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (contentToScan?: string) => {
    const text = (contentToScan !== undefined ? contentToScan : rawText).trim();
    if (!text) {
      setError('Please paste raw email headers or an .eml message to investigate.');
      return;
    }

    setError(null);
    setIsScanning(true);

    try {
      const res = await fetch('/api/email-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawContent: text }),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status}`);
      }

      const result = await res.json();
      setScanResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadSample = () => {
    setRawText(SAMPLE_PHISHING_EMAIL);
    handleScan(SAMPLE_PHISHING_EMAIL);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = ev => {
      const text = ev.target?.result as string;
      if (text) {
        setRawText(text);
        handleScan(text);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl relative">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <Mail className="w-5 h-5 text-cyan-400" />
            Phishing Email Detective
          </h3>
          <p className="text-xs text-slate-400">
            Forensic analysis of raw .eml files, RFC 822 email headers, SPF/DKIM/DMARC, Reply-To mismatches, and attachments.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <label className="cursor-pointer px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 flex items-center gap-1.5 transition-colors">
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Upload .eml File</span>
            <input
              type="file"
              accept=".eml,.txt"
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>

          <button
            onClick={handleLoadSample}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-amber-950/40 hover:bg-amber-900/40 border border-amber-800/50 text-amber-300 flex items-center gap-1.5 transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Load Phishing Sample</span>
          </button>
        </div>
      </div>

      {/* Input Text Area */}
      <div className="mb-6">
        <textarea
          rows={5}
          value={rawText}
          onChange={e => setRawText(e.target.value)}
          placeholder="Paste raw email headers or full .eml content here (e.g., Delivered-To, Authentication-Results, From, Reply-To)..."
          className="w-full bg-[#07090e] border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
        />

        <div className="flex items-center justify-between mt-2">
          <div className="text-[11px] text-slate-500">
            * Header parsing strips personal identifiers and tests authentication cryptographic proofs.
          </div>
          <button
            onClick={() => handleScan()}
            disabled={isScanning || !rawText.trim()}
            className="px-4 py-2 text-xs font-bold rounded-xl bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white disabled:opacity-40 transition-all flex items-center gap-2"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>{isScanning ? 'Analyzing Headers...' : 'Investigate Email Headers'}</span>
          </button>
        </div>

        {error && (
          <div className="mt-3 p-3 bg-red-950/40 border border-red-800/60 rounded-xl text-xs text-red-300">
            {error}
          </div>
        )}
      </div>

      {/* Scan Results View */}
      {scanResult && (
        <div className="space-y-6 pt-6 border-t border-slate-800/80">
          {/* Top Email Threat Score Banner */}
          <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className={`w-14 h-14 rounded-2xl flex flex-col items-center justify-center font-bold text-lg border ${
                scanResult.riskScore >= 60
                  ? 'bg-red-950/80 border-red-700 text-red-300'
                  : scanResult.riskScore >= 30
                  ? 'bg-amber-950/80 border-amber-700 text-amber-300'
                  : 'bg-emerald-950/80 border-emerald-700 text-emerald-300'
              }`}>
                <span>{scanResult.riskScore}</span>
                <span className="text-[9px] uppercase font-normal text-slate-400">/ 100</span>
              </div>
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  Email Threat Score
                </span>
                <h4 className="text-sm font-bold text-white mt-0.5">
                  {scanResult.summary}
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Subject: <strong className="text-slate-200">{scanResult.subject}</strong>
                </p>
              </div>
            </div>

            {/* Authentication Protocol Badges (SPF, DKIM, DMARC) */}
            <div className="flex items-center gap-2">
              {[
                { label: 'SPF', val: scanResult.authentication.spf.status },
                { label: 'DKIM', val: scanResult.authentication.dkim.status },
                { label: 'DMARC', val: scanResult.authentication.dmarc.status },
              ].map(auth => (
                <div
                  key={auth.label}
                  className={`px-3 py-1 rounded-lg border text-xs font-mono font-bold flex items-center gap-1.5 ${
                    auth.val === 'pass'
                      ? 'bg-emerald-950/60 border-emerald-700/60 text-emerald-300'
                      : auth.val === 'fail'
                      ? 'bg-red-950/60 border-red-700/60 text-red-300'
                      : 'bg-slate-900 border-slate-800 text-slate-400'
                  }`}
                >
                  {auth.val === 'pass' && <CheckCircle2 className="w-3.5 h-3.5" />}
                  {auth.val === 'fail' && <XCircle className="w-3.5 h-3.5" />}
                  {auth.label}: {auth.val.toUpperCase()}
                </div>
              ))}
            </div>
          </div>

          {/* Reply-To Mismatch Alert */}
          {scanResult.replyToMismatch && (
            <div className="bg-red-950/40 border border-red-800/80 rounded-xl p-4 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-bold text-red-300 uppercase tracking-wide">
                  CRITICAL: Reply-To Address Mismatch Detected
                </h4>
                <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                  The sender claims to be <strong className="text-white font-mono">{scanResult.claimedSender.email}</strong>,
                  but replies will be silently redirected to <strong className="text-red-400 font-mono">{scanResult.replyTo}</strong>.
                  This is a signature technique used in Business Email Compromise (BEC) and financial credential theft.
                </p>
              </div>
            </div>
          )}

          {/* Sender Infrastructure Comparison Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-3.5">
              <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block mb-1">
                Claimed Sender (From:)
              </span>
              <p className="text-xs font-bold text-white break-all">
                {scanResult.claimedSender.name}
              </p>
              <p className="text-xs font-mono text-cyan-300 break-all mt-0.5">
                {scanResult.claimedSender.email}
              </p>
            </div>

            <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-3.5">
              <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block mb-1">
                Return-Path (Actual Mail Server)
              </span>
              <p className="text-xs font-mono text-purple-300 break-all">
                {scanResult.returnPath}
              </p>
              <span className="text-[10px] text-slate-500 mt-1 block">
                Authenticated Domain: {scanResult.authenticatedDomain}
              </span>
            </div>

            <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-3.5">
              <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block mb-1">
                Reply Destination (Reply-To:)
              </span>
              <p className={`text-xs font-mono break-all font-bold ${scanResult.replyToMismatch ? 'text-red-400' : 'text-slate-200'}`}>
                {scanResult.replyTo || 'Same as Sender'}
              </p>
              <span className="text-[10px] text-slate-500 mt-1 block">
                {scanResult.replyToMismatch ? 'Hijack destination' : 'Standard alignment'}
              </span>
            </div>
          </div>

          {/* Extracted Hyperlinks and Attachments */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Embedded URLs */}
            <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold text-white uppercase tracking-wide flex items-center gap-1.5">
                  <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                  Extracted Links ({scanResult.extractedUrls.length})
                </span>
              </div>

              {scanResult.extractedUrls.length === 0 ? (
                <p className="text-xs text-slate-400">No embedded URLs found in message.</p>
              ) : (
                <div className="space-y-2 max-h-52 overflow-y-auto">
                  {scanResult.extractedUrls.map((link, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 bg-[#07090e] border border-slate-800 rounded-lg text-xs flex items-center justify-between gap-3"
                    >
                      <div className="overflow-hidden">
                        <p className="font-mono text-slate-200 truncate">{link.url}</p>
                        {link.reason && (
                          <span className="text-[10px] text-red-400 font-medium block mt-0.5">
                            {link.reason}
                          </span>
                        )}
                      </div>
                      {onScanUrlRequested && (
                        <button
                          onClick={() => onScanUrlRequested(link.url)}
                          className="px-2 py-1 bg-purple-900/40 hover:bg-purple-800/40 border border-purple-700/60 rounded text-[11px] text-cyan-300 font-semibold whitespace-nowrap"
                        >
                          Scan in PhantomTrace
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Attachments */}
            <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold text-white uppercase tracking-wide flex items-center gap-1.5">
                  <Paperclip className="w-3.5 h-3.5 text-purple-400" />
                  Attachments ({scanResult.attachments.length})
                </span>
              </div>

              {scanResult.attachments.length === 0 ? (
                <p className="text-xs text-slate-400">No attachments detected in this header payload.</p>
              ) : (
                <div className="space-y-2 max-h-52 overflow-y-auto">
                  {scanResult.attachments.map((att, idx) => (
                    <div
                      key={idx}
                      className={`p-2.5 rounded-lg border text-xs flex items-center justify-between ${
                        att.isRisky
                          ? 'bg-red-950/30 border-red-800 text-red-300'
                          : 'bg-[#07090e] border-slate-800 text-slate-300'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <FileCode className="w-4 h-4 flex-shrink-0" />
                        <div>
                          <p className="font-mono font-bold">{att.filename}</p>
                          {att.riskDetail && (
                            <span className="text-[10px] text-red-400 block mt-0.5">
                              {att.riskDetail}
                            </span>
                          )}
                        </div>
                      </div>
                      <span className="text-[10px] font-mono bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                        {att.isRisky ? 'DANGEROUS' : 'INSPECT'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
