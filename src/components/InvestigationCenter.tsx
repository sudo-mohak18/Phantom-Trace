import React, { useState } from 'react';
import {
  Search,
  ShieldAlert,
  ArrowRight,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Globe,
  Server,
  Database,
  Code2,
  Bot,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import { ScanResult } from '../types/scanner';
import { SecurityScoreGauge } from './SecurityScoreGauge';
import { AttackStoryView } from './AttackStoryView';
import { MultiLevelExplanations } from './MultiLevelExplanations';
import { ActiveTab } from './Header';

interface InvestigationCenterProps {
  currentScan: ScanResult | null;
  onScanUrl: (url: string) => Promise<void>;
  onLoadSample: (sampleId: string) => void;
  isScanning: boolean;
  scanStep: number; // 0 to 5
  scanError: string | null;
  setActiveTab: (tab: ActiveTab) => void;
}

const INVESTIGATION_STEPS = [
  {
    step: 1,
    title: 'URL Intelligence',
    subtitle: 'Normalization, domain extraction, Shannon entropy, homoglyph detection',
    icon: Globe,
  },
  {
    step: 2,
    title: 'Domain & Infrastructure',
    subtitle: 'DNS A/MX/NS records, IP geolocation, ASN transit, SSL certificate',
    icon: Server,
  },
  {
    step: 3,
    title: 'Reputation Telemetry',
    subtitle: 'OpenPhish, PhishTank, AbuseIPDB, SafeBrowsing blacklist feeds',
    icon: Database,
  },
  {
    step: 4,
    title: 'Website & DOM Inspection',
    subtitle: 'Static HTML form exfiltration, obfuscated JavaScript, anti-debugging hooks',
    icon: Code2,
  },
  {
    step: 5,
    title: 'AI Threat Assessment',
    subtitle: 'MITRE ATT&CK correlation, multi-tier narrative, risk scoring',
    icon: Bot,
  },
];

export const InvestigationCenter: React.FC<InvestigationCenterProps> = ({
  currentScan,
  onScanUrl,
  onLoadSample,
  isScanning,
  scanStep,
  scanError,
  setActiveTab,
}) => {
  const [inputUrl, setInputUrl] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputUrl.trim()) {
      onScanUrl(inputUrl.trim());
    }
  };

  return (
    <div className="space-y-8">
      {/* Welcome / Hero Section */}
      <div className="relative rounded-3xl p-8 sm:p-12 overflow-hidden border border-slate-800/80 bg-gradient-to-b from-[#0e1424]/90 to-[#07090e]/90 shadow-2xl">
        {/* Ambient background cyber grid glow */}
        <div className="absolute top-0 right-0 -mr-20 -mt-20 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 -ml-20 -mb-20 w-96 h-96 bg-cyan-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-purple-950/60 border border-purple-800/50 text-cyan-300 text-xs font-semibold mb-4">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Autonomous Phishing Detection & Threat Intelligence</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-black text-white tracking-tight leading-tight">
            Don't Trust the Link.{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-indigo-300 to-cyan-400">
              Investigate It.
            </span>
          </h1>

          <p className="mt-4 text-sm sm:text-base text-slate-300 leading-relaxed">
            AI-powered phishing detection and threat intelligence that helps SOC analysts, penetration testers, and everyday users understand what is hiding behind suspicious links.
          </p>

          {/* Central URL Investigation Input Bar */}
          <form onSubmit={handleSubmit} className="mt-8 flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <Search className="w-5 h-5 absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={inputUrl}
                onChange={e => setInputUrl(e.target.value)}
                placeholder="Enter suspicious URL or domain (e.g. paypal-security-verify.top/login)..."
                disabled={isScanning}
                className="w-full bg-[#07090e] border border-slate-700/80 text-sm text-slate-100 placeholder-slate-500 pl-12 pr-4 py-3.5 rounded-2xl focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={isScanning || !inputUrl.trim()}
              className="px-6 py-3.5 rounded-2xl bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white font-bold text-sm disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-950/50 flex items-center justify-center gap-2"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Investigating...</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4" />
                  <span>Investigate Link</span>
                </>
              )}
            </button>
          </form>

          {/* Sample preset buttons */}
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Try Sample Attacks:</span>
            <button
              type="button"
              onClick={() => {
                setInputUrl('https://paypal-security-account.support/verify/auth.php?token=84f29a');
                onLoadSample('sample-paypal-phish');
              }}
              className="px-2.5 py-1 rounded-lg bg-red-950/40 hover:bg-red-900/40 text-red-300 border border-red-800/50 transition-colors"
            >
              🚨 PayPal Phish (Malicious)
            </button>
            <button
              type="button"
              onClick={() => {
                setInputUrl('https://accounts.google.com/signin/v2/identifier');
                onLoadSample('sample-google-clean');
              }}
              className="px-2.5 py-1 rounded-lg bg-emerald-950/40 hover:bg-emerald-900/40 text-emerald-300 border border-emerald-800/50 transition-colors"
            >
              ✅ Google Accounts (Clean)
            </button>
          </div>

          {/* Error Message Display */}
          {scanError && (
            <div className="mt-4 p-4 rounded-xl bg-red-950/60 border border-red-800 text-xs text-red-200 flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-400 mt-0.5" />
              <div>
                <strong className="block font-bold">Investigation Blocked / Failed</strong>
                <span>{scanError}</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Interactive 5-Step Investigation Sequence */}
      {(isScanning || currentScan) && (
        <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-purple-400">
              Interactive Forensics Pipeline (5 Steps)
            </h3>
            {isScanning && (
              <span className="text-xs text-cyan-400 font-mono flex items-center gap-1.5">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Executing Pipeline Step {scanStep} of 5...
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
            {INVESTIGATION_STEPS.map(item => {
              const Icon = item.icon;
              const isCompleted = currentScan && (!isScanning || item.step < scanStep);
              const isCurrent = isScanning && item.step === scanStep;

              return (
                <div
                  key={item.step}
                  className={`p-3.5 rounded-xl border transition-all ${
                    isCurrent
                      ? 'bg-purple-950/50 border-cyan-400 shadow-md shadow-cyan-950/30'
                      : isCompleted
                      ? 'bg-[#0e1424] border-slate-800'
                      : 'bg-[#07090e]/60 border-slate-900 opacity-50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono font-bold text-slate-400">
                      STEP 0{item.step}
                    </span>
                    {isCurrent ? (
                      <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                    ) : isCompleted ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <div className="w-2 h-2 rounded-full bg-slate-800" />
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <Icon className="w-3.5 h-3.5 text-cyan-300" />
                    <h4 className="text-xs font-bold text-white truncate">
                      {item.title}
                    </h4>
                  </div>
                  <p className="text-[10px] text-slate-400 line-clamp-2 leading-relaxed">
                    {item.subtitle}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Investigation Results Display */}
      {currentScan && !isScanning && (
        <div className="space-y-6">
          {/* Threat Score Gauge & Breakdown */}
          <SecurityScoreGauge scan={currentScan} />

          {/* Quick Jump Bar to Advanced Views */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <button
              onClick={() => setActiveTab('explorer')}
              className="p-3.5 rounded-xl bg-[#0e1424] hover:bg-slate-900 border border-slate-800 hover:border-purple-600 transition-all text-left group"
            >
              <div className="flex items-center justify-between text-xs font-bold text-white mb-1">
                <span>Threat Explorer</span>
                <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-0.5" />
              </div>
              <p className="text-[11px] text-slate-400">
                Visual graph of DNS, IP, and infrastructure topology
              </p>
            </button>

            <button
              onClick={() => setActiveTab('code')}
              className="p-3.5 rounded-xl bg-[#0e1424] hover:bg-slate-900 border border-slate-800 hover:border-purple-600 transition-all text-left group"
            >
              <div className="flex items-center justify-between text-xs font-bold text-white mb-1">
                <span>Code Forensics</span>
                <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-0.5" />
              </div>
              <p className="text-[11px] text-slate-400">
                Inspect forms, obfuscated JS, and DOM findings
              </p>
            </button>

            <button
              onClick={() => setActiveTab('analyst')}
              className="p-3.5 rounded-xl bg-[#0e1424] hover:bg-slate-900 border border-slate-800 hover:border-purple-600 transition-all text-left group"
            >
              <div className="flex items-center justify-between text-xs font-bold text-white mb-1">
                <span>AI SOC Analyst</span>
                <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-0.5" />
              </div>
              <p className="text-[11px] text-slate-400">
                Ask Gemini 3.8 Flash about this specific threat
              </p>
            </button>

            <button
              onClick={() => setActiveTab('report')}
              className="p-3.5 rounded-xl bg-[#0e1424] hover:bg-slate-900 border border-slate-800 hover:border-purple-600 transition-all text-left group"
            >
              <div className="flex items-center justify-between text-xs font-bold text-white mb-1">
                <span>Export Report</span>
                <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-0.5" />
              </div>
              <p className="text-[11px] text-slate-400">
                Generate printable PDF, JSON & CSV IOCs
              </p>
            </button>
          </div>

          {/* Attack Story ("What Is This Link Trying To Do?") */}
          <AttackStoryView steps={currentScan.attackStory} verdict={currentScan.verdict} />

          {/* Multi-Level Explanations */}
          <MultiLevelExplanations explanations={currentScan.explanations} verdict={currentScan.verdict} />
        </div>
      )}
    </div>
  );
};
