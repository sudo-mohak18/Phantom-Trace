import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Skull,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Target,
  Activity,
  Layers,
} from 'lucide-react';
import { ScanResult } from '../types/scanner';

interface SecurityScoreGaugeProps {
  scan: ScanResult;
}

export const SecurityScoreGauge: React.FC<SecurityScoreGaugeProps> = ({ scan }) => {
  const [showIndicators, setShowIndicators] = useState(true);

  const { overallScore, verdict, confidence, category, indicators, mitreMapping } = scan;

  // Determine color accents based on verdict
  const isClean = verdict === 'clean';
  const isSuspicious = verdict === 'suspicious';
  const isMalicious = verdict === 'malicious';

  const strokeColor = isClean
    ? '#10b981' // emerald-500
    : isSuspicious
    ? '#f59e0b' // amber-500
    : '#ef4444'; // red-500

  const badgeBg = isClean
    ? 'bg-emerald-950/60 border-emerald-700/60 text-emerald-300'
    : isSuspicious
    ? 'bg-amber-950/60 border-amber-700/60 text-amber-300'
    : 'bg-red-950/60 border-red-700/60 text-red-300';

  // SVG Gauge calculations
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const progressOffset = circumference - (overallScore / 100) * circumference;

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl relative overflow-hidden">
      {/* Subtle background radar glow */}
      <div
        className="absolute -top-24 -right-24 w-64 h-64 rounded-full pointer-events-none opacity-20 blur-3xl"
        style={{
          background: isClean
            ? 'radial-gradient(circle, #10b981 0%, transparent 70%)'
            : isSuspicious
            ? 'radial-gradient(circle, #f59e0b 0%, transparent 70%)'
            : 'radial-gradient(circle, #ef4444 0%, transparent 70%)',
        }}
      />

      <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
        {/* Left: Gauge Circle & Overall Classification */}
        <div className="flex items-center gap-6">
          <div className="relative w-32 h-32 flex-shrink-0 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 130 130">
              {/* Background circle track */}
              <circle
                cx="65"
                cy="65"
                r={radius}
                className="stroke-slate-800"
                strokeWidth="10"
                fill="transparent"
              />
              {/* Animated Progress Circle */}
              <circle
                cx="65"
                cy="65"
                r={radius}
                stroke={strokeColor}
                strokeWidth="10"
                strokeDasharray={circumference}
                strokeDashoffset={progressOffset}
                strokeLinecap="round"
                fill="transparent"
                style={{ transition: 'stroke-dashoffset 1s ease-in-out' }}
              />
            </svg>

            {/* Score inside circle */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-3xl font-extrabold tracking-tight text-white">
                {overallScore}
              </span>
              <span className="text-[10px] font-medium uppercase tracking-wider text-slate-400">
                / 100
              </span>
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className={`px-2.5 py-1 text-xs font-bold uppercase tracking-wider rounded-md border flex items-center gap-1.5 ${badgeBg}`}>
                {isClean && <ShieldCheck className="w-3.5 h-3.5" />}
                {isSuspicious && <AlertTriangle className="w-3.5 h-3.5" />}
                {isMalicious && <Skull className="w-3.5 h-3.5" />}
                {verdict.toUpperCase()} THREAT
              </span>
              <span className="text-xs text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                Confidence: <strong className="text-slate-200 capitalize">{confidence}</strong>
              </span>
            </div>

            <h2 className="text-lg font-bold text-white tracking-tight">
              {category}
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-md">
              {isClean
                ? 'Target satisfies trusted infrastructure benchmarks. No active phishing signatures or suspicious cross-origin forms detected.'
                : isSuspicious
                ? 'Target exhibits anomalous characteristics such as high entropy, recent registration, or unverified redirectors.'
                : 'Target exhibits high-confidence malicious artifacts including brand impersonation, deceptive homoglyphs, or unauthorized credential harvesting.'}
            </p>
          </div>
        </div>

        {/* Right: Quick telemetry stats */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 w-full lg:w-auto">
          <div className="bg-[#0e1424] border border-slate-800/80 rounded-xl p-3 text-center">
            <span className="text-[11px] text-slate-400 block font-medium">Indicators</span>
            <span className="text-lg font-bold text-cyan-300 mt-0.5 block">{indicators.length}</span>
            <span className="text-[10px] text-slate-500">Heuristics active</span>
          </div>

          <div className="bg-[#0e1424] border border-slate-800/80 rounded-xl p-3 text-center">
            <span className="text-[11px] text-slate-400 block font-medium">Reputation</span>
            <span className={`text-lg font-bold mt-0.5 block ${isClean ? 'text-emerald-400' : 'text-red-400'}`}>
              {isClean ? '6/6 Clean' : 'Blacklisted'}
            </span>
            <span className="text-[10px] text-slate-500">Global feeds</span>
          </div>

          <div className="bg-[#0e1424] border border-slate-800/80 rounded-xl p-3 text-center col-span-2 sm:col-span-1">
            <span className="text-[11px] text-slate-400 block font-medium">Domain Age</span>
            <span className="text-lg font-bold text-purple-300 mt-0.5 block">
              {scan.domainIntelligence.ageDays > 365
                ? `${Math.round(scan.domainIntelligence.ageDays / 365)} yrs`
                : `${scan.domainIntelligence.ageDays} days`}
            </span>
            <span className="text-[10px] text-slate-500">{scan.domainIntelligence.registrar.split(' ')[0]}</span>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix alignment chips */}
      {mitreMapping.length > 0 && (
        <div className="mt-5 pt-4 border-t border-slate-800/80">
          <div className="flex items-center gap-2 mb-2">
            <Target className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-xs font-semibold text-slate-300 tracking-wide uppercase">
              MITRE ATT&CK Framework Mapping
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {mitreMapping.map(m => (
              <div
                key={m.id}
                className="px-2.5 py-1 text-xs bg-purple-950/40 border border-purple-800/50 rounded-lg text-purple-200 flex items-center gap-1.5"
              >
                <span className="font-mono font-bold text-cyan-400">{m.id}</span>
                <span className="text-slate-400">|</span>
                <span>{m.tactic}: {m.technique}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Contributing Indicators Breakdown Toggle */}
      <div className="mt-5 pt-4 border-t border-slate-800/80">
        <button
          onClick={() => setShowIndicators(!showIndicators)}
          className="w-full flex items-center justify-between text-xs font-semibold text-slate-300 hover:text-white transition-colors"
        >
          <div className="flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Contributing Risk Indicators Breakdown ({indicators.length})</span>
          </div>
          {showIndicators ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </button>

        {showIndicators && (
          <div className="mt-3 space-y-2">
            {indicators.map(ind => {
              const isHigh = ind.severity === 'high';
              const isMed = ind.severity === 'medium';
              return (
                <div
                  key={ind.id}
                  className="bg-[#0e1424]/60 border border-slate-800 rounded-xl p-3 flex items-start justify-between gap-4 transition-all hover:border-slate-700"
                >
                  <div className="flex items-start gap-2.5">
                    <span
                      className={`px-1.5 py-0.5 text-[10px] font-bold rounded uppercase mt-0.5 ${
                        isHigh
                          ? 'bg-red-950/80 text-red-300 border border-red-800/60'
                          : isMed
                          ? 'bg-amber-950/80 text-amber-300 border border-amber-800/60'
                          : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                      }`}
                    >
                      {ind.severity}
                    </span>
                    <div>
                      <h4 className="text-xs font-semibold text-slate-200">{ind.title}</h4>
                      <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{ind.detail}</p>
                    </div>
                  </div>
                  {ind.scoreContribution > 0 && (
                    <span className="text-xs font-mono font-bold text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-900/40 flex-shrink-0">
                      +{ind.scoreContribution} pts
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
