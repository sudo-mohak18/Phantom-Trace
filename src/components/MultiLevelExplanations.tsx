import React, { useState } from 'react';
import { User, Terminal, ShieldAlert, Copy, Check, Info } from 'lucide-react';
import { Explanations, ThreatVerdict } from '../types/scanner';

interface MultiLevelExplanationsProps {
  explanations: Explanations;
  verdict: ThreatVerdict;
}

export const MultiLevelExplanations: React.FC<MultiLevelExplanationsProps> = ({
  explanations,
  verdict,
}) => {
  const [level, setLevel] = useState<'beginner' | 'technical' | 'analyst'>('beginner');
  const [copied, setCopied] = useState(false);

  const activeText = explanations[level];

  const handleCopy = () => {
    navigator.clipboard.writeText(activeText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl relative">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            Multi-Level Security Explanations
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Select your preferred technical depth to understand the threat findings.
          </p>
        </div>

        {/* Level Switcher Tabs */}
        <div className="flex items-center bg-[#07090e] p-1 rounded-xl border border-slate-800 self-start sm:self-auto">
          <button
            onClick={() => setLevel('beginner')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-all ${
              level === 'beginner'
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <User className="w-3.5 h-3.5" />
            <span>Beginner</span>
          </button>

          <button
            onClick={() => setLevel('technical')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-all ${
              level === 'technical'
                ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-700/60 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Technical</span>
          </button>

          <button
            onClick={() => setLevel('analyst')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-all ${
              level === 'analyst'
                ? 'bg-purple-950/80 text-purple-300 border border-purple-700/60 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>SOC Analyst</span>
          </button>
        </div>
      </div>

      {/* Content Display Card */}
      <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-4 relative">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-cyan-400" />
            {level === 'beginner' && 'Non-Technical Everyday Explanation'}
            {level === 'technical' && 'Protocol, DOM & Encoding Forensics'}
            {level === 'analyst' && 'Incident Response Playbook & MITRE Mapping'}
          </span>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800/60 hover:bg-slate-700/60 transition-colors"
            title="Copy explanation"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>

        <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-sans whitespace-pre-line">
          {activeText}
        </p>
      </div>
    </div>
  );
};
