import React from 'react';
import { Compass, Eye, ShieldAlert, ArrowRight, CheckCircle2 } from 'lucide-react';
import { AttackStoryStep } from '../types/scanner';

interface AttackStoryViewProps {
  steps: AttackStoryStep[];
  verdict: 'clean' | 'suspicious' | 'malicious';
}

export const AttackStoryView: React.FC<AttackStoryViewProps> = ({ steps, verdict }) => {
  const isClean = verdict === 'clean';

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl relative overflow-hidden">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-purple-950/60 border border-purple-800/50 text-cyan-400">
            <Compass className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
              What Is This Link Trying To Do?
              <span className="text-xs font-normal text-purple-400 font-mono">
                [ATTACK STORY FORENSICS]
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Chronological attack narrative distinguishing observed evidence from inferred attacker intent.
            </p>
          </div>
        </div>

        <div className="hidden sm:flex items-center space-x-3 text-[11px]">
          <span className="flex items-center gap-1.5 text-cyan-400 bg-cyan-950/40 border border-cyan-800/40 px-2 py-0.5 rounded">
            <Eye className="w-3 h-3" />
            <span>Observed Evidence</span>
          </span>
          <span className="flex items-center gap-1.5 text-purple-400 bg-purple-950/40 border border-purple-800/40 px-2 py-0.5 rounded">
            <Compass className="w-3 h-3" />
            <span>Inferred Intent</span>
          </span>
        </div>
      </div>

      <div className="space-y-4 relative before:absolute before:inset-0 before:left-5 before:w-0.5 before:bg-slate-800/80">
        {steps.map((step, idx) => (
          <div key={step.step} className="relative flex items-start gap-4 pl-2">
            {/* Step Number Circle */}
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold font-mono z-10 flex-shrink-0 border shadow-md ${
              isClean
                ? 'bg-emerald-950 border-emerald-600 text-emerald-300'
                : 'bg-purple-950 border-purple-600 text-cyan-300'
            }`}>
              {isClean ? <CheckCircle2 className="w-4 h-4" /> : step.step}
            </div>

            {/* Step Card Content */}
            <div className="flex-1 bg-[#0e1424]/80 border border-slate-800/90 rounded-xl p-4 transition-all hover:border-slate-700">
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <h4 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                  <span>{step.title}</span>
                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700/80 text-slate-400">
                    Phase: {step.type}
                  </span>
                </h4>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed mb-3">
                {step.description}
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs pt-2 border-t border-slate-800/60">
                <div className="bg-[#07090e]/80 p-2.5 rounded-lg border border-cyan-900/30">
                  <span className="text-[10px] uppercase font-bold text-cyan-400 tracking-wider flex items-center gap-1 mb-1">
                    <Eye className="w-3 h-3" />
                    Observed Evidence (Facts)
                  </span>
                  <p className="text-slate-300 font-mono text-[11px] leading-relaxed">
                    {step.observedEvidence}
                  </p>
                </div>

                <div className="bg-[#07090e]/80 p-2.5 rounded-lg border border-purple-900/30">
                  <span className="text-[10px] uppercase font-bold text-purple-400 tracking-wider flex items-center gap-1 mb-1">
                    <Compass className="w-3 h-3" />
                    Inferred Attacker Intent
                  </span>
                  <p className="text-slate-300 text-[11px] leading-relaxed">
                    {step.inferredIntent}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
