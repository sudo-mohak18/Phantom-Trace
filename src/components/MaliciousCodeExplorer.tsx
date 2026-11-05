import React, { useState } from 'react';
import {
  Code2,
  FileCode,
  AlertTriangle,
  Eye,
  CheckCircle2,
  Terminal,
  ShieldAlert,
  HelpCircle,
  Copy,
  Check,
} from 'lucide-react';
import { WebsiteInspection, SuspiciousScript, SuspiciousForm } from '../types/scanner';

interface MaliciousCodeExplorerProps {
  inspection: WebsiteInspection;
  verdict: 'clean' | 'suspicious' | 'malicious';
}

export const MaliciousCodeExplorer: React.FC<MaliciousCodeExplorerProps> = ({
  inspection,
  verdict,
}) => {
  const [viewMode, setViewMode] = useState<'technical' | 'simple'>('technical');
  const [selectedScriptIndex, setSelectedScriptIndex] = useState<number>(0);
  const [copied, setCopied] = useState(false);

  const { suspiciousScripts, suspiciousForms, hiddenElements, externalResources } = inspection;
  const activeScript = suspiciousScripts[selectedScriptIndex];

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const hasFindings =
    suspiciousScripts.length > 0 ||
    suspiciousForms.length > 0 ||
    hiddenElements.length > 0;

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl relative">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <Code2 className="w-5 h-5 text-cyan-400" />
            Malicious Code & DOM Forensics
          </h3>
          <p className="text-xs text-slate-400">
            Static analysis of HTML forms, obfuscated JavaScript, anti-debugging hooks, and exfiltration logic.
          </p>
        </div>

        {/* View mode toggle */}
        <div className="flex items-center bg-[#07090e] p-1 rounded-xl border border-slate-800 text-xs self-start sm:self-auto">
          <button
            onClick={() => setViewMode('technical')}
            className={`px-3 py-1.5 font-semibold rounded-lg flex items-center gap-1.5 transition-all ${
              viewMode === 'technical'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Technical View</span>
          </button>
          <button
            onClick={() => setViewMode('simple')}
            className={`px-3 py-1.5 font-semibold rounded-lg flex items-center gap-1.5 transition-all ${
              viewMode === 'simple'
                ? 'bg-purple-950 text-purple-300 border border-purple-800/60'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <HelpCircle className="w-3.5 h-3.5" />
            <span>Simple Explanation</span>
          </button>
        </div>
      </div>

      {!hasFindings ? (
        <div className="bg-[#0e1424] border border-slate-800/80 rounded-xl p-8 text-center">
          <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
          <h4 className="text-sm font-bold text-white">No Suspicious Code Artifacts Detected</h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
            Static inspection found no unauthorized credential form actions, unvetted eval() payloads, or anti-debugging keyboard traps on this endpoint.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Findings Navigation List */}
          <div className="space-y-4">
            {/* Suspicious Forms Section */}
            {suspiciousForms.length > 0 && (
              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-red-400 font-bold block mb-2">
                  Credential Collection Forms ({suspiciousForms.length})
                </span>
                <div className="space-y-2">
                  {suspiciousForms.map((form, i) => (
                    <div
                      key={`form-${i}`}
                      className="bg-[#0e1424] border border-red-900/40 rounded-xl p-3"
                    >
                      <div className="flex items-center gap-1.5 text-xs font-bold text-red-400 mb-1">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>External Action Endpoint</span>
                      </div>
                      <p className="text-xs font-mono text-slate-200 break-all bg-slate-900/80 p-2 rounded border border-slate-800 mb-2">
                        {form.action}
                      </p>
                      <div className="text-[11px] text-slate-400">
                        Method: <strong className="text-white">{form.method}</strong> | Fields: <strong className="text-cyan-300 font-mono">[{form.inputTypes.join(', ')}]</strong>
                      </div>
                      <p className="text-[11px] text-amber-300/90 mt-1.5">
                        {form.flaggedReason}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Suspicious Scripts Section */}
            {suspiciousScripts.length > 0 && (
              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-amber-400 font-bold block mb-2">
                  Suspicious Scripts ({suspiciousScripts.length})
                </span>
                <div className="space-y-2">
                  {suspiciousScripts.map((script, idx) => (
                    <button
                      key={`script-btn-${idx}`}
                      onClick={() => setSelectedScriptIndex(idx)}
                      className={`w-full text-left p-3 rounded-xl border transition-all ${
                        selectedScriptIndex === idx
                          ? 'bg-purple-950/40 border-purple-600 text-white shadow-sm'
                          : 'bg-[#0e1424] border-slate-800 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs font-bold mb-1">
                        <span className="flex items-center gap-1.5 text-cyan-300">
                          <FileCode className="w-3.5 h-3.5" />
                          Line {script.lineNumber || 'Inline'}
                        </span>
                        <span className="px-1.5 py-0.5 text-[10px] uppercase rounded font-mono bg-red-950 text-red-300 border border-red-800/60">
                          {script.risk} Risk
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 truncate font-mono">
                        {script.snippet}
                      </p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Hidden Elements Section */}
            {hiddenElements.length > 0 && (
              <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-3">
                <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-bold block mb-2">
                  Hidden DOM Elements
                </span>
                {hiddenElements.map((el, i) => (
                  <div key={i} className="text-xs text-slate-300 flex items-center justify-between py-1 border-b border-slate-800/60 last:border-0">
                    <code className="text-cyan-400 font-mono">{el.tag}</code>
                    <span className="text-slate-400 text-[11px]">{el.reason}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Detailed Code Inspector Area */}
          <div className="lg:col-span-2 bg-[#07090e] border border-slate-800 rounded-xl overflow-hidden flex flex-col justify-between">
            {activeScript ? (
              <div className="p-5 flex-1 flex flex-col">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                  <div>
                    <span className="text-[11px] font-mono text-cyan-400 font-bold uppercase">
                      Script Pattern Analysis (Line {activeScript.lineNumber || 'Inline'})
                    </span>
                    <h4 className="text-sm font-bold text-white mt-0.5">
                      {activeScript.suspiciousPattern}
                    </h4>
                  </div>
                  <button
                    onClick={() => handleCopyCode(activeScript.snippet)}
                    className="flex items-center gap-1 text-xs text-slate-400 hover:text-white px-2.5 py-1 rounded bg-slate-900 border border-slate-800 transition-colors"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy Snippet'}</span>
                  </button>
                </div>

                {viewMode === 'technical' ? (
                  <div className="space-y-4 flex-1">
                    {/* Code display with line numbers */}
                    <div className="bg-[#0b0f19] border border-slate-800/90 rounded-lg p-3 font-mono text-xs overflow-x-auto">
                      <div className="flex gap-3 text-slate-300">
                        <span className="text-slate-600 select-none border-r border-slate-800 pr-3">
                          {activeScript.lineNumber || 1}
                        </span>
                        <code className="text-amber-300 whitespace-pre-wrap break-all">
                          {activeScript.snippet}
                        </code>
                      </div>
                    </div>

                    {/* Decoded payload if available */}
                    {activeScript.decodedPayload && (
                      <div className="bg-[#0b0f19] border border-purple-900/40 rounded-lg p-3">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400 font-bold block mb-1">
                          Decoded Payload Output (De-obfuscated)
                        </span>
                        <pre className="font-mono text-xs text-cyan-300 whitespace-pre-wrap break-all bg-[#07090e] p-2 rounded border border-slate-800">
                          {activeScript.decodedPayload}
                        </pre>
                      </div>
                    )}

                    <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3 text-xs">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold block mb-1">
                        Technical Threat Explanation
                      </span>
                      <p className="text-slate-300 leading-relaxed">
                        {activeScript.explanation}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4 flex-1">
                    <div className="bg-purple-950/30 border border-purple-800/50 rounded-xl p-4">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-purple-300 font-bold block mb-1">
                        What this code is actually doing
                      </span>
                      <p className="text-sm text-slate-200 leading-relaxed">
                        This website contains secret hidden computer commands designed to trick you.
                        Specifically, it scrambles text so security scanners cannot read it, and then secretly sends whatever you type directly to the attacker.
                      </p>
                    </div>

                    <div className="bg-red-950/30 border border-red-800/50 rounded-xl p-4">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-red-300 font-bold block mb-1">
                        Potential Impact to You
                      </span>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        If you enter your password on this page, the cybercriminal receives it within seconds. They may also attempt to lock your keyboard or disable right-clicking so you cannot inspect the website.
                      </p>
                    </div>

                    <div className="bg-emerald-950/30 border border-emerald-800/50 rounded-xl p-4">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-300 font-bold block mb-1">
                        Recommended Defensive Action
                      </span>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        Close this browser window immediately. Never attempt to log in or download files from this page.
                      </p>
                    </div>
                  </div>
                )}

                <div className="mt-4 pt-3 border-t border-slate-800 text-[10px] text-slate-500 font-mono">
                  * Code execution is safely simulated and sandboxed. Untrusted scripts are never executed in client browser.
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-400">
                Select a code finding from the left to inspect its forensics.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
