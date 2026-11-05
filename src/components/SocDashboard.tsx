import React from 'react';
import {
  LayoutDashboard,
  ShieldCheck,
  AlertTriangle,
  Skull,
  TrendingUp,
  History,
  Trash2,
  ExternalLink,
  Target,
  Sparkles,
} from 'lucide-react';
import { ScanResult } from '../types/scanner';

interface SocDashboardProps {
  recentScans: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
  onClearHistory: () => void;
  onLoadSample: (id: string) => void;
}

export const SocDashboard: React.FC<SocDashboardProps> = ({
  recentScans,
  onSelectScan,
  onClearHistory,
  onLoadSample,
}) => {
  // Compute aggregate statistics
  const totalScans = recentScans.length;
  const maliciousCount = recentScans.filter(s => s.verdict === 'malicious').length;
  const suspiciousCount = recentScans.filter(s => s.verdict === 'suspicious').length;
  const cleanCount = recentScans.filter(s => s.verdict === 'clean').length;

  const averageScore =
    totalScans > 0
      ? Math.round(recentScans.reduce((acc, curr) => acc + curr.overallScore, 0) / totalScans)
      : 0;

  // Most common categories
  const categoryCounts: Record<string, number> = {};
  for (const s of recentScans) {
    categoryCounts[s.category] = (categoryCounts[s.category] || 0) + 1;
  }

  // Most common indicators
  const indicatorCounts: Record<string, number> = {};
  for (const s of recentScans) {
    for (const ind of s.indicators) {
      indicatorCounts[ind.title] = (indicatorCounts[ind.title] || 0) + 1;
    }
  }

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl relative">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <LayoutDashboard className="w-5 h-5 text-cyan-400" />
            Security Operations Center (SOC) Intelligence Telemetry
          </h3>
          <p className="text-xs text-slate-400">
            Real-time aggregate forensics, detection trends, and historical threat investigations.
          </p>
        </div>

        {recentScans.length > 0 && (
          <button
            onClick={onClearHistory}
            className="px-3 py-1.5 text-xs text-slate-400 hover:text-red-400 rounded-lg bg-slate-900 border border-slate-800 hover:border-red-900/60 flex items-center gap-1.5 self-start sm:self-auto transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        )}
      </div>

      {/* Aggregate Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3.5 mb-6">
        <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold">
            Total Scanned
          </span>
          <p className="text-2xl font-extrabold text-white mt-1">
            {totalScans}
          </p>
          <span className="text-[10px] text-slate-500 mt-0.5 block">Session queries</span>
        </div>

        <div className="bg-[#0e1424] border border-red-950/60 rounded-xl p-4">
          <div className="flex items-center justify-between text-red-400">
            <span className="text-[11px] font-mono uppercase font-semibold">Malicious</span>
            <Skull className="w-4 h-4" />
          </div>
          <p className="text-2xl font-extrabold text-red-400 mt-1">
            {maliciousCount}
          </p>
          <span className="text-[10px] text-red-500/80 mt-0.5 block">
            {totalScans > 0 ? `${Math.round((maliciousCount / totalScans) * 100)}% of total` : '0%'}
          </span>
        </div>

        <div className="bg-[#0e1424] border border-amber-950/60 rounded-xl p-4">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-[11px] font-mono uppercase font-semibold">Suspicious</span>
            <AlertTriangle className="w-4 h-4" />
          </div>
          <p className="text-2xl font-extrabold text-amber-400 mt-1">
            {suspiciousCount}
          </p>
          <span className="text-[10px] text-amber-500/80 mt-0.5 block">Elevated risk</span>
        </div>

        <div className="bg-[#0e1424] border border-emerald-950/60 rounded-xl p-4">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-[11px] font-mono uppercase font-semibold">Clean / Benign</span>
            <ShieldCheck className="w-4 h-4" />
          </div>
          <p className="text-2xl font-extrabold text-emerald-400 mt-1">
            {cleanCount}
          </p>
          <span className="text-[10px] text-emerald-500/80 mt-0.5 block">Verified safe</span>
        </div>

        <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-4 col-span-2 lg:col-span-1">
          <span className="text-[11px] font-mono text-purple-400 uppercase font-semibold">
            Avg Threat Score
          </span>
          <p className="text-2xl font-extrabold text-purple-300 mt-1">
            {averageScore}
            <span className="text-xs font-normal text-slate-500">/100</span>
          </p>
          <span className="text-[10px] text-slate-500 mt-0.5 block">Severity index</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Investigations History Table */}
        <div className="lg:col-span-2 bg-[#0e1424] border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <History className="w-4 h-4 text-cyan-400" />
              Recent Investigations ({recentScans.length})
            </span>
          </div>

          {recentScans.length === 0 ? (
            <div className="py-12 text-center">
              <p className="text-xs text-slate-400">No investigations recorded in this session yet.</p>
              <button
                onClick={() => onLoadSample('sample-paypal-phish')}
                className="mt-3 px-3 py-1.5 text-xs font-semibold rounded-lg bg-purple-950/50 hover:bg-purple-900/50 border border-purple-800/60 text-cyan-300 inline-flex items-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Load Sample Investigation</span>
              </button>
            </div>
          ) : (
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {recentScans.map(scan => (
                <div
                  key={scan.id}
                  onClick={() => onSelectScan(scan)}
                  className="p-3 bg-[#07090e] hover:bg-slate-900/80 border border-slate-800 hover:border-purple-600/60 rounded-xl cursor-pointer transition-all flex items-center justify-between gap-4"
                >
                  <div className="overflow-hidden">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span
                        className={`px-1.5 py-0.2 text-[9px] font-bold uppercase rounded ${
                          scan.verdict === 'malicious'
                            ? 'bg-red-950 text-red-300 border border-red-800'
                            : scan.verdict === 'suspicious'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}
                      >
                        {scan.verdict}
                      </span>
                      <span className="text-xs font-bold text-white truncate max-w-xs">
                        {scan.urlIntelligence.domain}
                      </span>
                    </div>
                    <p className="text-[11px] font-mono text-slate-400 truncate max-w-sm">
                      {scan.targetUrl}
                    </p>
                  </div>

                  <div className="flex items-center gap-3 flex-shrink-0">
                    <div className="text-right">
                      <span className="text-xs font-mono font-bold text-slate-200">
                        {scan.overallScore}/100
                      </span>
                      <span className="text-[10px] text-slate-500 block">
                        {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-500 hover:text-cyan-400" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Threat Distribution & Top Indicators */}
        <div className="space-y-4">
          {/* Top Categories */}
          <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-5">
            <span className="text-xs font-bold text-white uppercase tracking-wider block mb-3">
              Observed Threat Categories
            </span>
            {Object.keys(categoryCounts).length === 0 ? (
              <p className="text-xs text-slate-500">Awaiting telemetry data.</p>
            ) : (
              <div className="space-y-2">
                {Object.entries(categoryCounts).map(([cat, count]) => (
                  <div key={cat} className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 truncate max-w-[170px]">{cat}</span>
                    <span className="font-mono font-bold text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {count}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Top Indicators */}
          <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-5">
            <span className="text-xs font-bold text-white uppercase tracking-wider block mb-3">
              Prevalent Forensic Indicators
            </span>
            {Object.keys(indicatorCounts).length === 0 ? (
              <p className="text-xs text-slate-500">Awaiting telemetry data.</p>
            ) : (
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {Object.entries(indicatorCounts)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 5)
                  .map(([title, count]) => (
                    <div key={title} className="flex items-center justify-between text-xs py-1 border-b border-slate-800/60 last:border-0">
                      <span className="text-slate-300 truncate max-w-[170px]">{title}</span>
                      <span className="font-mono text-purple-300 font-semibold">{count} hits</span>
                    </div>
                  ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
