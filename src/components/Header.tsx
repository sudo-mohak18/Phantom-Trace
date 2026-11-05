import React from 'react';
import {
  ShieldAlert,
  Search,
  Network,
  Code2,
  Bot,
  Mail,
  GraduationCap,
  LayoutDashboard,
  FileText,
  Sparkles,
} from 'lucide-react';

export type ActiveTab =
  | 'investigator'
  | 'explorer'
  | 'code'
  | 'analyst'
  | 'email'
  | 'awareness'
  | 'dashboard'
  | 'report';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  onLoadSample: (sampleId: string) => void;
  hasActiveScan: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onLoadSample,
  hasActiveScan,
}) => {
  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-[#07090e]/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Tagline */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('investigator')}>
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-400 p-[1.5px] shadow-lg shadow-purple-950/40">
              <div className="w-full h-full bg-[#0b0f19] rounded-[10px] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
              </div>
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-lg font-bold tracking-tight text-white">
                  PHANTOM<span className="text-cyan-400 font-extrabold ml-0.5">TRACE</span>
                </span>
                <span className="px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-purple-300 bg-purple-950/80 border border-purple-800/60 rounded">
                  v1.0 Pro
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Threat Intelligence & Phishing Forensics
              </p>
            </div>
          </div>

          {/* Navigation Items */}
          <nav className="hidden md:flex items-center space-x-1" aria-label="Main Navigation">
            <button
              onClick={() => setActiveTab('investigator')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center space-x-1.5 ${
                activeTab === 'investigator'
                  ? 'bg-purple-900/40 text-cyan-300 border border-purple-700/60 shadow-sm shadow-purple-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>Investigator</span>
            </button>

            <button
              onClick={() => setActiveTab('explorer')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center space-x-1.5 ${
                activeTab === 'explorer'
                  ? 'bg-purple-900/40 text-cyan-300 border border-purple-700/60 shadow-sm shadow-purple-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Threat Explorer</span>
            </button>

            <button
              onClick={() => setActiveTab('code')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center space-x-1.5 ${
                activeTab === 'code'
                  ? 'bg-purple-900/40 text-cyan-300 border border-purple-700/60 shadow-sm shadow-purple-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Code Forensics</span>
            </button>

            <button
              onClick={() => setActiveTab('analyst')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center space-x-1.5 ${
                activeTab === 'analyst'
                  ? 'bg-purple-900/40 text-cyan-300 border border-purple-700/60 shadow-sm shadow-purple-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Bot className="w-3.5 h-3.5" />
              <span>AI Analyst</span>
            </button>

            <button
              onClick={() => setActiveTab('email')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center space-x-1.5 ${
                activeTab === 'email'
                  ? 'bg-purple-900/40 text-cyan-300 border border-purple-700/60 shadow-sm shadow-purple-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Email Detective</span>
            </button>

            <button
              onClick={() => setActiveTab('awareness')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center space-x-1.5 ${
                activeTab === 'awareness'
                  ? 'bg-purple-900/40 text-cyan-300 border border-purple-700/60 shadow-sm shadow-purple-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <GraduationCap className="w-3.5 h-3.5" />
              <span>Cyber Awareness</span>
            </button>

            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center space-x-1.5 ${
                activeTab === 'dashboard'
                  ? 'bg-purple-900/40 text-cyan-300 border border-purple-700/60 shadow-sm shadow-purple-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              <span>Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('report')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center space-x-1.5 ${
                activeTab === 'report'
                  ? 'bg-purple-900/40 text-cyan-300 border border-purple-700/60 shadow-sm shadow-purple-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Reports</span>
            </button>
          </nav>

          {/* Quick Actions */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => onLoadSample('sample-paypal-phish')}
              className="hidden lg:flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium text-amber-300 bg-amber-950/40 hover:bg-amber-900/40 border border-amber-800/50 rounded-lg transition-all"
              title="Load verified PayPal phishing attack investigation"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Load Threat Sample</span>
            </button>

            {hasActiveScan && (
              <button
                onClick={() => setActiveTab('report')}
                className="px-3 py-1.5 text-xs font-medium text-white bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 rounded-lg shadow-sm shadow-purple-900/50 transition-all flex items-center space-x-1.5"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Export Report</span>
              </button>
            )}
          </div>
        </div>

        {/* Mobile Navigation Scrollbar */}
        <div className="flex md:hidden overflow-x-auto py-2 space-x-1 border-t border-slate-800/60 no-scrollbar">
          {[
            { id: 'investigator', label: 'Scan', icon: Search },
            { id: 'explorer', label: 'Graph', icon: Network },
            { id: 'code', label: 'Code', icon: Code2 },
            { id: 'analyst', label: 'AI Analyst', icon: Bot },
            { id: 'email', label: 'Email', icon: Mail },
            { id: 'awareness', label: 'Learn', icon: GraduationCap },
            { id: 'dashboard', label: 'Stats', icon: LayoutDashboard },
            { id: 'report', label: 'Report', icon: FileText },
          ].map(item => {
            const Icon = item.icon;
            const isSelected = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id as ActiveTab)}
                className={`px-2.5 py-1 text-xs whitespace-nowrap rounded-md flex items-center space-x-1 transition-all ${
                  isSelected
                    ? 'bg-purple-900/50 text-cyan-300 border border-purple-700/60'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="w-3 h-3" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
