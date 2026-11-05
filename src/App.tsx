/**
 * PhantomTrace - Unified Frontend Application
 * Professional Threat Intelligence & Phishing Forensics Platform
 */

import React, { useState, useEffect } from 'react';
import { Header, ActiveTab } from './components/Header';
import { InvestigationCenter } from './components/InvestigationCenter';
import { ThreatExplorer } from './components/ThreatExplorer';
import { MaliciousCodeExplorer } from './components/MaliciousCodeExplorer';
import { AiThreatAnalyst } from './components/AiThreatAnalyst';
import { PhishingEmailDetective } from './components/PhishingEmailDetective';
import { CyberAwarenessMode } from './components/CyberAwarenessMode';
import { SocDashboard } from './components/SocDashboard';
import { ReportModal } from './components/ReportModal';
import { SAMPLE_INVESTIGATIONS } from './services/mockIntelligence';
import { ScanResult } from './types/scanner';
import { ShieldAlert, Terminal, Lock } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('investigator');
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(SAMPLE_INVESTIGATIONS[0]);
  const [recentScans, setRecentScans] = useState<ScanResult[]>(() => {
    try {
      const stored = localStorage.getItem('phantomtrace_scans');
      return stored ? JSON.parse(stored) : SAMPLE_INVESTIGATIONS;
    } catch {
      return SAMPLE_INVESTIGATIONS;
    }
  });

  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(1);
  const [scanError, setScanError] = useState<string | null>(null);

  // Save scan history to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('phantomtrace_scans', JSON.stringify(recentScans.slice(0, 20)));
    } catch {
      // Storage quota or error
    }
  }, [recentScans]);

  const handleScanUrl = async (url: string) => {
    setIsScanning(true);
    setScanError(null);
    setScanStep(1);

    // Simulate animated step transitions during actual backend fetch
    const stepInterval = setInterval(() => {
      setScanStep(prev => (prev < 5 ? prev + 1 : prev));
    }, 450);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      clearInterval(stepInterval);

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.error || `Scan request failed with HTTP ${response.status}`);
      }

      const scanData: ScanResult = await response.json();
      setScanStep(5);
      setCurrentScan(scanData);

      // Add to recent investigations (deduplicate by targetUrl)
      setRecentScans(prev => {
        const filtered = prev.filter(s => s.targetUrl !== scanData.targetUrl);
        return [scanData, ...filtered];
      });

      setActiveTab('investigator');
    } catch (err) {
      clearInterval(stepInterval);
      const msg = err instanceof Error ? err.message : String(err);
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadSample = (sampleId: string) => {
    const sample = SAMPLE_INVESTIGATIONS.find(s => s.id === sampleId) || SAMPLE_INVESTIGATIONS[0];
    setCurrentScan(sample);
    setScanError(null);
    setScanStep(5);

    setRecentScans(prev => {
      const filtered = prev.filter(s => s.id !== sample.id);
      return [sample, ...filtered];
    });

    setActiveTab('investigator');
  };

  const handleClearHistory = () => {
    setRecentScans([]);
    try {
      localStorage.removeItem('phantomtrace_scans');
    } catch {
      // Storage error
    }
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans">
      {/* Top Application Header & Navigation */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onLoadSample={handleLoadSample}
        hasActiveScan={!!currentScan}
      />

      {/* Main Viewport Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'investigator' && (
          <InvestigationCenter
            currentScan={currentScan}
            onScanUrl={handleScanUrl}
            onLoadSample={handleLoadSample}
            isScanning={isScanning}
            scanStep={scanStep}
            scanError={scanError}
            setActiveTab={setActiveTab}
          />
        )}

        {activeTab === 'explorer' && (
          <div>
            {currentScan ? (
              <ThreatExplorer scan={currentScan} />
            ) : (
              <div className="p-12 text-center bg-[#0b0f19] border border-slate-800 rounded-2xl">
                <p className="text-sm text-slate-400">
                  Please investigate a URL first to view its relationship graph.
                </p>
                <button
                  onClick={() => handleLoadSample('sample-paypal-phish')}
                  className="mt-3 px-4 py-2 text-xs font-bold bg-purple-600 hover:bg-purple-500 rounded-lg text-white"
                >
                  Load Sample Graph
                </button>
              </div>
            )}
          </div>
        )}

        {activeTab === 'code' && (
          <div>
            {currentScan ? (
              <MaliciousCodeExplorer
                inspection={currentScan.websiteInspection}
                verdict={currentScan.verdict}
              />
            ) : (
              <div className="p-12 text-center bg-[#0b0f19] border border-slate-800 rounded-2xl">
                <p className="text-sm text-slate-400">
                  Please investigate a URL first to inspect code and DOM findings.
                </p>
                <button
                  onClick={() => handleLoadSample('sample-paypal-phish')}
                  className="mt-3 px-4 py-2 text-xs font-bold bg-purple-600 hover:bg-purple-500 rounded-lg text-white"
                >
                  Load Sample Code Forensics
                </button>
              </div>
            )}
          </div>
        )}

        {activeTab === 'analyst' && (
          <AiThreatAnalyst scan={currentScan} />
        )}

        {activeTab === 'email' && (
          <PhishingEmailDetective
            onScanUrlRequested={url => {
              handleScanUrl(url);
              setActiveTab('investigator');
            }}
          />
        )}

        {activeTab === 'awareness' && (
          <CyberAwarenessMode />
        )}

        {activeTab === 'dashboard' && (
          <SocDashboard
            recentScans={recentScans}
            onSelectScan={scan => {
              setCurrentScan(scan);
              setActiveTab('investigator');
            }}
            onClearHistory={handleClearHistory}
            onLoadSample={handleLoadSample}
          />
        )}

        {activeTab === 'report' && (
          <div>
            {currentScan ? (
              <ReportModal scan={currentScan} />
            ) : (
              <div className="p-12 text-center bg-[#0b0f19] border border-slate-800 rounded-2xl">
                <p className="text-sm text-slate-400">
                  Please investigate a URL first to generate an incident report.
                </p>
                <button
                  onClick={() => handleLoadSample('sample-paypal-phish')}
                  className="mt-3 px-4 py-2 text-xs font-bold bg-purple-600 hover:bg-purple-500 rounded-lg text-white"
                >
                  Load Sample Report
                </button>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Global Footer */}
      <footer className="border-t border-slate-800/80 bg-[#07090e] py-6 text-xs text-slate-500 no-print">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-slate-300">PHANTOMTRACE</span>
            <span>—</span>
            <span>Every suspicious link has a story. Discover it before it's too late.</span>
          </div>

          <div className="flex items-center space-x-4">
            <span className="flex items-center gap-1 font-mono text-[11px] text-slate-400">
              <Lock className="w-3 h-3 text-emerald-400" />
              SSRF Protected Sandbox
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-[11px] text-purple-400 font-mono">MITRE ATT&CK Aligned</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
