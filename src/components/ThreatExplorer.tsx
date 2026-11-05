import React, { useState, useMemo } from 'react';
import {
  Network,
  Search,
  Filter,
  Globe,
  Server,
  Lock,
  Code2,
  FileCode,
  ShieldAlert,
  Info,
  Maximize2,
  RotateCcw,
} from 'lucide-react';
import { ScanResult, GraphNode } from '../types/scanner';

interface ThreatExplorerProps {
  scan: ScanResult;
}

export const ThreatExplorer: React.FC<ThreatExplorerProps> = ({ scan }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string>('node-url');
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [zoomLevel, setZoomLevel] = useState<number>(1);

  const { graphData } = scan;

  // Filter nodes based on category and search
  const filteredNodes = useMemo(() => {
    return graphData.nodes.filter(node => {
      const matchesCategory =
        categoryFilter === 'all' ||
        (categoryFilter === 'network' && (node.category === 'ip' || node.category === 'dns')) ||
        (categoryFilter === 'infrastructure' && (node.category === 'domain' || node.category === 'ssl')) ||
        (categoryFilter === 'code' && (node.category === 'script' || node.category === 'form')) ||
        (categoryFilter === 'threat' && node.category === 'threat');

      const matchesSearch =
        node.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.detail.toLowerCase().includes(searchQuery.toLowerCase());

      return matchesCategory && matchesSearch;
    });
  }, [graphData.nodes, categoryFilter, searchQuery]);

  // Selected node object
  const selectedNode = useMemo(() => {
    return graphData.nodes.find(n => n.id === selectedNodeId) || graphData.nodes[0];
  }, [graphData.nodes, selectedNodeId]);

  // Node category icons
  const getNodeIcon = (category: GraphNode['category']) => {
    switch (category) {
      case 'url':
        return <Globe className="w-3.5 h-3.5 text-cyan-400" />;
      case 'domain':
        return <Server className="w-3.5 h-3.5 text-purple-400" />;
      case 'ip':
        return <Network className="w-3.5 h-3.5 text-blue-400" />;
      case 'ssl':
        return <Lock className="w-3.5 h-3.5 text-emerald-400" />;
      case 'form':
        return <Code2 className="w-3.5 h-3.5 text-red-400" />;
      case 'script':
        return <FileCode className="w-3.5 h-3.5 text-amber-400" />;
      case 'threat':
        return <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />;
      default:
        return <Info className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  // Node position arrangement in SVG workspace
  const getNodeCoordinates = (index: number, total: number) => {
    const centerX = 360;
    const centerY = 240;
    if (index === 0) return { x: centerX, y: centerY };

    const angle = ((index - 1) / Math.max(1, total - 1)) * 2 * Math.PI - Math.PI / 2;
    const radius = 170;
    return {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    };
  };

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl relative">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            Threat Relationship Graph
          </h3>
          <p className="text-xs text-slate-400">
            Interactive topology mapping URLs, DNS hosts, SSL certs, and exfiltration endpoints.
          </p>
        </div>

        {/* Search and Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search graph nodes..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="bg-[#07090e] border border-slate-800 text-xs text-slate-200 pl-8 pr-3 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500 w-36 sm:w-44"
            />
          </div>

          <div className="flex items-center bg-[#07090e] p-0.5 rounded-lg border border-slate-800 text-xs">
            {['all', 'infrastructure', 'network', 'code', 'threat'].map(cat => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`px-2 py-1 capitalize rounded-md transition-all ${
                  categoryFilter === cat
                    ? 'bg-purple-900/50 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <button
            onClick={() => setZoomLevel(prev => (prev === 1 ? 1.25 : 1))}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
            title="Toggle zoom"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* SVG Interactive Canvas */}
        <div className="lg:col-span-2 bg-[#07090e] border border-slate-800/90 rounded-xl overflow-hidden relative min-h-[460px] flex items-center justify-center">
          {/* Subtle grid background */}
          <div
            className="absolute inset-0 opacity-15"
            style={{
              backgroundImage: 'radial-gradient(circle, #38bdf8 1px, transparent 1px)',
              backgroundSize: '24px 24px',
            }}
          />

          <svg
            className="w-full h-full min-h-[460px] cursor-grab active:cursor-grabbing transition-transform"
            viewBox="0 0 720 480"
            style={{ transform: `scale(${zoomLevel})` }}
          >
            {/* Draw Links */}
            {graphData.links.map((link, idx) => {
              const sourceIdx = graphData.nodes.findIndex(n => n.id === link.source);
              const targetIdx = graphData.nodes.findIndex(n => n.id === link.target);
              if (sourceIdx === -1 || targetIdx === -1) return null;

              const sourceCoord = getNodeCoordinates(sourceIdx, graphData.nodes.length);
              const targetCoord = getNodeCoordinates(targetIdx, graphData.nodes.length);

              const isLinkActive =
                selectedNodeId === link.source || selectedNodeId === link.target;

              return (
                <g key={`link-${idx}`}>
                  <line
                    x1={sourceCoord.x}
                    y1={sourceCoord.y}
                    x2={targetCoord.x}
                    y2={targetCoord.y}
                    stroke={isLinkActive ? '#38bdf8' : '#334155'}
                    strokeWidth={isLinkActive ? 2 : 1.2}
                    strokeDasharray={link.label.includes('exfiltrat') || link.label.includes('threat') ? '4 3' : 'none'}
                    className="transition-colors duration-300"
                  />
                  {/* Link Label */}
                  <text
                    x={(sourceCoord.x + targetCoord.x) / 2}
                    y={(sourceCoord.y + targetCoord.y) / 2 - 4}
                    fill="#64748b"
                    fontSize="9"
                    fontFamily="monospace"
                    textAnchor="middle"
                  >
                    {link.label}
                  </text>
                </g>
              );
            })}

            {/* Draw Nodes */}
            {graphData.nodes.map((node, idx) => {
              const coord = getNodeCoordinates(idx, graphData.nodes.length);
              const isSelected = selectedNodeId === node.id;
              const isCenter = idx === 0;

              let nodeFill = '#0f172a';
              let nodeStroke = '#38bdf8';
              if (node.risk === 'malicious') nodeStroke = '#ef4444';
              else if (node.risk === 'suspicious') nodeStroke = '#f59e0b';
              else if (node.risk === 'clean') nodeStroke = '#10b981';

              return (
                <g
                  key={node.id}
                  transform={`translate(${coord.x}, ${coord.y})`}
                  onClick={() => setSelectedNodeId(node.id)}
                  className="cursor-pointer transition-transform hover:scale-110"
                >
                  {/* Outer selection ring */}
                  {isSelected && (
                    <circle
                      r={isCenter ? 32 : 24}
                      fill="none"
                      stroke="#a855f7"
                      strokeWidth="2.5"
                      strokeDasharray="3 3"
                      className="animate-spin"
                      style={{ animationDuration: '8s' }}
                    />
                  )}

                  {/* Node Body Circle */}
                  <circle
                    r={isCenter ? 26 : 18}
                    fill={nodeFill}
                    stroke={nodeStroke}
                    strokeWidth={isSelected ? 3 : 2}
                    className="shadow-lg"
                  />

                  {/* Node Label Text */}
                  <text
                    y={isCenter ? 38 : 28}
                    fill={isSelected ? '#ffffff' : '#cbd5e1'}
                    fontSize={isCenter ? '11' : '9.5'}
                    fontWeight={isSelected ? 'bold' : 'normal'}
                    fontFamily="sans-serif"
                    textAnchor="middle"
                  >
                    {node.label.length > 22 ? node.label.substring(0, 19) + '...' : node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Interactive instruction pill */}
          <div className="absolute bottom-3 left-3 bg-[#0b0f19]/90 border border-slate-800 text-[10px] text-slate-400 px-2.5 py-1 rounded-md">
            Click any node to view forensic evidence & telemetry.
          </div>
        </div>

        {/* Node Inspector Drawer */}
        <div className="bg-[#0e1424] border border-slate-800/90 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-4">
              <span className="text-[11px] font-mono uppercase tracking-wider text-purple-400 font-bold">
                Node Inspector
              </span>
              <span
                className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded ${
                  selectedNode.risk === 'malicious'
                    ? 'bg-red-950/80 text-red-300 border border-red-800'
                    : selectedNode.risk === 'suspicious'
                    ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                    : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                }`}
              >
                {selectedNode.risk}
              </span>
            </div>

            <div className="flex items-start gap-3 mb-4">
              <div className="p-2 rounded-xl bg-slate-900 border border-slate-800">
                {getNodeIcon(selectedNode.category)}
              </div>
              <div>
                <h4 className="text-sm font-bold text-white break-all">
                  {selectedNode.label}
                </h4>
                <span className="text-[11px] font-mono text-slate-400 capitalize">
                  Category: {selectedNode.category}
                </span>
              </div>
            </div>

            <div className="bg-[#07090e] p-3 rounded-xl border border-slate-800/80 mb-4">
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                Supporting Evidence & Telemetry
              </span>
              <p className="text-xs text-slate-200 leading-relaxed font-mono">
                {selectedNode.detail}
              </p>
            </div>

            {/* Related Connections */}
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-2">
                Active Connections ({graphData.links.filter(l => l.source === selectedNode.id || l.target === selectedNode.id).length})
              </span>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {graphData.links
                  .filter(l => l.source === selectedNode.id || l.target === selectedNode.id)
                  .map((link, i) => {
                    const otherId = link.source === selectedNode.id ? link.target : link.source;
                    const otherNode = graphData.nodes.find(n => n.id === otherId);
                    return (
                      <div
                        key={i}
                        onClick={() => setSelectedNodeId(otherId)}
                        className="p-2 bg-slate-900/60 hover:bg-slate-800/60 border border-slate-800 rounded-lg text-xs flex items-center justify-between cursor-pointer transition-colors"
                      >
                        <span className="text-slate-300 truncate max-w-[140px] font-medium">
                          {otherNode?.label || otherId}
                        </span>
                        <span className="text-[10px] font-mono text-cyan-400">
                          {link.label}
                        </span>
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>

          <div className="mt-5 pt-3 border-t border-slate-800 text-[11px] text-slate-500">
            Node ID: <code className="text-slate-400">{selectedNode.id}</code>
          </div>
        </div>
      </div>
    </div>
  );
};
