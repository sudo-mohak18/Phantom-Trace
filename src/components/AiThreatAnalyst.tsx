import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  Terminal,
  ShieldAlert,
  Loader2,
  RefreshCw,
  HelpCircle,
} from 'lucide-react';
import { ScanResult, ChatMessage } from '../types/scanner';

interface AiThreatAnalystProps {
  scan: ScanResult | null;
}

export const AiThreatAnalyst: React.FC<AiThreatAnalystProps> = ({ scan }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome-msg',
      sender: 'assistant',
      content:
        "Hello, I am **PhantomTrace Intelligence**, your dedicated SOC Threat Analyst. " +
        (scan
          ? `I've analyzed target **${scan.urlIntelligence.domain}** (${scan.verdict.toUpperCase()}, Score: ${scan.overallScore}/100). Ask me about the threat architecture, obfuscated scripts, MITRE tactics, or what to do if you interacted with this link.`
          : "Please scan a URL or select a sample investigation, and I will analyze the live threat intelligence for you."),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom of chat
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  // Suggested prompt pills
  const suggestedQuestions = [
    'Why was this URL flagged?',
    'What is this website trying to collect?',
    'What should I do if I clicked this link?',
    'Explain the suspicious JavaScript',
    'How should a SOC analyst investigate this finding?',
  ];

  const handleSendMessage = async (textToSend?: string) => {
    const messageContent = (textToSend || input).trim();
    if (!messageContent || isLoading) return;

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      content: messageContent,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      // Prepare multi-turn history for backend
      const historyPayload = messages
        .filter(m => m.id !== 'welcome-msg')
        .map(m => ({
          role: m.sender === 'user' ? ('user' as const) : ('model' as const),
          content: m.content,
        }));

      const res = await fetch('/api/gemini/analyst', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: messageContent,
          history: historyPayload,
          scanResult: scan || undefined,
        }),
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data = await res.json();
      const assistantMessage: ChatMessage = {
        id: `assistant-${Date.now()}`,
        sender: 'assistant',
        content: data.response || 'No analysis generated.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      const errorMessage: ChatMessage = {
        id: `error-${Date.now()}`,
        sender: 'assistant',
        content: `⚠️ Analyst communication error: ${errorMsg}. Please verify connection.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl shadow-xl flex flex-col h-[640px] overflow-hidden relative">
      {/* Analyst Header */}
      <div className="p-4 border-b border-slate-800/90 bg-[#0e1424] flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-purple-600 to-cyan-400 p-[1px] flex items-center justify-center">
            <div className="w-full h-full bg-[#0b0f19] rounded-[11px] flex items-center justify-center">
              <Bot className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
              <span>PhantomTrace Intelligence</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300">
                gemini-3.8-flash
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Conversational Threat Intelligence & SOC Analyst
            </p>
          </div>
        </div>

        {scan && (
          <div className="hidden sm:flex items-center gap-2 bg-[#07090e] px-3 py-1.5 rounded-lg border border-slate-800 text-xs">
            <span className="text-slate-400">Context:</span>
            <span className="font-mono text-cyan-300 font-semibold truncate max-w-[160px]">
              {scan.urlIntelligence.domain}
            </span>
            <span
              className={`px-1.5 py-0.2 text-[10px] font-bold uppercase rounded ${
                scan.verdict === 'malicious'
                  ? 'bg-red-950 text-red-300'
                  : scan.verdict === 'suspicious'
                  ? 'bg-amber-950 text-amber-300'
                  : 'bg-emerald-950 text-emerald-300'
              }`}
            >
              {scan.verdict}
            </span>
          </div>
        )}
      </div>

      {/* Chat Messages Area */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4">
        {messages.map(msg => {
          const isUser = msg.sender === 'user';
          return (
            <div
              key={msg.id}
              className={`flex items-start gap-3 ${isUser ? 'flex-row-reverse' : ''}`}
            >
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 text-xs font-bold ${
                  isUser
                    ? 'bg-cyan-600 text-white'
                    : 'bg-purple-950 border border-purple-800 text-cyan-400'
                }`}
              >
                {isUser ? 'YOU' : <Bot className="w-4 h-4" />}
              </div>

              <div
                className={`max-w-[85%] rounded-2xl p-4 text-xs sm:text-sm leading-relaxed ${
                  isUser
                    ? 'bg-cyan-950/70 text-cyan-50 border border-cyan-800/60 rounded-tr-none'
                    : 'bg-[#0e1424] text-slate-200 border border-slate-800 rounded-tl-none'
                }`}
              >
                <div className="whitespace-pre-line font-sans">
                  {msg.content}
                </div>
                <div className="mt-1.5 text-[10px] text-slate-500 font-mono text-right">
                  {msg.timestamp}
                </div>
              </div>
            </div>
          );
        })}

        {isLoading && (
          <div className="flex items-center gap-2 text-xs text-slate-400 pl-10">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span>PhantomTrace Intelligence analyzing telemetry & MITRE ATT&CK correlation...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Questions Pills */}
      {scan && (
        <div className="px-4 py-2 bg-[#0e1424]/70 border-t border-slate-800/60 flex items-center gap-2 overflow-x-auto no-scrollbar">
          <span className="text-[10px] font-mono text-purple-400 uppercase font-bold flex-shrink-0">
            Quick Prompts:
          </span>
          {suggestedQuestions.map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(q)}
              disabled={isLoading}
              className="text-xs text-slate-300 hover:text-white bg-slate-900/90 hover:bg-slate-800 border border-slate-800 px-2.5 py-1 rounded-full whitespace-nowrap transition-colors"
            >
              {q}
            </button>
          ))}
        </div>
      )}

      {/* Message Input Box */}
      <div className="p-3 bg-[#0e1424] border-t border-slate-800/80">
        <form
          onSubmit={e => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Ask PhantomTrace Intelligence about this URL, IOCs, or containment steps..."
            disabled={isLoading}
            className="flex-1 bg-[#07090e] border border-slate-800 rounded-xl px-4 py-2.5 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="p-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-md shadow-purple-950/40"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};
