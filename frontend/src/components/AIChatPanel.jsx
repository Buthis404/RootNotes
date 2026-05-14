import React, { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../api.js';

function ToolCallBlock({ toolCall }) {
  const [expanded, setExpanded] = useState(false);
  const name = toolCall.name || toolCall.tool_name || 'tool';
  const args = toolCall.args || toolCall.arguments || {};
  const result = toolCall.result || toolCall.result_summary || '';

  const argsStr = typeof args === 'string' ? args : JSON.stringify(args, null, 2);
  const argsPreview = argsStr.length > 60 ? argsStr.slice(0, 60) + '…' : argsStr;

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, marginBottom: 4, fontSize: 11, fontFamily: 'JetBrains Mono', overflow: 'hidden' }}>
      <div
        onClick={() => setExpanded(v => !v)}
        style={{ padding: '5px 10px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, color: '#808590', userSelect: 'none' }}
        onMouseEnter={e => e.currentTarget.style.background = '#ffffff06'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <span style={{ fontSize: 12 }}>🔧</span>
        <span style={{ color: '#c07af0', fontWeight: 600 }}>{name}</span>
        <span style={{ color: '#505560' }}>({argsPreview})</span>
        <span style={{ marginLeft: 'auto', fontSize: 10, color: '#404550' }}>{expanded ? '▲' : '▼'}</span>
      </div>
      {expanded && (
        <div style={{ borderTop: '1px solid #1e2029', padding: '8px 10px' }}>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Args</div>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#c8cdd6', fontSize: 11, lineHeight: 1.5 }}>{argsStr}</pre>
          {result && (
            <>
              <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 8, marginBottom: 4 }}>Result</div>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#39d353', fontSize: 11, lineHeight: 1.5 }}>{typeof result === 'string' ? result : JSON.stringify(result, null, 2)}</pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function ThinkingDots() {
  const [dots, setDots] = useState('');
  useEffect(() => {
    const iv = setInterval(() => setDots(d => d.length >= 3 ? '' : d + '.'), 400);
    return () => clearInterval(iv);
  }, []);
  return <span style={{ color: '#606570', fontStyle: 'italic', fontSize: 12 }}>thinking{dots}</span>;
}

export default function AIChatPanel({ selectedProject, accent }) {
  const [open, setOpen] = useState(false);
  const [btnHover, setBtnHover] = useState(false);
  const [history, setHistory] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [agentMode, setAgentMode] = useState(true);
  const [error, setError] = useState('');
  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  useEffect(() => {
    if (open && messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [history, open, loading]);

  const send = useCallback(async () => {
    const msg = input.trim();
    if (!msg || loading) return;
    setInput('');
    setError('');
    const userMsg = { role: 'user', content: msg };
    setHistory(prev => [...prev, userMsg]);
    setLoading(true);
    try {
      const res = await api.aiChat(selectedProject, {
        message: msg,
        history: [...history, userMsg]
          .filter(m => m.role !== 'system')
          .map(m => ({ role: m.role, content: m.content })),
        agent_mode: agentMode,
      });
      setHistory(prev => [...prev, {
        role: 'assistant',
        content: res.response || res.content || res.message || '',
        tool_calls_log: res.tool_calls_log || res.tool_calls || [],
        provider_used: res.provider_used || res.provider || '',
      }]);
    } catch (e) {
      setError(e.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  }, [input, loading, history, selectedProject, agentMode]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  const clearHistory = () => setHistory([]);

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box', resize: 'none' };

  return (
    <>
      {/* Toggle button */}
      <button
        onClick={() => setOpen(v => !v)}
        onMouseEnter={() => setBtnHover(true)}
        onMouseLeave={() => setBtnHover(false)}
        style={{
          position: 'fixed', bottom: 20, right: 20, zIndex: 999,
          width: 40, height: 40, borderRadius: '50%',
          background: open ? '#1a1c22' : accent, border: open ? `2px solid ${accent}` : 'none',
          cursor: 'pointer', color: open ? accent : '#fff',
          fontSize: 11, fontWeight: 700, fontFamily: 'Space Grotesk',
          boxShadow: '0 3px 12px rgba(0,0,0,0.5)',
          transition: 'opacity .2s, transform .2s',
          opacity: open || btnHover ? 1 : 0.35,
          transform: btnHover && !open ? 'scale(1.1)' : 'scale(1)',
        }}
        title={open ? 'Close AI' : 'Open AI Agent'}
      >
        AI
      </button>

      {/* Panel */}
      {open && (
        <div style={{
          position: 'fixed', top: 0, right: 0, bottom: 0,
          width: 420, zIndex: 1000,
          background: '#0d0f14', borderLeft: '1px solid #1e2029',
          display: 'flex', flexDirection: 'column',
          boxShadow: '-8px 0 40px rgba(0,0,0,0.6)',
          fontFamily: 'JetBrains Mono',
        }}>
          {/* Header */}
          <div style={{ padding: '14px 16px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>AI Agent</div>
              <div style={{ fontSize: 10, color: '#505560', marginTop: 2 }}>Context-aware pentesting assistant</div>
            </div>
            <button
              onClick={clearHistory}
              style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 9px', cursor: 'pointer', color: '#606570', fontSize: 10 }}
              title="Clear history"
            >
              Clear
            </button>
            <button
              onClick={() => setOpen(false)}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#606570', fontSize: 16, lineHeight: 1, padding: '2px 4px' }}
              title="Close"
            >
              ✕
            </button>
          </div>

          {/* Agent mode toggle */}
          <div style={{ padding: '8px 16px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 11, color: agentMode ? accent : '#606570' }}>
              <input
                type="checkbox"
                checked={agentMode}
                onChange={e => setAgentMode(e.target.checked)}
                style={{ accentColor: accent }}
              />
              Agent mode (tools enabled)
            </label>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {history.length === 0 && (
              <div style={{ color: '#404550', fontSize: 12, textAlign: 'center', marginTop: 40 }}>
                Ask me anything about this project.<br />
                <span style={{ fontSize: 10, color: '#303540' }}>I can read hosts, creds, findings, notes and run tools.</span>
              </div>
            )}
            {history.map((msg, i) => (
              <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
                {/* Tool calls (for assistant messages) */}
                {msg.role === 'assistant' && msg.tool_calls_log && msg.tool_calls_log.length > 0 && (
                  <div style={{ width: '100%', marginBottom: 4 }}>
                    {msg.tool_calls_log.map((tc, j) => <ToolCallBlock key={j} toolCall={tc} />)}
                  </div>
                )}
                {/* Message bubble */}
                {msg.content && (
                  <div style={{
                    maxWidth: '85%',
                    background: msg.role === 'user' ? accent + '22' : '#0a0c10',
                    border: `1px solid ${msg.role === 'user' ? accent + '55' : '#1e2029'}`,
                    borderRadius: msg.role === 'user' ? '12px 12px 2px 12px' : '12px 12px 12px 2px',
                    padding: '9px 12px',
                    color: '#c8cdd6',
                    fontSize: 12,
                    lineHeight: 1.6,
                    wordBreak: 'break-word',
                    whiteSpace: 'pre-wrap',
                  }}>
                    {msg.content}
                  </div>
                )}
                {/* Provider info */}
                {msg.role === 'assistant' && msg.provider_used && (
                  <div style={{ fontSize: 9, color: '#404550', marginTop: 3 }}>Provider: {msg.provider_used}</div>
                )}
              </div>
            ))}
            {loading && (
              <div style={{ display: 'flex', alignItems: 'flex-start' }}>
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: '12px 12px 12px 2px', padding: '9px 12px' }}>
                  <ThinkingDots />
                </div>
              </div>
            )}
            {error && (
              <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '8px 12px', fontSize: 11, color: '#cc2233' }}>
                {error}
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input area */}
          <div style={{ padding: '12px 16px', borderTop: '1px solid #1e2029', flexShrink: 0 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
              <textarea
                ref={textareaRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask AI... (Enter to send, Shift+Enter for newline)"
                rows={3}
                style={{ ...inp, lineHeight: 1.5 }}
                disabled={loading}
              />
              <button
                onClick={send}
                disabled={loading || !input.trim()}
                style={{
                  background: input.trim() && !loading ? accent : '#1a1c22',
                  border: 'none', borderRadius: 5, padding: '8px 14px',
                  cursor: input.trim() && !loading ? 'pointer' : 'not-allowed',
                  color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono',
                  flexShrink: 0, transition: 'background .15s', alignSelf: 'flex-end',
                  height: 36,
                }}
              >
                Send
              </button>
            </div>
            <div style={{ fontSize: 9, color: '#303540', marginTop: 6 }}>Enter to send · Shift+Enter for newline</div>
          </div>
        </div>
      )}
    </>
  );
}
