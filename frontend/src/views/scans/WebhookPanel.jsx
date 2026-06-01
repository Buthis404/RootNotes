/**
 * Webhook panel — token management, examples, event types.
 *
 * Extracted from ScansView.jsx.
 */
import PropTypes from 'prop-types';
import { useState, useEffect } from 'react';
import { api } from '../../api.js';

const WEBHOOK_EXAMPLE_PAYLOAD = JSON.stringify({
  type: "beacon",
  ip: "x.x.x.x",
  hostname: "DC01",
  os: "Windows Server 2019",
  username: String.raw`CORP\administrator`,
  domain: "CORP.LOCAL",
  source: "adaptix",
}, null, 2);

const WEBHOOK_EVENT_TYPES = [
  { type: 'beacon',  color: '#cc2233', desc: 'New implant / session — creates host + cred' },
  { type: 'implant', color: '#cc2233', desc: 'Alias for beacon' },
  { type: 'cred',    color: '#c07af0', desc: 'Credential dump — creates cred record' },
  { type: 'hash',    color: '#c07af0', desc: 'NTLM hash — creates cred with type=hash' },
  { type: 'finding', color: '#e8574a', desc: 'Vulnerability — creates finding' },
];

function WebhookUrlBlock({ token, fullUrl, copied, onCopy }) {
  return (
    <div style={{ background: '#0c0e13', border: '1px solid #1a1c22', borderRadius: 6, padding: 14, marginBottom: 14 }}>
      <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Webhook URL</div>
      {token ? (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <code style={{ flex: 1, fontSize: 11, color: '#a0c0ff', fontFamily: 'JetBrains Mono', wordBreak: 'break-all' }}>{fullUrl}</code>
          <button onClick={() => onCopy(fullUrl, 'url')}
            style={{ background: copied === 'url' ? '#39d35322' : '#1a1c22', border: `1px solid ${copied === 'url' ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: copied === 'url' ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
            {copied === 'url' ? 'Copied!' : 'Copy'}
          </button>
        </div>
      ) : (
        <div style={{ fontSize: 12, color: '#505560' }}>No webhook configured. Click Generate to create one.</div>
      )}
    </div>
  );
}
WebhookUrlBlock.propTypes = {
  token: PropTypes.any,
  fullUrl: PropTypes.any,
  copied: PropTypes.any,
  onCopy: PropTypes.any,
};

function WebhookExampleBlock({ examplePayload, fullUrl, copied, onCopy }) {
  return (
    <>
      <div style={{ fontSize: 10, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Example payload (beacon)</div>
      <div style={{ position: 'relative' }}>
        <pre style={{ background: '#0c0e13', border: '1px solid #1a1c22', borderRadius: 6, padding: 12, fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono', overflowX: 'auto', margin: 0 }}>
          {examplePayload}
        </pre>
        <button onClick={() => onCopy(examplePayload, 'example')}
          style={{ position: 'absolute', top: 8, right: 8, background: copied === 'example' ? '#39d35322' : '#1a1c22', border: `1px solid ${copied === 'example' ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: copied === 'example' ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {copied === 'example' ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <div style={{ marginTop: 14, fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', lineHeight: 1.8 }}>
        <div style={{ marginBottom: 4, color: '#505560' }}>Usage examples:</div>
        <div>curl -s -X POST {fullUrl || '<webhook_url>'} \</div>
        <div>&nbsp;&nbsp;-H 'Content-Type: application/json' \</div>
        <div>&nbsp;&nbsp;-d '{String.raw`{"type":"beacon","ip":"10.0.0.1","username":"CORP\\admin"}`}'</div>
      </div>
    </>
  );
}
WebhookExampleBlock.propTypes = {
  examplePayload: PropTypes.any,
  fullUrl: PropTypes.any,
  copied: PropTypes.any,
  onCopy: PropTypes.any,
};

async function _loadWebhook(pid, setToken, setUrl, setLoading) {
  if (!pid) { setLoading(false); return; }
  try {
    const r = await api.getProjectWebhook(pid);
    setToken(r.token || '');
    setUrl(r.url || '');
  } catch {}
  setLoading(false);
}

async function _regenerateWebhook(pid, setToken, setUrl, setRegenerating) {
  setRegenerating(true);
  try {
    const r = await api.regenerateProjectWebhook(pid);
    setToken(r.token);
    setUrl(r.url);
  } catch {}
  setRegenerating(false);
}

function _copyWebhook(text, key, setCopied) {
  navigator.clipboard.writeText(text).then(() => {
    setCopied(key);
    setTimeout(() => setCopied(''), 1500);
  });
}

function WebhookBody({ token, url, copied, regenerating, pid, setToken, setUrl, setRegenerating, setCopied }) {
  const fullUrl = url ? `${globalThis.location.origin}${url}` : '';
  return (
    <>
      <WebhookUrlBlock token={token} fullUrl={fullUrl} copied={copied} onCopy={(t, k) => _copyWebhook(t, k, setCopied)} />
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={() => _regenerateWebhook(pid, setToken, setUrl, setRegenerating)} disabled={regenerating}
          style={{ background: regenerating ? '#1a1c22' : '#cc2233', border: 'none', borderRadius: 5, padding: '7px 14px', cursor: regenerating ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          {(() => { if (regenerating) { return 'Generating...'; } if (token) { return 'Regenerate token'; } return 'Generate token'; })()}
        </button>
        {token && (
          <button onClick={() => _copyWebhook(token, 'token', setCopied)}
            style={{ background: copied === 'token' ? '#39d35322' : '#1a1c22', border: `1px solid ${copied === 'token' ? '#39d353' : '#2a2d35'}`, borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: copied === 'token' ? '#39d353' : '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
            {copied === 'token' ? 'Token copied!' : 'Copy token'}
          </button>
        )}
      </div>
      <div style={{ fontSize: 10, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Supported event types</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
        {WEBHOOK_EVENT_TYPES.map(({ type, color, desc }) => (
          <div key={type} title={desc}
            style={{ background: `${color}18`, border: `1px solid ${color}44`, borderRadius: 12, padding: '3px 10px', fontSize: 10, color, fontFamily: 'JetBrains Mono', cursor: 'default' }}>
            {type}
          </div>
        ))}
      </div>
      <WebhookExampleBlock examplePayload={WEBHOOK_EXAMPLE_PAYLOAD} fullUrl={fullUrl} copied={copied} onCopy={(t, k) => _copyWebhook(t, k, setCopied)} />
    </>
  );
}
WebhookBody.propTypes = {
  token: PropTypes.any,
  url: PropTypes.any,
  copied: PropTypes.any,
  regenerating: PropTypes.any,
  pid: PropTypes.any,
  setToken: PropTypes.any,
  setUrl: PropTypes.any,
  setRegenerating: PropTypes.any,
  setCopied: PropTypes.any,
};

export default function WebhookPanel({ pid, accent }) {
  const [token, setToken] = useState('');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);
  const [copied, setCopied] = useState('');

  useEffect(() => { _loadWebhook(pid, setToken, setUrl, setLoading); }, [pid]);

  if (loading) return <div style={{ color: '#404550', fontSize: 12 }}>Loading...</div>;
  return <WebhookBody token={token} url={url} copied={copied} regenerating={regenerating}
    pid={pid} setToken={setToken} setUrl={setUrl} setRegenerating={setRegenerating} setCopied={setCopied} />;
}
WebhookPanel.propTypes = {
  pid: PropTypes.any,
  accent: PropTypes.any,
};
