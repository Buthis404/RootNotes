import { useState, useEffect } from 'react';

let _addToast = null;
export function toast(message, type = 'info') {
  if (_addToast) _addToast({ message, type, id: Date.now() + Math.random() });
}
export function toastError(message) { toast(message, 'error'); }
export function toastSuccess(message) { toast(message, 'success'); }
export function toastWarn(message) { toast(message, 'warn'); }

export default function ToastContainer() {
  const [toasts, setToasts] = useState([]);

  useEffect(() => {
    _addToast = (t) => {
      setToasts(prev => [...prev, t]);
      setTimeout(() => setToasts(prev => prev.filter(x => x.id !== t.id)), 4000);
    };
    return () => { _addToast = null; };
  }, []);

  if (!toasts.length) return null;

  const colors = { error: '#cc2233', success: '#39d353', warn: '#f09a3a', info: '#4a9eff' };

  return (
    <div style={{ position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)', zIndex: 9999, display: 'flex', flexDirection: 'column', gap: 8, pointerEvents: 'none' }}>
      {toasts.map(t => (
        <div key={t.id} style={{
          background: '#13151c',
          border: `1px solid ${colors[t.type] || colors.info}55`,
          borderLeft: `3px solid ${colors[t.type] || colors.info}`,
          borderRadius: 6,
          padding: '10px 16px',
          color: '#e0e4ec',
          fontSize: 12,
          fontFamily: 'JetBrains Mono',
          boxShadow: '0 4px 20px #00000080',
          maxWidth: 420,
          pointerEvents: 'auto',
          animation: 'fadeInUp .2s ease',
        }}>
          {t.message}
        </div>
      ))}
      <style>{`@keyframes fadeInUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }`}</style>
    </div>
  );
}
