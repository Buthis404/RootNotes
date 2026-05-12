export function inp() {
  return { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };
}

export function toolbarBtn(color, solid) {
  return {
    background: solid ? color : 'transparent',
    color: solid ? '#fff' : color,
    border: solid ? 'none' : `1px solid ${color}44`,
    borderRadius: 5,
    padding: '7px 12px',
    cursor: 'pointer',
    fontSize: 11,
    fontFamily: 'JetBrains Mono',
    fontWeight: 600,
  };
}

export function toggleBtn(active, accent) {
  return {
    background: active ? `${accent}22` : '#13161f',
    border: `1px solid ${active ? accent + '66' : '#1e2230'}`,
    borderRadius: 4,
    padding: '5px 10px',
    cursor: 'pointer',
    color: active ? accent : '#808590',
    fontSize: 10,
    fontFamily: 'JetBrains Mono',
  };
}

export const CRON_PRESETS = [
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Every 6h',   value: '0 */6 * * *' },
  { label: 'Daily 2am',  value: '0 2 * * *' },
  { label: 'Mon 8am',    value: '0 8 * * 1' },
];
