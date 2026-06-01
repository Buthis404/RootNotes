import { memo } from 'react';
import PropTypes from 'prop-types';
import { NODE_STATUS } from '../../constants.js';
import { inferNodeType, HOST_ROLES } from '../../utils/hostMeta.js';
import { ROLE_SHORT } from './constants.js';

// Memoised — every node in NetworkView re-creates the parent <g> on each
// WS delta / pan / tweak, but the inner shape only depends on type +
// status + selected. Memo cuts SVG path re-rendering by ~99% on large
// maps. Default referential equality is enough since `accent` is a
// stable string prop in the parent.
export const NodeShape = memo(function NodeShape({ type, status, size = 40, selected, accent }) {
  const sc = NODE_STATUS[status]?.color || '#404550';
  const W = size;
  const H = size;
  const base = { filter: `drop-shadow(0 0 5px ${sc}55)` };

  if (['server', 'web', 'dc', 'workstation', 'attacker'].includes(type)) {
    const isAtt = type === 'attacker';
    const isDC = type === 'dc';
    return (
      <svg width={W} height={H} viewBox="0 0 40 40" style={base}>
        {selected && <rect x="1" y="1" width="38" height="38" rx="7" fill="none" stroke={accent} strokeWidth="2" opacity=".7" />}
        <rect x="4" y="4" width="32" height="32" rx="6" fill={isAtt ? `${sc}33` : '#12141a'} stroke={sc} strokeWidth={isAtt ? 2 : 1.5} />
        {isAtt && <><line x1="20" y1="10" x2="20" y2="30" stroke={sc} strokeWidth="1.5" opacity=".6" /><line x1="10" y1="20" x2="30" y2="20" stroke={sc} strokeWidth="1.5" opacity=".6" /><circle cx="20" cy="20" r="4" fill={sc} opacity=".9" /></>}
        {type === 'server' && <><rect x="10" y="13" width="20" height="5" rx="1.5" fill={sc} opacity=".3" /><rect x="10" y="22" width="20" height="5" rx="1.5" fill={sc} opacity=".2" /><circle cx="14" cy="15.5" r="1.2" fill={sc} opacity=".8" /><circle cx="14" cy="24.5" r="1.2" fill={sc} opacity=".5" /></>}
        {type === 'web' && <><ellipse cx="20" cy="20" rx="8" ry="8" fill="none" stroke={sc} strokeWidth="1.2" opacity=".5" /><line x1="12" y1="20" x2="28" y2="20" stroke={sc} strokeWidth="1" opacity=".5" /><path d="M16 13a12 8 0 010 14" fill="none" stroke={sc} strokeWidth="1" opacity=".4" /></>}
        {type === 'workstation' && <><rect x="10" y="12" width="20" height="13" rx="2" fill="none" stroke={sc} strokeWidth="1.2" opacity=".6" /><rect x="16" y="25" width="8" height="3" rx="1" fill={sc} opacity=".4" /></>}
        {isDC && <><path d="M13 16 L20 12 L27 16 L27 24 L20 28 L13 24Z" fill="none" stroke={sc} strokeWidth="1.3" opacity=".7" /><circle cx="20" cy="20" r="2.5" fill={sc} opacity=".8" /></>}
      </svg>
    );
  }

  if (type === 'firewall') {
    return (
      <svg width={W} height={H} viewBox="0 0 40 40" style={base}>
        {selected && <circle cx="20" cy="20" r="19" fill="none" stroke={accent} strokeWidth="2" opacity=".7" />}
        <path d="M20 4 L34 11 L34 24 C34 31 20 36 20 36 C20 36 6 31 6 24 L6 11Z" fill="#12141a" stroke={sc} strokeWidth="1.5" />
        <path d="M14 19 L18 14 L18 21 L22 16 L22 26 L26 21" fill="none" stroke={sc} strokeWidth="1.5" strokeLinecap="round" opacity=".8" />
      </svg>
    );
  }

  return (
    <svg width={W} height={H} viewBox="0 0 40 40" style={base}>
      {selected && <circle cx="20" cy="20" r="19" fill="none" stroke={accent} strokeWidth="2" opacity=".7" />}
      <circle cx="20" cy="20" r="15" fill="#12141a" stroke={sc} strokeWidth="1.5" />
      <circle cx="20" cy="20" r="8" fill="none" stroke={sc} strokeWidth="1" opacity=".4" />
      <circle cx="20" cy="20" r="3" fill={sc} opacity=".8" />
      {[0, 60, 120, 180, 240, 300].map(a => {
        const r = a * Math.PI / 180;
        return <line key={a} x1={20 + 8 * Math.cos(r)} y1={20 + 8 * Math.sin(r)} x2={20 + 15 * Math.cos(r)} y2={20 + 15 * Math.sin(r)} stroke={sc} strokeWidth="1.2" opacity=".6" />;
      })}
    </svg>
  );
});

NodeShape.propTypes = {
  type: PropTypes.string,
  status: PropTypes.string,
  size: PropTypes.number,
  selected: PropTypes.bool,
  accent: PropTypes.string,
};

export function guessNodeType(host) {
  return inferNodeType(host);
}

export function inferAllRoles(host) {
  if (!host) return [];
  const roles = [];
  const seen = new Set();
  const push = (id) => {
    if (!seen.has(id) && HOST_ROLES[id]) {
      seen.add(id);
      roles.push({ id, ...HOST_ROLES[id], short: ROLE_SHORT[id] || id.slice(0, 3).toUpperCase() });
    }
  };

  if (host.is_attacker || host.role === 'attacker') {
    push('attacker');
    return roles;
  }
  if (host.role && host.role !== 'unknown') push(host.role);

  const tags = new Set((host.tags || []).map(t => String(t).toLowerCase()));
  const ports = new Set((host.ports || []).map(p => String(p).split('/')[0]));
  const WEB_PORTS = new Set(['80', '443', '8080', '8443']);

  if (tags.has('dc') || tags.has('domain-controller') || ports.has('88')) push('domain_controller');
  if ([...ports].some(p => WEB_PORTS.has(p))) push('web_server');
  if (tags.has('pivot') || tags.has('jump') || tags.has('jumphost') || tags.has('jump_host')) push('jump_host');
  if (tags.has('firewall') || tags.has('fw')) push('firewall');
  if (tags.has('router')) push('network_device');
  if (tags.has('db') || tags.has('database') || ports.has('3306') || ports.has('5432') || ports.has('1433')) push('database');
  if (tags.has('external')) push('external');

  return roles.slice(0, 4);
}
