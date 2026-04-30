const WEB_PORTS = new Set(['80', '443', '8080', '8443', '8000', '8008']);

export const HOST_ROLES = {
  unknown: { label: 'Unknown', color: '#808590', nodeType: 'server' },
  workstation: { label: 'Workstation', color: '#39d353', nodeType: 'workstation' },
  server: { label: 'Server', color: '#808590', nodeType: 'server' },
  domain_controller: { label: 'Domain Controller', color: '#c07af0', nodeType: 'dc' },
  file_server: { label: 'File Server', color: '#6fc8f0', nodeType: 'server' },
  web_server: { label: 'Web Server', color: '#5b8af5', nodeType: 'web' },
  database: { label: 'Database', color: '#f09a3a', nodeType: 'server' },
  jump_host: { label: 'Jump Host', color: '#e8cc42', nodeType: 'server' },
  attacker: { label: 'Attacker', color: '#cc2233', nodeType: 'attacker' },
  external: { label: 'External', color: '#e8574a', nodeType: 'cloud' },
  network_device: { label: 'Network Device', color: '#6fc8f0', nodeType: 'router' },
  custom: { label: 'Custom', color: '#15bbb1', nodeType: 'server' },
};

function lowerSet(values = []) {
  return new Set(values.map(v => String(v || '').toLowerCase()).filter(Boolean));
}

function includesAny(set, values) {
  return values.some(value => set.has(value));
}

function hasNote(text, needle) {
  return String(text || '').toLowerCase().includes(needle.toLowerCase());
}

export function normalizeDomain(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

export function isAttackerHost(host) {
  return host?.is_attacker === true || host?.role === 'attacker' || host?.status === 'attacker' || (host?.tags || []).some(t => String(t).toLowerCase() === 'attacker');
}

const CRED_TAG_META = {
  bloodhound: { label: 'BH', color: '#c07af0' },
  'domain-admin': { label: 'DA', color: '#e8574a' },
  'enterprise-admin': { label: 'EA', color: '#f09a3a' },
  'schema-admin': { label: 'Schema', color: '#f09a3a' },
  kerberoastable: { label: 'Kerberoast', color: '#e8cc42' },
  'asrep-roastable': { label: 'ASREP', color: '#e8cc42' },
  'password-never-expires': { label: 'PwdNoExp', color: '#5b8af5' },
  'password-not-required': { label: 'NoPwd', color: '#cc2233' },
  sensitive: { label: 'Sensitive', color: '#c07af0' },
  admincount: { label: 'AdminCount', color: '#f09a3a' },
  disabled: { label: 'Disabled', color: '#606570' },
  'unconstrained-delegation': { label: 'UNC-DELEG', color: '#cc2233' },
};

export function getCredTagMeta(tag) {
  const key = String(tag || '').toLowerCase();
  return CRED_TAG_META[key] || { label: tag, color: '#808590' };
}

export function inferHostRole(host) {
  if (isAttackerHost(host)) return { id: 'attacker', label: 'Attacker', color: '#cc2233' };
  if (host?.role && HOST_ROLES[host.role]) {
    const role = HOST_ROLES[host.role];
    return { id: host.role, label: role.label, color: role.color };
  }
  const tags = lowerSet(host?.tags || []);
  const services = lowerSet(host?.services || []);
  const ports = new Set((host?.ports || []).map(p => String(p || '')));
  const os = String(host?.os || '').toLowerCase();

  if (isAttackerHost(host)) return { id: 'attacker', label: 'Attacker', color: '#cc2233' };
  if (includesAny(tags, ['firewall', 'fw'])) return { id: 'firewall', label: 'Firewall', color: '#f09a3a' };
  if (includesAny(tags, ['router'])) return { id: 'router', label: 'Router', color: '#6fc8f0' };
  if (includesAny(tags, ['dc', 'domain-controller']) || services.has('kerberos') || ports.has('88')) {
    return { id: 'dc', label: 'Domain Controller', color: '#c07af0' };
  }
  if (includesAny(tags, ['web']) || [...ports].some(p => WEB_PORTS.has(p)) || [...services].some(s => s.includes('http'))) {
    return { id: 'web', label: 'Web Server', color: '#5b8af5' };
  }
  if (includesAny(tags, ['workstation', 'ws']) || ports.has('3389') || os.includes('windows 10') || os.includes('windows 11')) {
    return { id: 'workstation', label: 'Workstation', color: '#39d353' };
  }
  if (host?.domain || os.includes('server')) return { id: 'server', label: 'Server', color: '#808590' };
  return { id: 'server', label: 'Host', color: '#808590' };
}

export function inferNodeType(host) {
  if (host?.role && HOST_ROLES[host.role]) return HOST_ROLES[host.role].nodeType;
  const role = inferHostRole(host).id;
  if (['attacker', 'firewall', 'router', 'dc', 'web', 'workstation'].includes(role)) return role;
  return 'server';
}

export function hasAutoRoleSignals(host) {
  const tags = lowerSet(host?.tags || []);
  return host?.role || host?.domain || includesAny(tags, ['bloodhound', 'dc', 'domain-controller', 'workstation', 'web', 'server', 'firewall', 'router']);
}

export function getHostBadges(host) {
  const tags = lowerSet(host?.tags || []);
  const notes = String(host?.notes || '');
  const badges = [];
  const role = inferHostRole(host);

  if (role.label !== 'Host') badges.push({ label: role.label, color: role.color });
  if (host?.domain) badges.push({ label: 'AD', color: '#c07af0' });
  if (tags.has('high-value')) badges.push({ label: 'HIGH', color: '#e8cc42' });
  if (tags.has('laps')) badges.push({ label: 'LAPS', color: '#39d353' });
  if (tags.has('unconstrained-delegation')) badges.push({ label: 'UNC-DELEG', color: '#cc2233' });
  if (tags.has('constrained-delegation')) badges.push({ label: 'CONSTR', color: '#f09a3a' });
  if (tags.has('spn')) badges.push({ label: 'SPN', color: '#5b8af5' });
  if (tags.has('disabled') || hasNote(notes, '[bh] disabled')) badges.push({ label: 'Disabled', color: '#606570' });
  return badges;
}

export function getCredBadges(cred) {
  const notes = String(cred?.notes || '');
  const tags = lowerSet(cred?.tags || []);
  const badges = [];

  if (cred?.is_domain) badges.push({ label: 'AD', color: '#f09a3a' });
  if (cred?.cracked) badges.push({ label: 'Cracked', color: '#39d353' });
  if (cred?.secret) badges.push({ label: cred?.type === 'ntlm' ? 'Hash' : 'Secret', color: '#5b8af5' });
  Object.keys(CRED_TAG_META).forEach(tag => {
    if (tags.has(tag)) badges.push(getCredTagMeta(tag));
  });
  if (hasNote(notes, 'domain admin')) badges.push({ label: 'DA', color: '#e8574a' });
  if (hasNote(notes, 'enterprise admin')) badges.push({ label: 'EA', color: '#f09a3a' });
  if (hasNote(notes, 'schema admin')) badges.push({ label: 'Schema', color: '#f09a3a' });
  if (hasNote(notes, 'kerberoastable')) badges.push({ label: 'Kerberoast', color: '#e8cc42' });
  if (hasNote(notes, 'as-rep roastable')) badges.push({ label: 'ASREP', color: '#e8cc42' });
  if (hasNote(notes, 'password never expires')) badges.push({ label: 'PwdNoExp', color: '#5b8af5' });
  if (hasNote(notes, 'password not required')) badges.push({ label: 'NoPwd', color: '#cc2233' });
  if (hasNote(notes, 'marked as sensitive')) badges.push({ label: 'Sensitive', color: '#c07af0' });
  if (hasNote(notes, 'admincount=1')) badges.push({ label: 'AdminCount', color: '#f09a3a' });
  if (hasNote(notes, 'status: disabled')) badges.push({ label: 'Disabled', color: '#606570' });
  return badges;
}

export function summarizeCreds(creds = []) {
  const total = creds.length;
  const withSecrets = creds.filter(c => c.secret).length;
  const hashes = creds.filter(c => c.secret && ['hash', 'ntlm'].includes(c.type)).length;
  const passwords = creds.filter(c => c.secret && !['hash', 'ntlm', 'key', 'token'].includes(c.type)).length;
  const keys = creds.filter(c => c.secret && ['key', 'token'].includes(c.type)).length;
  return { total, withSecrets, hashes, passwords, keys };
}
