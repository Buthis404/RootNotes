import { useState, useRef } from 'react';
import JSZip from 'jszip';
import Icon from './Icon.jsx';
import { api } from '../api.js';
import { inferHostRole } from '../utils/hostMeta.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

const shortDomain = (s) => (s || '').toLowerCase();
const hostnameOnly = (fqdn) => fqdn ? fqdn.split('.')[0].toUpperCase() : '';
const tsToDate = (ts) => {
  if (!ts || ts <= 0) return '';
  try { return new Date(ts * 1000).toISOString().slice(0, 10); } catch { return ''; }
};

function detectBHType(obj, filename) {
  const t = obj?.meta?.type;
  if (t) return t.toLowerCase();
  const f = filename.toLowerCase().replace(/.*\//, ''); // strip path from zip entries
  if (f.includes('computer')) return 'computers';
  if (f.includes('user'))     return 'users';
  if (f.includes('group'))    return 'groups';
  if (f.includes('domain'))   return 'domains';
  if (f.includes('gpo'))      return 'gpos';
  if (f.includes('ou'))       return 'ous';
  // BloodHound CE — first item has Kind field
  const kind = (obj?.data?.[0]?.Kind || obj?.data?.[0]?.kind || '').toLowerCase();
  if (kind) return kind + 's';
  return 'unknown';
}

// Recursively expand SID list → set of user SIDs (max 3 levels deep)
function resolveToUserSids(entries, groupMap, depth = 0) {
  const result = new Set();
  if (depth > 3) return result;
  for (const { sid, type } of entries) {
    const t = (type || '').toLowerCase();
    if (t === 'user' || t === 'base') {
      result.add(sid);
    } else if (t === 'group') {
      const grp = groupMap[sid];
      if (grp) {
        const sub = resolveToUserSids(grp.members, groupMap, depth + 1);
        for (const s of sub) result.add(s);
      }
    } else if (t === 'computer') {
      // computer acting as principal — skip for now
    } else {
      // unknown type — treat as user
      result.add(sid);
    }
  }
  return result;
}

// ── Parser ────────────────────────────────────────────────────────────────────

function parseBloodHoundFiles(files) {
  const computerMap = {};
  const userMap     = {};
  const groupMap    = {};
  const domainList  = [];

  const collectEntries = (item, key) => {
    const variants = [key, key.toLowerCase(), key.toUpperCase()];
    for (const v of variants) {
      const block = item[v];
      if (!block) continue;
      const results = block.Results || block.results || [];
      return results.map(r => ({
        sid:  r.ObjectIdentifier || r.objectidentifier || r.MemberSID || r.membersid || '',
        type: r.ObjectType       || r.objecttype       || 'User',
      })).filter(r => r.sid);
    }
    return [];
  };

  // ── Pass 1: build raw maps ─────────────────────────────────────────────────
  for (const { type, obj } of files) {
    const items = obj.data || [];

    if (type === 'computers') {
      for (const item of items) {
        const sid = item.ObjectIdentifier || item.objectidentifier || '';
        if (!sid) continue;
        const p = item.Properties || item.properties || {};

        const fqdn     = p.name || p.Name || '';
        const hostname = hostnameOnly(fqdn);
        const domain   = shortDomain(p.domain || p.Domain || '');
        const ip       = p.ipaddress || p.IPv4Address || p.ipv4address || '';
        const dnsName  = p.dnsname || p.DNSName || '';

        // OS info — combine all available fields
        const osParts = [
          p.operatingsystem || p.OperatingSystem || '',
          p.operatingsystemservicepack || p.OperatingSystemServicePack || '',
        ].filter(Boolean);
        const os = osParts.join(' ').trim();

        // Flags
        const enabled              = p.enabled !== false;
        const haslaps              = !!(p.haslaps || p.HasLAPS);
        const unconstrainedDeleg   = !!(p.unconstraineddelegation || p.UnconstrainedDelegation);
        const constrainedDeleg     = !!(p.trustedtoauth || p.TrustedToAuth || p.AllowedToDelegate);
        const description          = p.description || p.Description || '';
        const isHighValue          = !!(p.highvalue || p.HighValue);
        const lastLogon            = tsToDate(p.lastlogon || p.LastLogon || p.lastlogontimestamp);
        const pwdLastSet           = tsToDate(p.pwdlastset || p.PwdLastSet);

        // SPNs
        const spns = p.serviceprincipalnames || p.ServicePrincipalNames || [];

        // Access rights collections
        const localAdmins   = collectEntries(item, 'LocalAdmins');
        const rdpUsers      = collectEntries(item, 'RemoteDesktopUsers');
        const psRemote      = collectEntries(item, 'PSRemoteUsers');
        const dcomUsers     = collectEntries(item, 'DcomUsers');

        // UserRights — DCSync and other critical rights
        const userRights = item.UserRights || item.userrights || [];
        const dcsyncEntries = [];
        for (const right of userRights) {
          const rightName = right.RightName || right.rightname || '';
          if (rightName === 'DCSync' || rightName === 'GetChangesAll' || rightName === 'GetChanges') {
            (right.Results || right.results || []).forEach(r => {
              dcsyncEntries.push({
                sid:  r.ObjectIdentifier || r.objectidentifier || '',
                type: r.ObjectType || r.objecttype || 'User',
              });
            });
          }
        }

        // Sessions (active user → computer)
        const sessionUserSids = [];
        const sessBlock = item.Sessions || item.sessions || {};
        for (const s of sessBlock.Results || sessBlock.results || []) {
          const usid = s.UserSID || s.usersid || s.UserObjectIdentifier || '';
          if (usid) sessionUserSids.push(usid);
        }
        // PrivilegedSessions
        const privSessBlock = item.PrivilegedSessions || item.privilegedsessions || {};
        for (const s of privSessBlock.Results || privSessBlock.results || []) {
          const usid = s.UserSID || s.usersid || '';
          if (usid && !sessionUserSids.includes(usid)) sessionUserSids.push(usid);
        }

        // Constrained delegation targets — can be SID refs or SPN strings
        const delegTargets = [];
        for (const d of item.AllowedToDelegate || item.allowedtodelegate || []) {
          const ref = d.ObjectIdentifier || d.objectidentifier || d.Value || d.value || '';
          const dtype = (d.ObjectType || d.objecttype || '').toLowerCase();
          if (ref) delegTargets.push({ ref, type: dtype || 'computer' });
        }

        computerMap[sid] = {
          sid, fqdn, hostname, domain, ip, dnsName, os, enabled,
          haslaps, unconstrainedDeleg, constrainedDeleg, isHighValue,
          description, lastLogon, pwdLastSet, spns,
          localAdmins, rdpUsers, psRemote, dcomUsers,
          dcsyncEntries, sessionUserSids, delegTargets,
        };
      }
    }

    if (type === 'users') {
      for (const item of items) {
        const sid = item.ObjectIdentifier || item.objectidentifier || '';
        if (!sid) continue;
        const p = item.Properties || item.properties || {};

        const name   = p.name || p.Name || '';
        const sam    = p.samaccountname || p.SamAccountName || name.split('@')[0] || '';
        const domain = shortDomain(p.domain || p.Domain || '');

        // Flags
        const enabled           = p.enabled !== false;
        const adminCount        = !!(p.admincount || p.AdminCount);
        const hasspn            = !!(p.hasspn || p.HasSPN);
        const dontreqpreauth    = !!(p.dontreqpreauth || p.DontReqPreAuth);
        const pwdneverexpires   = !!(p.pwdneverexpires || p.PwdNeverExpires);
        const passwordnotreqd   = !!(p.passwordnotreqd || p.PasswordNotReqd);
        const sensitive         = !!(p.sensitive || p.Sensitive);
        const unconstrainedDeleg= !!(p.unconstraineddelegation || p.UnconstrainedDelegation);

        // Info fields
        const description  = p.description  || p.Description  || '';
        const displayname  = p.displayname  || p.DisplayName  || '';
        const email        = p.email        || p.Email        || '';
        const title        = p.title        || p.Title        || '';
        const lastLogon    = tsToDate(p.lastlogon || p.LastLogon || p.lastlogontimestamp);
        const pwdLastSet   = tsToDate(p.pwdlastset || p.PwdLastSet);

        // SPNs (Kerberoastable if non-empty)
        const spns = p.serviceprincipalnames || p.ServicePrincipalNames || [];

        // Group memberships (will be filled in pass 2 from groups.json)
        const memberOfSids = (item.MemberOf || item.memberof || []).map(m =>
          m.ObjectIdentifier || m.objectidentifier || ''
        ).filter(Boolean);

        // AllowedToDelegate targets
        const delegTargets = (item.AllowedToDelegate || item.allowedtodelegate || []).map(m =>
          m.ObjectIdentifier || m.objectidentifier || m.Value || m.value || ''
        ).filter(Boolean);

        userMap[sid] = {
          sid, name, sam, domain, enabled, adminCount,
          hasspn: hasspn || spns.length > 0,
          dontreqpreauth, pwdneverexpires, passwordnotreqd, sensitive,
          unconstrainedDeleg,
          description, displayname, email, title,
          lastLogon, pwdLastSet, spns, memberOfSids, delegTargets,
          isDA: false, isEA: false, isSchemaAdmin: false,
          groupNames: [],
        };
      }
    }

    if (type === 'groups') {
      for (const item of items) {
        const sid = item.ObjectIdentifier || item.objectidentifier || '';
        if (!sid) continue;
        const p = item.Properties || item.properties || {};
        const name = p.name || p.Name || '';
        const members = (item.Members || item.members || []).map(m => ({
          sid:  m.ObjectIdentifier || m.objectidentifier || '',
          type: m.ObjectType       || m.objecttype       || 'User',
        })).filter(m => m.sid);
        groupMap[sid] = { sid, name, members };
      }
    }

    if (type === 'domains') {
      for (const item of items) {
        const p = item.Properties || item.properties || {};
        const trusts = (item.Trusts || item.trusts || []).map(t => ({
          target: shortDomain(t.TargetDomainName || t.targetdomainname || ''),
          direction: t.TrustDirection || t.trustdirection || '',
          kind: t.TrustType || t.trusttype || '',
        }));
        domainList.push({
          name: shortDomain(p.name || p.Name || p.domain || ''),
          sid: item.ObjectIdentifier || '',
          functional: p.functionallevel || p.FunctionalLevel || '',
          trusts,
        });
      }
    }
  }

  // ── Pass 2: resolve roles from groups ─────────────────────────────────────
  for (const grp of Object.values(groupMap)) {
    const upper = grp.name.toUpperCase();
    const isDA  = /^DOMAIN ADMINS@/.test(upper)  || upper === 'DOMAIN ADMINS';
    const isEA  = /^ENTERPRISE ADMINS@/.test(upper) || upper === 'ENTERPRISE ADMINS';
    const isSA  = /^SCHEMA ADMINS@/.test(upper)   || upper === 'SCHEMA ADMINS';

    for (const m of grp.members) {
      const u = userMap[m.sid];
      if (u) {
        if (isDA) u.isDA = true;
        if (isEA) u.isEA = true;
        if (isSA) u.isSchemaAdmin = true;
        // Track ALL groups
        if (!u.groupNames.includes(grp.name)) u.groupNames.push(grp.name);
      }
    }

    // Also resolve users from memberOf on user objects
    for (const u of Object.values(userMap)) {
      if (u.memberOfSids.includes(grp.sid) && !u.groupNames.includes(grp.name)) {
        u.groupNames.push(grp.name);
        if (isDA) u.isDA = true;
        if (isEA) u.isEA = true;
        if (isSA) u.isSchemaAdmin = true;
      }
    }
  }

  // ── Pass 3: resolve group SIDs → user SIDs in access rights ───────────────
  const computers = Object.values(computerMap).map(c => ({
    ...c,
    laUserSids:      resolveToUserSids(c.localAdmins,    groupMap),
    rdpUserSids:     resolveToUserSids(c.rdpUsers,       groupMap),
    psRemoteUserSids:resolveToUserSids(c.psRemote,       groupMap),
    dcomUserSids:    resolveToUserSids(c.dcomUsers,      groupMap),
    dcsyncUserSids:  resolveToUserSids(c.dcsyncEntries,  groupMap),
  }));

  const users = Object.values(userMap);

  // SID → user lookup (O(1) instead of O(n) find)
  const userBySid = userMap;

  // ── Stats ──────────────────────────────────────────────────────────────────
  let relCount = 0;
  for (const c of computers) {
    relCount += c.laUserSids.size + c.rdpUserSids.size + c.psRemoteUserSids.size + c.dcsyncUserSids.size;
  }

  // Count potential network map edges
  let mapEdgeCount = 0;
  // session-based: for each comp, count users with sessions on other comps
  const userSessionCompsPreview = {};
  for (const c of computers) {
    for (const usid of c.sessionUserSids) {
      if (!userSessionCompsPreview[usid]) userSessionCompsPreview[usid] = 0;
      userSessionCompsPreview[usid]++;
    }
  }
  for (const c of computers) {
    for (const sid of c.laUserSids)       if (userSessionCompsPreview[sid]) mapEdgeCount++;
    for (const sid of c.dcsyncUserSids)   if (userSessionCompsPreview[sid]) mapEdgeCount++;
    mapEdgeCount += c.delegTargets?.length || 0;
  }

  return {
    computers, users, groupMap, domainList, userBySid,
    stats: {
      computers:     computers.length,
      users:         users.length,
      daUsers:       users.filter(u => u.isDA).length,
      eaUsers:       users.filter(u => u.isEA).length,
      kerberoastable:users.filter(u => u.hasspn && u.enabled).length,
      asreproastable:users.filter(u => u.dontreqpreauth && u.enabled).length,
      relationships: relCount,
      lapsHosts:     computers.filter(c => c.haslaps).length,
      unconstrHosts: computers.filter(c => c.unconstrainedDeleg).length,
      mapEdges:      mapEdgeCount,
    },
  };
}

// ── Build host tags from BH data ──────────────────────────────────────────────
function buildHostTags(c) {
  const tags = ['bloodhound'];
  const role = inferHostRole({
    os: c.os,
    ports: c.spns?.some(spn => String(spn).toLowerCase().includes('http')) ? ['80'] : [],
    services: c.spns?.some(spn => String(spn).toLowerCase().includes('http')) ? ['http'] : [],
    domain: c.domain,
    tags: c.dcsyncUserSids?.size > 0 ? ['dc'] : [],
  });
  if (c.haslaps)             tags.push('laps');
  if (c.unconstrainedDeleg)  tags.push('unconstrained-delegation');
  if (c.constrainedDeleg)    tags.push('constrained-delegation');
  if (c.isHighValue)         tags.push('high-value');
  if (c.spns?.length)        tags.push('spn');
  if (c.dcsyncUserSids?.size > 0) tags.push('dc');
  if (!c.enabled)            tags.push('disabled');
  if (role.id === 'dc')      tags.push('domain-controller');
  if (role.id === 'workstation') tags.push('workstation');
  if (role.id === 'web')     tags.push('web');
  if (role.id === 'server')  tags.push('server');
  return tags;
}

// Build notes string for host
function buildHostNotes(c) {
  const lines = [];
  const role = inferHostRole({
    os: c.os,
    ports: c.spns?.some(spn => String(spn).toLowerCase().includes('http')) ? ['80'] : [],
    services: c.spns?.some(spn => String(spn).toLowerCase().includes('http')) ? ['http'] : [],
    domain: c.domain,
    tags: c.dcsyncUserSids?.size > 0 ? ['dc'] : [],
  });
  if (c.description)       lines.push(`[BH] ${c.description}`);
  lines.push(`[BH] Role: ${role.label}`);
  lines.push(`[BH] Status: ${c.enabled ? 'enabled' : 'disabled'}`);
  if (c.haslaps)           lines.push('[BH] LAPS enabled');
  if (c.unconstrainedDeleg)lines.push('[BH] Unconstrained delegation!');
  if (c.constrainedDeleg)  lines.push('[BH] Constrained delegation (TrustedToAuth)');
  if (c.isHighValue)       lines.push('[BH] High value asset');
  if (c.spns?.length)      lines.push(`[BH] SPNs: ${c.spns.slice(0, 3).join(', ')}${c.spns.length > 3 ? '...' : ''}`);
  if (c.lastLogon)         lines.push(`[BH] Last logon: ${c.lastLogon}`);
  if (c.pwdLastSet)        lines.push(`[BH] Pwd last set: ${c.pwdLastSet}`);
  return lines.join('\n');
}

// Build notes string for credential
function buildCredNotes(u) {
  const lines = [];
  if (u.domain) lines.push(`Domain: ${u.domain}`);
  lines.push(`Status: ${u.enabled ? 'enabled' : 'disabled'}`);
  if (u.isDA)           lines.push('⚡ Domain Admin');
  if (u.isEA)           lines.push('⚡ Enterprise Admin');
  if (u.isSchemaAdmin)  lines.push('Schema Admin');
  if (u.adminCount)     lines.push('AdminCount=1');
  if (u.hasspn)         lines.push('Kerberoastable (has SPN)');
  if (u.dontreqpreauth) lines.push('AS-REP Roastable');
  if (u.pwdneverexpires)lines.push('Password never expires');
  if (u.passwordnotreqd)lines.push('Password not required');
  if (u.sensitive)      lines.push('Marked as sensitive');
  if (u.unconstrainedDeleg) lines.push('Unconstrained delegation!');
  if (u.description)    lines.push(`Description: ${u.description}`);
  if (u.displayname && u.displayname !== u.sam) lines.push(`Display name: ${u.displayname}`);
  if (u.email)          lines.push(`Email: ${u.email}`);
  if (u.title)          lines.push(`Title: ${u.title}`);
  if (u.lastLogon)      lines.push(`Last logon: ${u.lastLogon}`);
  if (u.pwdLastSet)     lines.push(`Pwd last set: ${u.pwdLastSet}`);
  if (u.spns?.length)   lines.push(`SPNs: ${u.spns.slice(0, 2).join(', ')}`);
  // Top group memberships (excluding default DA/EA already noted)
  const extraGroups = u.groupNames.filter(g => {
    const up = g.toUpperCase();
    return !up.includes('DOMAIN ADMINS') && !up.includes('ENTERPRISE ADMINS') &&
           !up.includes('SCHEMA ADMINS') && !up.includes('DOMAIN USERS') &&
           !up.includes('EVERYONE') && !up.includes('AUTHENTICATED USERS');
  });
  if (extraGroups.length) lines.push(`Groups: ${extraGroups.slice(0, 4).join(', ')}${extraGroups.length > 4 ? '...' : ''}`);
  return lines.join('\n');
}

function buildCredTags(u) {
  const tags = ['bloodhound'];
  if (!u.enabled) tags.push('disabled');
  if (u.isDA) tags.push('domain-admin');
  if (u.isEA) tags.push('enterprise-admin');
  if (u.isSchemaAdmin) tags.push('schema-admin');
  if (u.adminCount) tags.push('admincount');
  if (u.hasspn) tags.push('kerberoastable');
  if (u.dontreqpreauth) tags.push('asrep-roastable');
  if (u.pwdneverexpires) tags.push('password-never-expires');
  if (u.passwordnotreqd) tags.push('password-not-required');
  if (u.sensitive) tags.push('sensitive');
  if (u.unconstrainedDeleg) tags.push('unconstrained-delegation');
  return tags;
}

// ── Component ─────────────────────────────────────────────────────────────────

const PHASES = [
  'Importing hosts',
  'Importing credentials',
  'Fetching updated data',
  'Setting access relationships',
  'Updating network maps',
];

export default function BloodHoundParser({ accent, pid, onClose, onDone }) {
  const [tab, setTab]           = useState('summary');
  const [parsed, setParsed]     = useState(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError]       = useState('');
  const [importing, setImporting] = useState(false);
  const [progress, setProgress]   = useState(null);
  const [importOptions, setImportOptions] = useState({
    hosts: true,
    creds: true,
    relationships: true,
    networkEdges: true,
  });
  const fileInputRef = useRef();

  // ── File loading ────────────────────────────────────────────────────────────
  const parseJsonFile = async (text, filename) => {
    const obj  = JSON.parse(text);
    const type = detectBHType(obj, filename);
    return type !== 'unknown' ? { type, obj, filename } : null;
  };

  const loadZipFile = async (file) => {
    const zip = await JSZip.loadAsync(file);
    const out = [];
    for (const [name, entry] of Object.entries(zip.files)) {
      if (!name.endsWith('.json') || entry.dir) continue;
      try {
        const text = await entry.async('text');
        const r = await parseJsonFile(text, name);
        if (r) out.push(r);
      } catch {}
    }
    return out;
  };

  const handleFiles = async (rawFiles) => {
    setError('');
    let loaded = [];
    for (const file of rawFiles) {
      if (file.name.endsWith('.zip')) {
        try { loaded = loaded.concat(await loadZipFile(file)); }
        catch (e) { setError(`ZIP error: ${file.name} — ${e.message}`); return; }
      } else if (file.name.endsWith('.json')) {
        try {
          const text = await file.text();
          const r = await parseJsonFile(text, file.name);
          if (r) loaded.push(r);
        } catch { setError(`Parse error: ${file.name}`); return; }
      }
    }
    if (!loaded.length) { setError('No recognised BloodHound JSON files found'); return; }
    setParsed(parseBloodHoundFiles(loaded));
    setTab('summary');
  };

  const onDrop = (e) => {
    e.preventDefault(); setDragging(false);
    handleFiles(Array.from(e.dataTransfer.files).filter(f => f.name.endsWith('.json') || f.name.endsWith('.zip')));
  };

  // ── Import ──────────────────────────────────────────────────────────────────
  const doImport = async () => {
    if (!parsed) return;
    setImporting(true); setError('');

    try {
      // ── Phase 1: hosts ────────────────────────────────────────────────────
      const hostPayload = parsed.computers.map(c => ({
        pid,
        ip: c.ip || c.hostname || 'unknown',
        hostname: c.hostname,
        os: c.os || 'Windows',
        domain: c.domain,
        status: c.enabled ? 'alive' : 'unknown',
        ports: [], services: [], ips: c.ip ? [c.ip] : [],
        tags: buildHostTags(c),
        notes: buildHostNotes(c),
      }));
      setProgress({ phase: 0, cur: 0, total: importOptions.hosts ? hostPayload.length : 1 });
      if (importOptions.hosts && hostPayload.length) {
        await api.batchImport(pid, { hosts: hostPayload, creds: [] });
        setProgress({ phase: 0, cur: hostPayload.length, total: hostPayload.length });
      } else {
        setProgress({ phase: 0, cur: 1, total: 1 });
      }

      // ── Phase 2: credentials ──────────────────────────────────────────────
      setProgress({ phase: 1, cur: 0, total: importOptions.creds ? parsed.users.length : 1 });
      const existingCreds = await api.getCreds(pid);

      // Build credential key from username (handles both "user" and "user@domain" formats)
      const credKey = (username) => (username || '').toLowerCase().trim();

      // Index existing domain creds — match by either bare sam or sam@domain
      const credByKey = {};
      for (const c of existingCreds) {
        if (!c.is_domain) continue;
        const k = credKey(c.username);
        credByKey[k] = c;
      }

      let credsDone = 0;
      for (const u of parsed.users) {
        if (!importOptions.creds) break;
        const sam    = (u.sam || u.name.split('@')[0]).trim();
        // Use sam@domain when domain is known to avoid collisions in multi-domain pentests
        const fullName = u.domain ? `${sam}@${u.domain}` : sam;
        const key      = credKey(fullName);
        const altKey   = credKey(sam); // fallback match against bare sam (legacy creds)
        const notes = buildCredNotes(u);
        const tags = buildCredTags(u);

        // Also keep a parallel index for Phase 4 matching by SID
        u._credUsername = fullName;

        const existing = credByKey[key] || credByKey[altKey];
        if (existing) {
          // Merge notes — only add lines not already present
          const existingLines = new Set((existing.notes || '').split('\n').map(l => l.trim()));
          const newLines = notes.split('\n').filter(l => l.trim() && !existingLines.has(l.trim()));
          const mergedNotes = newLines.length
            ? (existing.notes || '').trimEnd() + '\n' + newLines.join('\n')
            : existing.notes || '';
          if (mergedNotes !== (existing.notes || '')) {
            const mergedTags = [...new Set([...(existing.tags || []), ...tags])];
            const updated = await api.updateCred(existing.id, { notes: mergedNotes.trim(), tags: mergedTags });
            credByKey[key] = updated;
          } else {
            const mergedTags = [...new Set([...(existing.tags || []), ...tags])];
            if (JSON.stringify(mergedTags) !== JSON.stringify(existing.tags || [])) {
              const updated = await api.updateCred(existing.id, { tags: mergedTags });
              credByKey[key] = updated;
            }
          }
        } else {
          try {
            const created = await api.createCred({
              pid, username: fullName, secret: '', type: 'password',
              host: '', service: 'AD', cracked: false, is_domain: true, notes, tags,
            });
            credByKey[key] = created;
          } catch {}
        }

        credsDone++;
        setProgress({ phase: 1, cur: credsDone, total: parsed.users.length });
      }
      if (!importOptions.creds) setProgress({ phase: 1, cur: 1, total: 1 });

      // ── Phase 3: fetch fresh IDs ──────────────────────────────────────────
      setProgress({ phase: 2, cur: 0, total: 1 });
      const [freshHosts, freshCreds] = await Promise.all([api.getHosts(pid), api.getCreds(pid)]);
      setProgress({ phase: 2, cur: 1, total: 1 });

      const hostByHostname = {};
      const hostByIp       = {};
      for (const h of freshHosts) {
        if (h.hostname) hostByHostname[h.hostname.toUpperCase()] = h;
        if (h.ip)       hostByIp[h.ip] = h;
      }
      // Index fresh creds by full username AND bare sam (to support both formats)
      const credByUsername = {};
      for (const c of freshCreds) {
        if (!c.is_domain) continue;
        const uname = (c.username || '').toLowerCase();
        credByUsername[uname] = c;
        // Also index by bare sam (without @domain part)
        const bareSam = uname.split('@')[0];
        if (!credByUsername[bareSam]) credByUsername[bareSam] = c;
      }

      // ── Phase 4: access relationships ─────────────────────────────────────
      // Build all (cred_id, host_id) → roles[] map
      const relMap = {};
      const findCredForUser = (u) => {
        const sam      = (u.sam || u.name.split('@')[0]).toLowerCase();
        const fullName = (u._credUsername || (u.domain ? `${sam}@${u.domain}` : sam)).toLowerCase();
        return credByUsername[fullName] || credByUsername[sam] || null;
      };
      const addRel = (comp, sid, roles) => {
        const host = hostByHostname[comp.hostname] || hostByIp[comp.ip] || null;
        if (!host) return;
        const u = parsed.userBySid[sid];
        if (!u) return;
        const cred = findCredForUser(u);
        if (!cred) return;
        const key = `${cred.id}::${host.id}`;
        if (!relMap[key]) relMap[key] = { cred_id: cred.id, host_id: host.id, pid, roles: new Set(), notes: '' };
        for (const r of roles) relMap[key].roles.add(r);
      };

      for (const comp of parsed.computers) {
        for (const sid of comp.laUserSids)       addRel(comp, sid, ['local_admin']);
        for (const sid of comp.rdpUserSids)       addRel(comp, sid, ['rdp']);
        for (const sid of comp.psRemoteUserSids)  addRel(comp, sid, ['winrm']);
        // DCSync → treat as domain_admin level
        for (const sid of comp.dcsyncUserSids)    addRel(comp, sid, ['domain_admin']);
        // Active sessions → note but no role toggle (sessions are dynamic)
        for (const usid of comp.sessionUserSids) {
          const u = parsed.userBySid[usid];
          if (!u) continue;
          const host = hostByHostname[comp.hostname] || hostByIp[comp.ip] || null;
          if (!host) continue;
          const cred = findCredForUser(u);
          if (!cred) continue;
          const key = `${cred.id}::${host.id}`;
          if (!relMap[key]) relMap[key] = { cred_id: cred.id, host_id: host.id, pid, roles: new Set(), notes: '' };
          if (!relMap[key].notes.includes('Active session')) {
            relMap[key].notes = (relMap[key].notes ? relMap[key].notes + '\n' : '') + 'Active session observed (BloodHound)';
          }
        }
      }

      const mergedRels = Object.values(relMap).map(r => ({ ...r, roles: [...r.roles] }));
      let relsDone = 0;
      setProgress({ phase: 3, cur: 0, total: importOptions.relationships ? mergedRels.length : 1 });

      for (const r of mergedRels) {
        if (!importOptions.relationships) break;
        try {
          const existing = await api.getCredHostNotes({ cred_id: r.cred_id, host_id: r.host_id });
          if (existing?.length) {
            const cur = existing[0];
            const mergedAccess = [...new Set([...(cur.access || []), ...r.roles])];
            const mergedNotes  = r.notes && !cur.notes?.includes(r.notes)
              ? ((cur.notes || '').trimEnd() + '\n' + r.notes).trim()
              : cur.notes || '';
            const changed = mergedAccess.length !== (cur.access || []).length ||
              mergedNotes !== (cur.notes || '');
            if (changed) await api.updateCredHostNote(cur.id, { access: mergedAccess, notes: mergedNotes });
          } else {
            await api.upsertCredHostNote({ cred_id: r.cred_id, host_id: r.host_id, pid, notes: r.notes, access: r.roles });
          }
        } catch {}
        relsDone++;
        setProgress({ phase: 3, cur: relsDone, total: mergedRels.length });
      }
      if (!importOptions.relationships) setProgress({ phase: 3, cur: 1, total: 1 });

      // ── Phase 5: network map edges ────────────────────────────────────────
      setProgress({ phase: 4, cur: 0, total: 1 });
      try {
        if (!importOptions.networkEdges) {
          setProgress({ phase: 4, cur: 1, total: 1 });
        } else {
        const networks = await api.getNetworks(pid);

        // Build SID → computer lookup
        const compBySid = {};
        for (const c of parsed.computers) compBySid[c.sid] = c;

        // Build userSid → [computerSid] from sessions (where that user has active session)
        const userSessionComps = {}; // userSid → Set<computerSid>
        for (const comp of parsed.computers) {
          for (const usid of comp.sessionUserSids) {
            if (!userSessionComps[usid]) userSessionComps[usid] = new Set();
            userSessionComps[usid].add(comp.sid);
          }
        }

        // Edge type definitions: { fromSid, toSid, label, style }
        // style: 'lateral' | 'exploit' | 'tunnel' | 'normal'
        const bhEdges = []; // { fromHostname, fromIp, toHostname, toIp, label, style }

        const edgeKey = new Set();
        const addEdge = (fromComp, toComp, label, style) => {
          if (!fromComp || !toComp || fromComp.sid === toComp.sid) return;
          const k = `${fromComp.sid}→${toComp.sid}:${label}`;
          if (edgeKey.has(k)) return;
          edgeKey.add(k);
          bhEdges.push({ fromHostname: fromComp.hostname, fromIp: fromComp.ip, toHostname: toComp.hostname, toIp: toComp.ip, label, style });
        };

        for (const targetComp of parsed.computers) {
          // Session-based lateral movement: userHasSessionOnSrc → targetComp via LA/RDP/WRM
          const accessMap = [
            { sids: targetComp.laUserSids,       label: 'LA',    style: 'lateral' },
            { sids: targetComp.rdpUserSids,       label: 'RDP',   style: 'normal'  },
            { sids: targetComp.psRemoteUserSids,  label: 'WinRM', style: 'normal'  },
          ];
          for (const { sids, label, style } of accessMap) {
            for (const userSid of sids) {
              const srcComps = userSessionComps[userSid] || new Set();
              for (const srcSid of srcComps) {
                addEdge(compBySid[srcSid], targetComp, label, style);
              }
            }
          }

          // DCSync: user has DCSync on targetComp (DC), user has session on srcComp
          for (const userSid of targetComp.dcsyncUserSids) {
            const srcComps = userSessionComps[userSid] || new Set();
            for (const srcSid of srcComps) {
              addEdge(compBySid[srcSid], targetComp, 'DCSync', 'exploit');
            }
            // Also: if DA user has local admin on some comp → draw LA-comp → DC
            for (const srcComp of parsed.computers) {
              if (srcComp.sid === targetComp.sid) continue;
              if (srcComp.laUserSids.has(userSid)) {
                addEdge(srcComp, targetComp, 'DCSync path', 'exploit');
              }
            }
          }

          // Constrained delegation: targetComp can delegate to delegTarget
          for (const dt of targetComp.delegTargets) {
            // dt.ref may be SID or SPN string like "HOST/dc01.domain.com"
            let destComp = null;
            if (dt.ref.includes('/')) {
              // SPN — extract hostname
              const spnHost = dt.ref.split('/')[1]?.split(':')[0]?.split('.')[0]?.toUpperCase();
              if (spnHost) destComp = parsed.computers.find(c => c.hostname === spnHost) || null;
            } else {
              // SID
              destComp = compBySid[dt.ref] || null;
            }
            if (destComp) addEdge(targetComp, destComp, 'delegate', 'tunnel');
          }
        }

        // Domain trust edges
        for (const dom of parsed.domainList) {
          for (const trust of dom.trusts || []) {
            // Trust edges are between domains — we'll create them if domain nodes exist on map
            // Domain nodes are identified by label matching domain name
            bhEdges.push({ fromDomain: dom.name, toDomain: trust.target, label: `trust:${trust.direction || '?'}`, style: 'tunnel' });
          }
        }

        // Now apply edges to each network map
        let netsUpdated = 0;
        for (const net of networks) {
          const nodes  = net.nodes  || [];
          const edges  = net.edges  || [];
          const regions = net.regions || [];
          if (!nodes.length) continue;

          // Build node lookup: hostname → nodeId, ip → nodeId, label → nodeId
          const nodeByHostname = {};
          const nodeByIp       = {};
          const nodeByLabel    = {};
          for (const n of nodes) {
            if (n.label) nodeByLabel[n.label.toUpperCase()] = n.id;
            if (n.ip)    nodeByIp[n.ip] = n.id;
            // Try to match hostname from label (label may be hostname or FQDN)
            const hn = (n.label || '').split('.')[0].toUpperCase();
            if (hn) nodeByHostname[hn] = n.id;
          }

          const existingKeys = new Set(edges.map(e => `${e.from}→${e.to}:${e.label}`));
          const newEdges = [];

          for (const e of bhEdges) {
            if (e.fromDomain !== undefined) {
              // Domain trust edge
              const fromId = nodeByLabel[e.fromDomain?.toUpperCase()] || nodeByHostname[e.fromDomain?.split('.')[0]?.toUpperCase()];
              const toId   = nodeByLabel[e.toDomain?.toUpperCase()]   || nodeByHostname[e.toDomain?.split('.')[0]?.toUpperCase()];
              if (fromId && toId && fromId !== toId) {
                const k = `${fromId}→${toId}:${e.label}`;
                if (!existingKeys.has(k)) { existingKeys.add(k); newEdges.push({ id: 'ebh' + Date.now() + Math.random().toString(36).slice(2, 6), from: fromId, to: toId, label: e.label, style: e.style }); }
              }
              continue;
            }
            const fromId = nodeByHostname[e.fromHostname] || nodeByIp[e.fromIp];
            const toId   = nodeByHostname[e.toHostname]   || nodeByIp[e.toIp];
            if (!fromId || !toId || fromId === toId) continue;
            const k = `${fromId}→${toId}:${e.label}`;
            if (!existingKeys.has(k)) {
              existingKeys.add(k);
              newEdges.push({ id: 'ebh' + Date.now() + Math.random().toString(36).slice(2, 6), from: fromId, to: toId, label: e.label, style: e.style });
            }
          }

          if (newEdges.length) {
            await api.updateNetwork(net.id, { nodes, edges: [...edges, ...newEdges], regions });
            netsUpdated++;
          }
        }

        setProgress({ phase: 4, cur: 1, total: 1 });
        }
      } catch {} // network map update is best-effort

      if (onDone) onDone();
      onClose();
    } catch (e) {
      setError('Import error: ' + (e.message || String(e)));
      setImporting(false);
      setProgress(null);
    }
  };

  // ── UI helpers ───────────────────────────────────────────────────────────────
  const badge = (color, text) => (
    <span style={{ fontSize: 8, color, background: color + '22', border: `1px solid ${color}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', display: 'inline-block', whiteSpace: 'nowrap' }}>
      {text}
    </span>
  );
  const th = { padding: '5px 8px', textAlign: 'left', color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 9, fontWeight: 600, borderBottom: '1px solid #1e2029', whiteSpace: 'nowrap' };
  const td = { padding: '4px 8px', borderBottom: '1px solid #0e1016', verticalAlign: 'top' };
  const mono = { fontFamily: 'JetBrains Mono', fontSize: 10 };

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <div style={{ position: 'fixed', inset: 0, background: '#00000099', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
         onClick={e => e.target === e.currentTarget && !importing && onClose()}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 10, width: 860, maxHeight: '90vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 64px #000000cc' }}>

        {/* Header */}
        <div style={{ padding: '12px 16px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: '#e0e4ec', fontFamily: 'Space Grotesk', flex: 1 }}>🩸 BloodHound Parser</span>
          {parsed && <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono' }}>
            {parsed.stats.computers} computers · {parsed.stats.users} users · {parsed.stats.daUsers} DA · {parsed.stats.kerberoastable} kerberoastable · {parsed.stats.relationships} access rels
          </span>}
          {!importing && <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={13} color="#606570" /></button>}
        </div>

        {/* Drop zone */}
        {!parsed && (
          <div onDrop={onDrop} onDragOver={e => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)}
               style={{ margin: 20, border: `2px dashed ${dragging ? accent : '#2a2d35'}`, borderRadius: 8, padding: '48px 20px', textAlign: 'center', cursor: 'pointer', background: dragging ? accent + '08' : 'transparent' }}
               onClick={() => fileInputRef.current?.click()}>
            <div style={{ fontSize: 34, marginBottom: 12 }}>🩸</div>
            <div style={{ fontSize: 13, color: '#c8cdd6', fontWeight: 700, fontFamily: 'Space Grotesk', marginBottom: 8 }}>Drop SharpHound / BloodHound exports</div>
            <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', lineHeight: 2 }}>
              ZIP archive (SharpHound output) · или отдельные JSON файлы<br/>
              computers · users · groups · domains
            </div>
            <input ref={fileInputRef} type="file" accept=".json,.zip" multiple style={{ display: 'none' }}
                   onChange={e => handleFiles(Array.from(e.target.files))} />
          </div>
        )}

        {/* Error */}
        {error && <div style={{ margin: '0 16px 8px', padding: '6px 10px', background: '#cc223320', border: '1px solid #cc223344', borderRadius: 4, fontSize: 10, color: '#e05060', fontFamily: 'JetBrains Mono' }}>{error}</div>}

        {/* Progress */}
        {importing && progress && (
          <div style={{ padding: '24px 28px', flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 18 }}>
            {PHASES.map((ph, i) => {
              const done   = i < progress.phase;
              const active = i === progress.phase;
              const pct = active && progress.total > 0 ? Math.round(progress.cur / progress.total * 100) : done ? 100 : 0;
              return (
                <div key={i}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
                    <span style={{ width: 18, height: 18, borderRadius: '50%', background: done ? '#39d353' : active ? accent : '#1a1c22', border: `1px solid ${done ? '#39d353' : active ? accent : '#2a2d35'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, color: '#fff', flexShrink: 0, fontFamily: 'JetBrains Mono' }}>
                      {done ? '✓' : i + 1}
                    </span>
                    <span style={{ fontSize: 11, color: done ? '#39d353' : active ? '#e0e4ec' : '#404550', fontFamily: 'Space Grotesk', flex: 1 }}>{ph}</span>
                    {active && <span style={{ fontSize: 9, color: accent, fontFamily: 'JetBrains Mono' }}>{progress.cur} / {progress.total}</span>}
                    {done && <span style={{ fontSize: 9, color: '#39d35380', fontFamily: 'JetBrains Mono' }}>done</span>}
                  </div>
                  <div style={{ height: 3, background: '#1a1c22', borderRadius: 2, marginLeft: 28 }}>
                    <div style={{ height: '100%', width: pct + '%', background: done ? '#39d353' : active ? accent : 'transparent', borderRadius: 2, transition: 'width .15s' }} />
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Tabs */}
        {parsed && !importing && <>
          <div style={{ display: 'flex', borderBottom: '1px solid #1e2029', padding: '0 14px', flexShrink: 0, overflowX: 'auto' }}>
            {[
              { id: 'summary',   label: 'Summary' },
              { id: 'computers', label: `Computers (${parsed.computers.length})` },
              { id: 'users',     label: `Users (${parsed.users.length})` },
              { id: 'relations', label: `Access (${parsed.stats.relationships})` },
              { id: 'domains',   label: `Domains (${parsed.domainList.length})` },
            ].map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                style={{ background: 'none', border: 'none', borderBottom: `2px solid ${tab === t.id ? accent : 'transparent'}`, padding: '8px 12px', cursor: 'pointer', color: tab === t.id ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: tab === t.id ? 700 : 400, marginBottom: -1, whiteSpace: 'nowrap' }}>
                {t.label}
              </button>
            ))}
            <button onClick={() => { setParsed(null); setError(''); }} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '0 8px', whiteSpace: 'nowrap' }}>← New files</button>
          </div>

          <div style={{ flex: 1, overflowY: 'auto' }}>

            {tab === 'summary' && (
              <div style={{ padding: '14px 16px 0' }}>
                <div style={{ background: '#12141a', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px' }}>
                  <div style={{ fontSize: 10, color: '#9098a8', fontFamily: 'Space Grotesk', fontWeight: 700, marginBottom: 8 }}>Import objects</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {[
                      ['hosts', `Hosts (${parsed.computers.length})`],
                      ['creds', `Creds (${parsed.users.length})`],
                      ['relationships', `Access rels (${parsed.stats.relationships})`],
                      ['networkEdges', `Network edges (~${parsed.stats.mapEdges})`],
                    ].map(([key, label]) => (
                      <label key={key} style={{ display: 'flex', alignItems: 'center', gap: 6, background: importOptions[key] ? accent + '14' : '#0e1016', border: `1px solid ${importOptions[key] ? accent + '44' : '#2a2d35'}`, borderRadius: 4, padding: '5px 8px', cursor: 'pointer', color: importOptions[key] ? '#e0e4ec' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                        <input type="checkbox" checked={importOptions[key]} onChange={e => setImportOptions(prev => ({ ...prev, [key]: e.target.checked }))} style={{ accentColor: accent }} />
                        {label}
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── SUMMARY ── */}
            {tab === 'summary' && (
              <div style={{ padding: 16, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
                {[
                  { label: 'Computers',       value: parsed.stats.computers,     color: '#5b8af5', sub: 'hosts to create/update' },
                  { label: 'Users',           value: parsed.stats.users,         color: '#39d353', sub: 'creds to create/update' },
                  { label: 'Domain Admins',   value: parsed.stats.daUsers,       color: '#e8574a', sub: 'in DA group' },
                  { label: 'Enterprise Adm.', value: parsed.stats.eaUsers,       color: '#f09a3a', sub: 'in EA group' },
                  { label: 'Kerberoastable',  value: parsed.stats.kerberoastable,color: '#e8cc42', sub: 'users with SPN' },
                  { label: 'AS-REP Roast.',   value: parsed.stats.asreproastable,color: '#f09a3a', sub: 'no preauth required' },
                  { label: 'Access rels.',    value: parsed.stats.relationships,  color: accent,    sub: 'LA / RDP / WRM / DCSync' },
                  { label: 'LAPS hosts',      value: parsed.stats.lapsHosts,     color: '#39d353', sub: 'local admin pwd mgmt' },
                  { label: 'Unconstr. deleg.',value: parsed.stats.unconstrHosts,  color: '#cc2233', sub: 'high value targets' },
                  { label: 'Map edges',       value: parsed.stats.mapEdges,       color: '#6fc8f0', sub: 'lateral / DCSync / delegate' },
                ].map(card => (
                  <div key={card.label} style={{ background: '#12141a', border: `1px solid ${card.color}33`, borderRadius: 6, padding: '10px 12px' }}>
                    <div style={{ fontSize: 22, fontWeight: 800, color: card.color, fontFamily: 'JetBrains Mono', lineHeight: 1 }}>{card.value}</div>
                    <div style={{ fontSize: 10, color: '#e0e4ec', fontFamily: 'Space Grotesk', fontWeight: 600, marginTop: 3 }}>{card.label}</div>
                    <div style={{ fontSize: 8, color: '#404550', fontFamily: 'JetBrains Mono', marginTop: 2 }}>{card.sub}</div>
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1', background: '#12141a', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 14px', fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono', lineHeight: 1.9 }}>
                  <div style={{ color: '#9098a8', marginBottom: 4, fontWeight: 600, fontSize: 10 }}>Import plan</div>
                  <div>• Hosts: upsert by IP or hostname. Updates OS, domain, notes, tags, BH flags and inferred host role.</div>
                  <div>• Creds: creates missing AD creds, enriches notes with roles, flags, status, groups and metadata.</div>
                  <div>• Access: LA → local_admin · RDP → rdp · PSRemote → winrm · DCSync → domain_admin</div>
                  <div>• Sessions: пишет заметку "Active session observed" в cred_host_notes</div>
                  <div>• Existing roles сохраняются, новые добавляются</div>
                  <div>• Network maps: рисует рёбра на всех картах сети где есть совпадающие ноды:</div>
                  <div style={{ paddingLeft: 12 }}>session+LA → lateral · session+DCSync → exploit · delegation → tunnel · domain trust → tunnel</div>
                </div>
              </div>
            )}

            {/* ── COMPUTERS ── */}
            {tab === 'computers' && (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                <thead>
                  <tr>
                    <th style={th}>Hostname</th>
                    <th style={th}>IP</th>
                    <th style={th}>Domain</th>
                    <th style={th}>OS</th>
                    <th style={th}>Flags</th>
                    <th style={th}>LA</th>
                    <th style={th}>RDP</th>
                    <th style={th}>WRM</th>
                    <th style={th}>DCSync</th>
                    <th style={th}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {parsed.computers.map((c, i) => (
                    <tr key={i}>
                      <td style={{ ...td, ...mono, color: '#e0e4ec' }}>{c.hostname}</td>
                      <td style={{ ...td, ...mono, color: '#9098a8' }}>{c.ip || <span style={{ color: '#303540' }}>—</span>}</td>
                      <td style={td}>{c.domain ? badge('#c07af0', c.domain) : <span style={{ color: '#303540' }}>—</span>}</td>
                      <td style={{ ...td, color: '#606570', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9 }}>{c.os || '—'}</td>
                      <td style={{ ...td, display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                        {c.haslaps            && badge('#39d353', 'LAPS')}
                        {c.unconstrainedDeleg && badge('#cc2233', 'UNC-DELEG')}
                        {c.constrainedDeleg   && badge('#f09a3a', 'CONSTRAINED')}
                        {c.isHighValue        && badge('#e8cc42', 'HIGH-VAL')}
                      </td>
                      <td style={td}>{badge(c.laUserSids.size ? '#e8574a' : '#2a2d35', c.laUserSids.size)}</td>
                      <td style={td}>{badge(c.rdpUserSids.size ? '#5b8af5' : '#2a2d35', c.rdpUserSids.size)}</td>
                      <td style={td}>{badge(c.psRemoteUserSids.size ? '#39d353' : '#2a2d35', c.psRemoteUserSids.size)}</td>
                      <td style={td}>{badge(c.dcsyncUserSids.size ? '#cc2233' : '#2a2d35', c.dcsyncUserSids.size)}</td>
                      <td style={td}>{badge(c.enabled ? '#39d353' : '#404550', c.enabled ? 'on' : 'off')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {/* ── USERS ── */}
            {tab === 'users' && (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                <thead>
                  <tr>
                    <th style={th}>Username</th>
                    <th style={th}>Domain</th>
                    <th style={th}>Roles / Flags</th>
                    <th style={th}>Description</th>
                    <th style={th}>Last logon</th>
                    <th style={th}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {parsed.users.map((u, i) => (
                    <tr key={i}>
                      <td style={{ ...td, ...mono, color: '#e0e4ec' }}>{u.sam || u.name}</td>
                      <td style={td}>{u.domain ? badge('#c07af0', u.domain) : <span style={{ color: '#303540' }}>—</span>}</td>
                      <td style={{ ...td }}>
                        <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                          {u.isDA            && badge('#e8574a', 'DA')}
                          {u.isEA            && badge('#f09a3a', 'EA')}
                          {u.isSchemaAdmin   && badge('#f09a3a', 'SchemaAdmin')}
                          {u.adminCount      && badge('#f09a3a', 'AdminCount')}
                          {u.hasspn          && badge('#e8cc42', 'Kerberoast')}
                          {u.dontreqpreauth  && badge('#e8cc42', 'ASREPRoast')}
                          {u.pwdneverexpires && badge('#5b8af5', 'PwdNoExp')}
                          {u.passwordnotreqd && badge('#cc2233', 'NoPwd')}
                          {u.sensitive       && badge('#c07af0', 'Sensitive')}
                          {u.unconstrainedDeleg && badge('#cc2233', 'UNC-DELEG')}
                        </div>
                      </td>
                      <td style={{ ...td, color: '#808590', fontSize: 9, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={u.description}>{u.description || '—'}</td>
                      <td style={{ ...td, ...mono, color: '#606570', fontSize: 9 }}>{u.lastLogon || '—'}</td>
                      <td style={td}>{badge(u.enabled ? '#39d353' : '#404550', u.enabled ? 'on' : 'off')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {/* ── RELATIONS ── */}
            {tab === 'relations' && (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                <thead>
                  <tr>
                    <th style={th}>Computer</th>
                    <th style={th}>User</th>
                    <th style={th}>Domain</th>
                    <th style={th}>Access</th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const rows = [];
                    const addRows = (comp, sids, access, color) => {
                      for (const sid of sids) {
                        const u = parsed.userBySid[sid];
                        if (u) rows.push({ computer: comp.hostname, user: u.sam || u.name, domain: u.domain, access, color });
                      }
                    };
                    for (const c of parsed.computers) {
                      addRows(c, c.laUserSids,       'Local Admin', '#e8574a');
                      addRows(c, c.rdpUserSids,       'RDP',         '#5b8af5');
                      addRows(c, c.psRemoteUserSids,  'WinRM',       '#39d353');
                      addRows(c, c.dcsyncUserSids,    'DCSync',      '#cc2233');
                    }
                    if (!rows.length) return (
                      <tr><td colSpan={4} style={{ ...td, color: '#404550', textAlign: 'center', padding: 24 }}>
                        No access relationships — load computers.json with LocalAdmins / RemoteDesktopUsers data
                      </td></tr>
                    );
                    return rows.map((r, i) => (
                      <tr key={i}>
                        <td style={{ ...td, ...mono, color: '#9098a8' }}>{r.computer}</td>
                        <td style={{ ...td, ...mono, color: '#e0e4ec' }}>{r.user}</td>
                        <td style={td}>{r.domain ? badge('#c07af0', r.domain) : '—'}</td>
                        <td style={td}>{badge(r.color, r.access)}</td>
                      </tr>
                    ));
                  })()}
                </tbody>
              </table>
            )}

            {/* ── DOMAINS ── */}
            {tab === 'domains' && (
              <div style={{ padding: 16 }}>
                {parsed.domainList.length === 0 && <div style={{ color: '#404550', fontSize: 10, fontFamily: 'JetBrains Mono' }}>No domain data — load domains.json</div>}
                {parsed.domainList.map((d, i) => (
                  <div key={i} style={{ background: '#12141a', borderRadius: 5, padding: '10px 14px', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: d.trusts?.length ? 8 : 0 }}>
                      {badge('#c07af0', 'AD')}
                      <span style={{ fontSize: 12, color: '#c07af0', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>{d.name}</span>
                      {d.functional && <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono' }}>FL: {d.functional}</span>}
                      <span style={{ fontSize: 8, color: '#303540', fontFamily: 'JetBrains Mono' }}>{d.sid}</span>
                    </div>
                    {d.trusts?.map((t, j) => (
                      <div key={j} style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono', paddingLeft: 14 }}>
                        Trust → {t.target} ({t.direction} / {t.kind})
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div style={{ padding: '10px 16px', borderTop: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', flex: 1 }}>
              {parsed.stats.computers} hosts · {parsed.stats.users} creds · {parsed.stats.relationships} access · ~{parsed.stats.mapEdges} map edges
            </span>
            <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '6px 14px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Cancel</button>
            <button onClick={doImport} style={{ background: accent, border: 'none', borderRadius: 5, padding: '6px 20px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
              Import selected
            </button>
          </div>
        </>}
      </div>
    </div>
  );
}
