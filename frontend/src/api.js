const BASE = '/api';

function getToken() {
  return localStorage.getItem('rt_token') || '';
}

async function req(method, path, body, authRequired = true) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const opts = { method, headers };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  if (res.status === 204) return null;
  if (res.status === 401 && authRequired) {
    localStorage.removeItem('rt_token');
    window.dispatchEvent(new Event('rt:logout'));
    throw new Error('Unauthorized');
  }
  if (res.status === 409) {
    const data = await res.json();
    const err = new Error('conflict');
    err.status = 409;
    err.serverNote = data.detail;
    throw err;
  }
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    try { msg = JSON.parse(text).detail || text; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

export const api = {
  // Auth
  authStatus:  ()       => req('GET',  '/auth/status',  undefined, false),
  authSetup:   (data)   => req('POST', '/auth/setup',   data, false),
  authLogin:   (data)   => req('POST', '/auth/login',   data, false),
  authMe:      ()       => req('GET',  '/auth/me'),

  // Admin – user management
  adminListUsers:   ()        => req('GET',    '/admin/users'),
  adminCreateUser:  (data)    => req('POST',   '/admin/users',      data),
  adminUpdateUser:  (id, data)=> req('PATCH',  `/admin/users/${id}`, data),
  adminDeleteUser:  (id)      => req('DELETE', `/admin/users/${id}`),

  // Projects
  getProjects:   ()       => req('GET',    '/projects'),
  createProject: (data)   => req('POST',   '/projects',        data),
  updateProject: (id, data)=> req('PATCH', `/projects/${id}`,  data),
  deleteProject: (id)     => req('DELETE', `/projects/${id}`),

  // Notes
  getNotes:            (pid)    => req('GET',    `/notes${pid ? `?pid=${pid}` : ''}`),
  createNote:          (data)   => req('POST',   '/notes',              data),
  updateNote:          (id, data)=> req('PATCH', `/notes/${id}`,        data),
  deleteNote:          (id)     => req('DELETE', `/notes/${id}`),
  getNoteAttachments:  (id)     => req('GET',    `/notes/${id}/attachments`),
  uploadNoteAttachment: async (id, file) => {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(BASE + `/notes/${id}/attachments`, {
      method: 'POST', body: form,
      headers: { 'Authorization': `Bearer ${getToken()}` },
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
  deleteAttachment: (id) => req('DELETE', `/attachments/${id}`),

  // Hosts
  getHosts:    (pid)     => req('GET',    `/hosts${pid ? `?pid=${pid}` : ''}`),
  createHost:  (data)    => req('POST',   '/hosts',          data),
  updateHost:  (id, data)=> req('PATCH',  `/hosts/${id}`,    data),
  deleteHost:  (id)      => req('DELETE', `/hosts/${id}`),

  // Creds
  getCreds:    (pid)     => req('GET',    `/creds${pid ? `?pid=${pid}` : ''}`),
  createCred:  (data)    => req('POST',   '/creds',          data),
  updateCred:  (id, data)=> req('PATCH',  `/creds/${id}`,    data),
  deleteCred:  (id)      => req('DELETE', `/creds/${id}`),

  // Networks
  getNetworks:    (pid)     => req('GET',    `/networks${pid ? `?pid=${pid}` : ''}`),
  createNetwork:  (data)    => req('POST',   '/networks',        data),
  updateNetwork:  (id, data)=> req('PATCH',  `/networks/${id}`,  data),
  deleteNetwork:  (id)      => req('DELETE', `/networks/${id}`),

  // Findings
  getFindings:    (pid)      => req('GET',    `/findings${pid ? `?pid=${pid}` : ''}`),
  createFinding:  (data)     => req('POST',   '/findings',          data),
  updateFinding:  (id, data) => req('PATCH',  `/findings/${id}`,    data),
  deleteFinding:  (id)       => req('DELETE', `/findings/${id}`),

  // Checklist
  getChecklist:      (pid, phase) => req('GET',    `/checklist?pid=${pid}${phase ? `&phase=${phase}` : ''}`),
  bulkCreateChecklist:(items)     => req('POST',   '/checklist',         items),
  updateChecklistItem:(id, data)  => req('PATCH',  `/checklist/${id}`,   data),
  deleteChecklistItem:(id)        => req('DELETE', `/checklist/${id}`),

  // Timeline
  getTimeline: (pid, entity) => req('GET', `/timeline?pid=${pid}${entity ? `&entity=${entity}` : ''}`),

  // Objectives
  getObjectives:    (pid)      => req('GET',    `/objectives${pid ? `?pid=${pid}` : ''}`),
  createObjective:  (data)     => req('POST',   '/objectives',           data),
  updateObjective:  (id, data) => req('PATCH',  `/objectives/${id}`,     data),
  deleteObjective:  (id)       => req('DELETE', `/objectives/${id}`),

  // Attack Paths
  getAttackPaths:    (pid)          => req('GET',    `/attack-paths${pid ? `?pid=${pid}` : ''}`),
  createAttackPath:  (data)         => req('POST',   '/attack-paths',           data),
  updateAttackPath:  (id, data)     => req('PATCH',  `/attack-paths/${id}`,     data),
  deleteAttackPath:  (id)           => req('DELETE', `/attack-paths/${id}`),

  // Attack Steps
  getAttackSteps:    (pid)          => req('GET',    `/attack-steps${pid ? `?pid=${pid}` : ''}`),
  createAttackStep:  (data)         => req('POST',   '/attack-steps',           data),
  updateAttackStep:  (id, data)     => req('PATCH',  `/attack-steps/${id}`,     data),
  deleteAttackStep:  (id)           => req('DELETE', `/attack-steps/${id}`),

  // Loot
  getLoots:    (pid)      => req('GET',    `/loots${pid ? `?pid=${pid}` : ''}`),
  createLoot:  (data)     => req('POST',   '/loots',          data),
  updateLoot:  (id, data) => req('PATCH',  `/loots/${id}`,    data),
  deleteLoot:  (id)       => req('DELETE', `/loots/${id}`),

  // Scope
  getScopes:    (pid)      => req('GET',    `/scopes${pid ? `?pid=${pid}` : ''}`),
  createScope:  (data)     => req('POST',   '/scopes',          data),
  updateScope:  (id, data) => req('PATCH',  `/scopes/${id}`,    data),
  deleteScope:  (id)       => req('DELETE', `/scopes/${id}`),

  // Host activities
  getHostActivities: (pid, hostId) => req('GET', `/host-activities${pid || hostId ? `?${new URLSearchParams({ ...(pid ? { pid } : {}), ...(hostId ? { host_id: hostId } : {}) }).toString()}` : ''}`),
  createHostActivity: (data) => req('POST', '/host-activities', data),
  updateHostActivity: (id, data) => req('PATCH', `/host-activities/${id}`, data),
  deleteHostActivity: (id) => req('DELETE', `/host-activities/${id}`),

  // Cred-host notes
  getCredHostNotes: (params) => {
    const qs = new URLSearchParams(params).toString();
    return req('GET', `/cred-host-notes${qs ? '?' + qs : ''}`);
  },
  upsertCredHostNote: (data)     => req('POST',   '/cred-host-notes',      data),
  updateCredHostNote: (id, data) => req('PATCH',  `/cred-host-notes/${id}`, data),
  deleteCredHostNote: (id)       => req('DELETE', `/cred-host-notes/${id}`),

  // Search
  search: (q, pid) => req('GET', `/search?q=${encodeURIComponent(q)}${pid ? `&pid=${pid}` : ''}`),

  // Global presence
  getPresence: () => req('GET', '/presence'),

  // Custom finding templates
  listFindingTemplates: () => req('GET', '/finding-templates'),
  listCustomFindingTemplates: () => req('GET', '/finding-templates/custom'),
  createCustomFindingTemplate: (data) => req('POST', '/finding-templates/custom', data),
  deleteCustomFindingTemplate: (id) => req('DELETE', `/finding-templates/custom/${id}`),
  exportFindingTemplates: () => fetch(BASE + '/finding-templates/export', {
    headers: { 'Authorization': `Bearer ${getToken()}` },
  }).then(async res => {
    if (!res.ok) throw new Error(await res.text());
    return res.blob();
  }),
  importFindingTemplates: async (file) => {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(BASE + '/finding-templates/import', {
      method: 'POST', body: form,
      headers: { 'Authorization': `Bearer ${getToken()}` },
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  // Custom snippets
  listSnippets: () => req('GET', '/snippets'),
  listCustomSnippets: () => req('GET', '/snippets/custom'),
  createCustomSnippet: (data) => req('POST', '/snippets/custom', data),
  updateCustomSnippet: (id, data) => req('PATCH', `/snippets/custom/${id}`, data),
  deleteCustomSnippet: (id) => req('DELETE', `/snippets/custom/${id}`),
  exportSnippets: () => fetch(BASE + '/snippets/export', {
    headers: { 'Authorization': `Bearer ${getToken()}` },
  }).then(async res => {
    if (!res.ok) throw new Error(await res.text());
    return res.blob();
  }),
  importSnippets: async (file) => {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(BASE + '/snippets/import', {
      method: 'POST', body: form,
      headers: { 'Authorization': `Bearer ${getToken()}` },
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  // Batch import
  batchImport: (pid, data) => req('POST', `/import/${pid}`, data),

  // Project export/import
  exportProject: (pid) => fetch(BASE + `/export/${pid}`, {
    headers: { 'Authorization': `Bearer ${getToken()}` },
  }).then(async res => {
    if (!res.ok) throw new Error(await res.text());
    return res.blob();
  }),
  importProject: async (file) => {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(BASE + '/import_project', {
      method: 'POST', body: form,
      headers: { 'Authorization': `Bearer ${getToken()}` },
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
};
