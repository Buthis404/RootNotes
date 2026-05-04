/**
 * Unified API re-export for backward compatibility.
 * Import from here or from individual domain modules.
 */
import { req, upload, download, BASE, getToken } from './client.js';

export const api = {
  // Auth
  authStatus:  ()         => req('GET',  '/auth/status',  undefined, false),
  authSetup:   (data)     => req('POST', '/auth/setup',   data, false),
  authLogin:   (data)     => req('POST', '/auth/login',   data, false),
  authMe:      ()         => req('GET',  '/auth/me'),
  authUpdateMe:(data)     => req('PATCH','/auth/me',      data),
  authChangePassword: (data) => req('POST', '/auth/change-password', data),

  // Admin
  adminListUsers:   ()          => req('GET',    '/admin/users'),
  adminCreateUser:  (data)      => req('POST',   '/admin/users',       data),
  adminUpdateUser:  (id, data)  => req('PATCH',  `/admin/users/${id}`, data),
  adminDeleteUser:  (id)        => req('DELETE', `/admin/users/${id}`),
  adminListModules:   ()          => req('GET',    '/admin/modules'),
  adminCreateModule:  (data)      => req('POST',   '/admin/modules',       data),
  adminUpdateModule:  (name, data)=> req('PATCH',  `/admin/modules/${encodeURIComponent(name)}`, data),
  adminDeleteModule:  (name)      => req('DELETE', `/admin/modules/${encodeURIComponent(name)}`),
  adminDownloadModuleTemplate: () => download('/admin/modules/template'),
  adminDownloadFrontendModuleTemplate: () => download('/admin/modules/template/frontend'),
  adminValidateModule: (data)     => req('POST',   '/admin/modules/validate', data),
  adminUploadModule:    (file)    => upload('/admin/modules/upload', file),
  adminGetAttackerSSHConfig: ()   => req('GET', '/admin/modules/attacker-ssh/config'),
  adminCreateAttackerTarget: (data) => req('POST', '/admin/modules/attacker-ssh/targets', data),
  adminUpdateAttackerTarget: (id, data) => req('PATCH', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}`, data),
  adminDeleteAttackerTarget: (id) => req('DELETE', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}`),
  adminTestAttackerTarget: (id)   => req('POST', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}/test`),
  adminTestAttackerSSH: (data)    => req('POST', '/admin/modules/attacker-ssh/test', data),
  adminExecuteAttackerSSH: (data) => req('POST', '/admin/modules/attacker-ssh/execute', data),

  // Projects
  getProjects:   ()         => req('GET',    '/projects'),
  createProject: (data)     => req('POST',   '/projects',        data),
  updateProject: (id, data) => req('PATCH',  `/projects/${id}`,  data),
  deleteProject: (id)       => req('DELETE', `/projects/${id}`),

  // Notes
  getNotes:             (pid)       => req('GET',    `/notes${pid ? `?pid=${pid}` : ''}`),
  createNote:           (data)      => req('POST',   '/notes',               data),
  updateNote:           (id, data)  => req('PATCH',  `/notes/${id}`,         data),
  deleteNote:           (id)        => req('DELETE', `/notes/${id}`),
  getNoteAttachments:   (id)        => req('GET',    `/notes/${id}/attachments`),
  uploadNoteAttachment: (id, file)  => upload(`/notes/${id}/attachments`, file),
  deleteAttachment:     (id)        => req('DELETE', `/attachments/${id}`),

  // Hosts
  getHosts:    (pid)        => req('GET',    `/hosts${pid ? `?pid=${pid}` : ''}`),
  createHost:  (data)       => req('POST',   '/hosts',          data),
  updateHost:  (id, data)   => req('PATCH',  `/hosts/${id}`,    data),
  deleteHost:  (id)         => req('DELETE', `/hosts/${id}`),

  // Creds
  getCreds:    (pid)        => req('GET',    `/creds${pid ? `?pid=${pid}` : ''}`),
  createCred:  (data)       => req('POST',   '/creds',          data),
  updateCred:  (id, data)   => req('PATCH',  `/creds/${id}`,    data),
  deleteCred:  (id)         => req('DELETE', `/creds/${id}`),

  // Networks
  getNetworks:    (pid)       => req('GET',    `/networks${pid ? `?pid=${pid}` : ''}`),
  createNetwork:  (data)      => req('POST',   '/networks',        data),
  updateNetwork:  (id, data)  => req('PATCH',  `/networks/${id}`,  data),
  deleteNetwork:  (id)        => req('DELETE', `/networks/${id}`),
  createNetworkNode:         (pid, data) => req('POST',   `/projects/${pid}/network/nodes`, data),
  updateNetworkNode:         (pid, nodeId, networkId, data) => req('PATCH',  `/projects/${pid}/network/nodes/${nodeId}?network_id=${encodeURIComponent(networkId)}`, data),
  updateNetworkNodePosition: (pid, nodeId, networkId, data) => req('PATCH',  `/projects/${pid}/network/nodes/${nodeId}/position?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkNode:         (pid, nodeId, networkId) => req('DELETE', `/projects/${pid}/network/nodes/${nodeId}?network_id=${encodeURIComponent(networkId)}`),
  createNetworkLink:         (pid, data) => req('POST',   `/projects/${pid}/network/links`, data),
  updateNetworkLink:         (pid, linkId, networkId, data) => req('PATCH',  `/projects/${pid}/network/links/${linkId}?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkLink:         (pid, linkId, networkId) => req('DELETE', `/projects/${pid}/network/links/${linkId}?network_id=${encodeURIComponent(networkId)}`),
  createNetworkRegion:       (pid, data) => req('POST',   `/projects/${pid}/network/regions`, data),
  updateNetworkRegion:       (pid, regionId, networkId, data) => req('PATCH',  `/projects/${pid}/network/regions/${regionId}?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkRegion:       (pid, regionId, networkId) => req('DELETE', `/projects/${pid}/network/regions/${regionId}?network_id=${encodeURIComponent(networkId)}`),

  // Findings
  getFindings:    (pid)       => req('GET',    `/findings${pid ? `?pid=${pid}` : ''}`),
  createFinding:  (data)      => req('POST',   '/findings',          data),
  updateFinding:  (id, data)  => req('PATCH',  `/findings/${id}`,    data),
  deleteFinding:  (id)        => req('DELETE', `/findings/${id}`),

  // Checklist
  getChecklist:       (pid, phase) => req('GET',    `/checklist?pid=${pid}${phase ? `&phase=${phase}` : ''}`),
  bulkCreateChecklist: (items)     => req('POST',   '/checklist',         items),
  updateChecklistItem: (id, data)  => req('PATCH',  `/checklist/${id}`,   data),
  deleteChecklistItem: (id)        => req('DELETE', `/checklist/${id}`),

  // Timeline
  getTimeline: (pid, entity) => req('GET', `/timeline?pid=${pid}${entity ? `&entity=${entity}` : ''}`),

  // Objectives
  getObjectives:    (pid)       => req('GET',    `/objectives${pid ? `?pid=${pid}` : ''}`),
  createObjective:  (data)      => req('POST',   '/objectives',           data),
  updateObjective:  (id, data)  => req('PATCH',  `/objectives/${id}`,     data),
  deleteObjective:  (id)        => req('DELETE', `/objectives/${id}`),

  // Attack Paths
  getAttackPaths:   (pid)       => req('GET',    `/attack-paths${pid ? `?pid=${pid}` : ''}`),
  createAttackPath: (data)      => req('POST',   '/attack-paths',           data),
  updateAttackPath: (id, data)  => req('PATCH',  `/attack-paths/${id}`,     data),
  deleteAttackPath: (id)        => req('DELETE', `/attack-paths/${id}`),

  // Attack Steps
  getAttackSteps:   (pid)       => req('GET',    `/attack-steps${pid ? `?pid=${pid}` : ''}`),
  createAttackStep: (data)      => req('POST',   '/attack-steps',           data),
  updateAttackStep: (id, data)  => req('PATCH',  `/attack-steps/${id}`,     data),
  deleteAttackStep: (id)        => req('DELETE', `/attack-steps/${id}`),

  // Loot
  getLoots:    (pid)       => req('GET',    `/loots${pid ? `?pid=${pid}` : ''}`),
  createLoot:  (data)      => req('POST',   '/loots',          data),
  updateLoot:  (id, data)  => req('PATCH',  `/loots/${id}`,    data),
  deleteLoot:  (id)        => req('DELETE', `/loots/${id}`),
  uploadLootFile: (id, file) => upload(`/loots/${id}/file`, file),

  // Scope
  getScopes:    (pid)      => req('GET',    `/scopes${pid ? `?pid=${pid}` : ''}`),
  createScope:  (data)     => req('POST',   '/scopes',          data),
  updateScope:  (id, data) => req('PATCH',  `/scopes/${id}`,    data),
  deleteScope:  (id)       => req('DELETE', `/scopes/${id}`),

  // Host activities
  getHostActivities:  (pid, hostId) => req('GET', `/host-activities${pid || hostId ? `?${new URLSearchParams({ ...(pid ? { pid } : {}), ...(hostId ? { host_id: hostId } : {}) }).toString()}` : ''}`),
  createHostActivity: (data)        => req('POST',   '/host-activities',          data),
  updateHostActivity: (id, data)    => req('PATCH',  `/host-activities/${id}`,    data),
  deleteHostActivity: (id)          => req('DELETE', `/host-activities/${id}`),
  executeAttackerCommand: (pid, data) => req('POST', `/projects/${pid}/attacker-exec`, data),
  listAttackerExecutionTargets: (pid) => req('GET', `/projects/${pid}/attacker-exec/targets`),

  // Cred-host notes
  getCredHostNotes:   (params)      => { const qs = new URLSearchParams(params).toString(); return req('GET', `/cred-host-notes${qs ? '?' + qs : ''}`); },
  upsertCredHostNote: (data)        => req('POST',   '/cred-host-notes',       data),
  updateCredHostNote: (id, data)    => req('PATCH',  `/cred-host-notes/${id}`, data),
  deleteCredHostNote: (id)          => req('DELETE', `/cred-host-notes/${id}`),

  // Search & presence
  search:      (q, pid) => req('GET', `/search?q=${encodeURIComponent(q)}${pid ? `&pid=${pid}` : ''}`),
  getPresence: ()        => req('GET', '/presence'),
  listModules: ()        => req('GET', '/modules'),
  listConnectors: ()     => req('GET', '/connectors'),

  // Finding templates
  listFindingTemplates:        ()       => req('GET',    '/finding-templates'),
  listCustomFindingTemplates:  ()       => req('GET',    '/finding-templates/custom'),
  createCustomFindingTemplate: (data)   => req('POST',   '/finding-templates/custom', data),
  deleteCustomFindingTemplate: (id)     => req('DELETE', `/finding-templates/custom/${id}`),
  exportFindingTemplates:      ()       => download('/finding-templates/export'),
  importFindingTemplates:      (file)   => upload('/finding-templates/import', file),

  // Snippets
  listSnippets:        ()           => req('GET',    '/snippets'),
  listCustomSnippets:  ()           => req('GET',    '/snippets/custom'),
  createCustomSnippet: (data)       => req('POST',   '/snippets/custom',     data),
  updateCustomSnippet: (id, data)   => req('PATCH',  `/snippets/custom/${id}`, data),
  deleteCustomSnippet: (id)         => req('DELETE', `/snippets/custom/${id}`),
  exportSnippets:      ()           => download('/snippets/export'),
  importSnippets:      (file)       => upload('/snippets/import', file),

  // Batch import & project export/import
  batchImport:   (pid, data) => req('POST', `/import/${pid}`, data),
  exportProject: (pid)       => download(`/export/${pid}`),
  importProject: (file)      => upload('/import_project', file),

  // Topology
  topologyPreview: (pid, formData) => {
    const token = localStorage.getItem('rt_token') || '';
    return fetch(`/api/projects/${pid}/topology/preview`, {
      method: 'POST', body: formData,
      headers: { 'Authorization': `Bearer ${token}` },
    }).then(async res => {
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    });
  },
  topologyApply:         (pid, data)    => req('POST', `/projects/${pid}/topology/apply`,          data),
  topologyRebuildLayout: (pid, data)    => req('POST', `/projects/${pid}/topology/rebuild-layout`, data),
  topologyAutoBuild:     (pid, data)    => req('POST', `/projects/${pid}/topology/auto-build`,     data),
  getTopology:           (pid)          => req('GET',  `/projects/${pid}/topology`),
  getTopologySources:    (pid)          => req('GET',  `/projects/${pid}/topology/sources`),

  // Project members
  getProjectMembers:       (pid)             => req('GET',    `/projects/${pid}/members`),
  getProjectAvailableUsers:(pid)             => req('GET',    `/projects/${pid}/available-users`),
  addProjectMember:        (pid, data)       => req('POST',   `/projects/${pid}/members`,            data),
  bulkAddProjectMembers:   (pid, data)       => req('POST',   `/projects/${pid}/members/bulk`,       data),
  updateProjectMember:     (pid, uid, data)  => req('PATCH',  `/projects/${pid}/members/${uid}`,     data),
  removeProjectMember:     (pid, uid)        => req('DELETE', `/projects/${pid}/members/${uid}`),
  transferOwnership:       (pid, data)       => req('POST',   `/projects/${pid}/transfer-ownership`, data),
  getMyProjectPermissions: (pid)             => req('GET',    `/projects/${pid}/permissions/me`),

  // CSV exports
  exportHostsCsv:    (pid) => download(`/projects/${pid}/export/hosts.csv`),
  exportFindingsCsv: (pid) => download(`/projects/${pid}/export/findings.csv`),
  exportCredsCsv:    (pid) => download(`/projects/${pid}/export/creds.csv`),

  // Project templates
  listProjectTemplates:  ()           => req('GET',  '/project-templates'),
  applyProjectTemplate:  (templateId) => req('POST', `/project-templates/${templateId}/apply`),

  // Bulk host import
  bulkImportHosts: (data) => req('POST', '/hosts/bulk', data),

  // Scans (nmap/nuclei/cme via attacker SSH)
  runNmapScan:    (pid, data) => req('POST', `/projects/${pid}/scans/nmap`,   data),
  runNucleiScan:  (pid, data) => req('POST', `/projects/${pid}/scans/nuclei`, data),
  runCmeScan:     (pid, data) => req('POST', `/projects/${pid}/scans/cme`,    data),

  // Webhooks (C2)
  getProjectWebhook:        (pid)  => req('GET',  `/projects/${pid}/webhook`),
  regenerateProjectWebhook: (pid)  => req('POST', `/projects/${pid}/webhook/regenerate`),

  // C2 integrations
  listC2Integrations:    ()              => req('GET',    '/admin/c2'),
  createC2Integration:   (data)          => req('POST',   '/admin/c2',            data),
  updateC2Integration:   (id, data)      => req('PATCH',  `/admin/c2/${id}`,      data),
  deleteC2Integration:   (id)            => req('DELETE', `/admin/c2/${id}`),
  testC2Integration:     (id)            => req('POST',   `/admin/c2/${id}/test`),
  syncC2ToProject:       (id, pid)       => req('POST',   `/admin/c2/${id}/sync/${pid}`),
  listC2ForProject:      (pid)           => req('GET',    `/admin/c2/for-project/${pid}`),
  getC2LiveSessions:     (pid)           => req('GET',    `/admin/c2/sessions/${pid}`),

  // Bulk actions
  bulkExec:      (pid, data)           => req('POST', `/projects/${pid}/bulk-exec`,                data),
  validateCred:  (pid, credId, data)   => req('POST', `/projects/${pid}/creds/${credId}/validate`, data),

  // Jobs
  listJobs:   (pid, params = {}) => {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([,v]) => v != null))).toString();
    return req('GET', `/projects/${pid}/jobs${qs ? `?${qs}` : ''}`);
  },
  getJob:     (pid, jobId) => req('GET',    `/projects/${pid}/jobs/${jobId}`),
  deleteJob:  (pid, jobId) => req('DELETE', `/projects/${pid}/jobs/${jobId}`),
  cancelJob:  (pid, jobId) => req('PATCH',  `/projects/${pid}/jobs/${jobId}/cancel`),
  rerunJob:   (pid, jobId) => req('POST',   `/projects/${pid}/jobs/${jobId}/rerun`),
  retryJob:   (pid, jobId) => req('POST',   `/projects/${pid}/jobs/${jobId}/retry`),

  // Playbooks
  listPlaybooks: () => req('GET', '/playbooks'),
  runPlaybook: (pid, playbookId, data) => req('POST', `/projects/${pid}/playbooks/${encodeURIComponent(playbookId)}/run`, data),
  listPlaybookRuns: (pid, params = {}) => {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null))).toString();
    return req('GET', `/projects/${pid}/playbook-runs${qs ? `?${qs}` : ''}`);
  },
  getPlaybookRun: (pid, runId) => req('GET', `/projects/${pid}/playbook-runs/${runId}`),
};
