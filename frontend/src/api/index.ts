/**
 * Unified API client.
 *
 * All functions return Promise<unknown> — response shapes are not yet typed.
 * Add specific return types here as TypeScript migration progresses (B7-7).
 */
import { req, upload, download } from './client.js';

type ParamValue = string | number | null;

export const api = {
  // Auth
  authStatus:  ()         => req('GET',  '/auth/status',  undefined, false),
  authSetup:   (data: unknown)     => req('POST', '/auth/setup',   data, false),
  authLogin:   (data: unknown)     => req('POST', '/auth/login',   data, false),
  authMe:      ()         => req('GET',  '/auth/me'),
  authUpdateMe:(data: unknown)     => req('PATCH','/auth/me',      data),
  authChangePassword: (data: unknown) => req('POST', '/auth/change-password', data),
  authLogout:  ()         => req('POST', '/auth/logout', undefined, false),
  authMfaVerify:  (data: unknown) => req('POST', '/auth/mfa/verify',  data, false),
  authMfaSetup:   ()              => req('POST', '/auth/mfa/setup'),
  authMfaEnable:  (data: unknown) => req('POST', '/auth/mfa/enable',  data),
  authMfaDisable: (data: unknown) => req('POST', '/auth/mfa/disable', data),

  // Admin
  adminListUsers:   ()          => req('GET',    '/admin/users'),
  adminCreateUser:  (data: unknown)      => req('POST',   '/admin/users',       data),
  adminUpdateUser:  (id: string, data: unknown)  => req('PATCH',  `/admin/users/${id}`, data),
  adminDeleteUser:  (id: string)        => req('DELETE', `/admin/users/${id}`),
  // Audit integrity (B9-4)
  adminAuditStatus:  ()              => req('GET', '/admin/audit/status'),
  adminAuditVerify:  (pid?: string)  => req('GET', `/admin/audit/verify${pid ? '?pid=' + encodeURIComponent(pid) : ''}`),

  adminListModules:   ()          => req('GET',    '/admin/modules'),
  adminCreateModule:  (data: unknown)      => req('POST',   '/admin/modules',       data),
  adminUpdateModule:  (name: string, data: unknown)=> req('PATCH',  `/admin/modules/${encodeURIComponent(name)}`, data),
  adminDeleteModule:  (name: string)      => req('DELETE', `/admin/modules/${encodeURIComponent(name)}`),
  adminDownloadModuleTemplate: () => download('/admin/modules/template'),
  adminDownloadFrontendModuleTemplate: () => download('/admin/modules/template/frontend'),
  adminValidateModule: (data: unknown)     => req('POST',   '/admin/modules/validate', data),
  adminSignModule:     (data: unknown)     => req('POST',   '/admin/modules/sign',     data),
  adminUploadModule:    (file: File)    => upload('/admin/modules/upload', file),
  adminGetAttackerSSHConfig: ()   => req('GET', '/admin/modules/attacker-ssh/config'),
  adminCreateAttackerTarget: (data: unknown) => req('POST', '/admin/modules/attacker-ssh/targets', data),
  adminUpdateAttackerTarget: (id: string, data: unknown) => req('PATCH', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}`, data),
  adminDeleteAttackerTarget: (id: string) => req('DELETE', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}`),
  adminTestAttackerTarget: (id: string)   => req('POST', `/admin/modules/attacker-ssh/targets/${encodeURIComponent(id)}/test`),
  adminTestAttackerSSH: (data: unknown)    => req('POST', '/admin/modules/attacker-ssh/test', data),
  adminExecuteAttackerSSH: (data: unknown) => req('POST', '/admin/modules/attacker-ssh/execute', data),

  // Projects
  getProjects:   ()         => req('GET',    '/projects'),
  createProject: (data: unknown)     => req('POST',   '/projects',        data),
  updateProject: (id: string, data: unknown) => req('PATCH',  `/projects/${id}`,  data),
  deleteProject: (id: string)       => req('DELETE', `/projects/${id}`),

  // Notes
  getNotes:             (pid?: string)       => req('GET',    `/notes${pid ? '?pid=' + pid : ''}`),
  createNote:           (data: unknown)      => req('POST',   '/notes',               data),
  updateNote:           (id: string, data: unknown)  => req('PATCH',  `/notes/${id}`,         data),
  deleteNote:           (id: string)         => req('DELETE', `/notes/${id}`),
  getNoteAttachments:   (id: string)         => req('GET',    `/notes/${id}/attachments`),
  uploadNoteAttachment: (id: string, file: File)  => upload(`/notes/${id}/attachments`, file),
  deleteAttachment:     (id: string)         => req('DELETE', `/attachments/${id}`),

  // Hosts
  getHosts:    (pid?: string)        => req('GET',    `/hosts${pid ? '?pid=' + pid : ''}`),
  createHost:  (data: unknown)       => req('POST',   '/hosts',          data),
  updateHost:  (id: string, data: unknown)   => req('PATCH',  `/hosts/${id}`,    data),
  deleteHost:  (id: string)          => req('DELETE', `/hosts/${id}`),

  // Creds
  getCreds:    (pid?: string)        => req('GET',    `/creds${pid ? '?pid=' + pid : ''}`),
  createCred:  (data: unknown)       => req('POST',   '/creds',          data),
  updateCred:  (id: string, data: unknown)   => req('PATCH',  `/creds/${id}`,    data),
  deleteCred:  (id: string)          => req('DELETE', `/creds/${id}`),

  // Networks
  getNetworks:    (pid?: string)       => req('GET',    `/networks${pid ? '?pid=' + pid : ''}`),
  createNetwork:  (data: unknown)      => req('POST',   '/networks',        data),
  updateNetwork:  (id: string, data: unknown)  => req('PATCH',  `/networks/${id}`,  data),
  deleteNetwork:  (id: string)         => req('DELETE', `/networks/${id}`),
  createNetworkNode:         (pid: string, data: unknown) => req('POST',   `/projects/${pid}/network/nodes`, data),
  updateNetworkNode:         (pid: string, nodeId: string, networkId: string, data: unknown) => req('PATCH',  `/projects/${pid}/network/nodes/${nodeId}?network_id=${encodeURIComponent(networkId)}`, data),
  updateNetworkNodePosition: (pid: string, nodeId: string, networkId: string, data: unknown) => req('PATCH',  `/projects/${pid}/network/nodes/${nodeId}/position?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkNode:         (pid: string, nodeId: string, networkId: string) => req('DELETE', `/projects/${pid}/network/nodes/${nodeId}?network_id=${encodeURIComponent(networkId)}`),
  createNetworkLink:         (pid: string, data: unknown) => req('POST',   `/projects/${pid}/network/links`, data),
  updateNetworkLink:         (pid: string, linkId: string, networkId: string, data: unknown) => req('PATCH',  `/projects/${pid}/network/links/${linkId}?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkLink:         (pid: string, linkId: string, networkId: string) => req('DELETE', `/projects/${pid}/network/links/${linkId}?network_id=${encodeURIComponent(networkId)}`),
  createNetworkRegion:       (pid: string, data: unknown) => req('POST',   `/projects/${pid}/network/regions`, data),
  updateNetworkRegion:       (pid: string, regionId: string, networkId: string, data: unknown) => req('PATCH',  `/projects/${pid}/network/regions/${regionId}?network_id=${encodeURIComponent(networkId)}`, data),
  deleteNetworkRegion:       (pid: string, regionId: string, networkId: string) => req('DELETE', `/projects/${pid}/network/regions/${regionId}?network_id=${encodeURIComponent(networkId)}`),

  // Findings
  getFindings:    (pid?: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams({ ...(pid ? { pid } : {}), ...Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][]) }).toString();
    return req('GET', `/findings${qs ? '?' + qs : ''}`);
  },
  createFinding:  (data: unknown)      => req('POST',   '/findings',          data),
  updateFinding:  (id: string, data: unknown)  => req('PATCH',  `/findings/${id}`,    data),
  deleteFinding:  (id: string)         => req('DELETE', `/findings/${id}`),
  scanCandidates: (pid: string)        => req('POST',   `/findings/scan-candidates?pid=${pid}`),

  // Checklist
  getChecklist:        (pid: string, phase?: string) => req('GET',    `/checklist?pid=${pid}${phase ? '&phase=' + phase : ''}`),
  bulkCreateChecklist: (items: unknown)     => req('POST',   '/checklist',         items),
  updateChecklistItem: (id: string, data: unknown)  => req('PATCH',  `/checklist/${id}`,   data),
  deleteChecklistItem: (id: string)         => req('DELETE', `/checklist/${id}`),

  // Timeline
  getTimeline:       (pid: string, entity?: string) => req('GET', `/timeline?pid=${pid}${entity ? '&entity=' + entity : ''}`),
  undoTimelineEvent: (eventId: string) => req('POST', `/timeline/${eventId}/undo`),

  // Objectives
  getObjectives:    (pid?: string)       => req('GET',    `/objectives${pid ? '?pid=' + pid : ''}`),
  createObjective:  (data: unknown)      => req('POST',   '/objectives',           data),
  updateObjective:  (id: string, data: unknown)  => req('PATCH',  `/objectives/${id}`,     data),
  deleteObjective:  (id: string)         => req('DELETE', `/objectives/${id}`),

  // Attack Paths
  getAttackPaths:   (pid?: string)       => req('GET',    `/attack-paths${pid ? '?pid=' + pid : ''}`),
  createAttackPath: (data: unknown)      => req('POST',   '/attack-paths',           data),
  updateAttackPath: (id: string, data: unknown)  => req('PATCH',  `/attack-paths/${id}`,     data),
  deleteAttackPath: (id: string)         => req('DELETE', `/attack-paths/${id}`),

  // Attack Steps
  getAttackSteps:   (pid?: string)       => req('GET',    `/attack-steps${pid ? '?pid=' + pid : ''}`),
  createAttackStep: (data: unknown)      => req('POST',   '/attack-steps',           data),
  updateAttackStep: (id: string, data: unknown)  => req('PATCH',  `/attack-steps/${id}`,     data),
  deleteAttackStep: (id: string)         => req('DELETE', `/attack-steps/${id}`),

  // Loot
  getLoots:    (pid?: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams({ ...(pid ? { pid } : {}), ...Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][]) }).toString();
    return req('GET', `/loots${qs ? '?' + qs : ''}`);
  },
  createLoot:  (data: unknown)      => req('POST',   '/loots',          data),
  updateLoot:  (id: string, data: unknown)  => req('PATCH',  `/loots/${id}`,    data),
  deleteLoot:  (id: string)         => req('DELETE', `/loots/${id}`),
  uploadLootFile: (id: string, file: File) => upload(`/loots/${id}/file`, file),
  getJobArtifacts: (pid: string, jobId: string) => req('GET', `/projects/${pid}/jobs/${jobId}/artifacts`),

  // Scope
  getScopes:    (pid?: string)      => req('GET',    `/scopes${pid ? '?pid=' + pid : ''}`),
  createScope:  (data: unknown)     => req('POST',   '/scopes',          data),
  updateScope:  (id: string, data: unknown) => req('PATCH',  `/scopes/${id}`,    data),
  deleteScope:  (id: string)        => req('DELETE', `/scopes/${id}`),

  // Host activities
  getHostActivities:  (pid?: string, hostId?: string) => req('GET', '/host-activities' + (pid || hostId ? '?' + new URLSearchParams({ ...(pid ? { pid } : {}), ...(hostId ? { host_id: hostId } : {}) }).toString() : '')),
  createHostActivity: (data: unknown)        => req('POST',   '/host-activities',          data),
  updateHostActivity: (id: string, data: unknown)    => req('PATCH',  `/host-activities/${id}`,    data),
  deleteHostActivity: (id: string)           => req('DELETE', `/host-activities/${id}`),
  executeAttackerCommand: (pid: string, data: unknown) => req('POST', `/projects/${pid}/attacker-exec`, data),
  listAttackerExecutionTargets: (pid: string) => req('GET', `/projects/${pid}/attacker-exec/targets`),

  // Cred-host notes
  getCredHostNotes:   (params: Record<string, string>) => { const qs = new URLSearchParams(params).toString(); return req('GET', `/cred-host-notes${qs ? '?' + qs : ''}`); },
  upsertCredHostNote: (data: unknown)        => req('POST',   '/cred-host-notes',       data),
  updateCredHostNote: (id: string, data: unknown)    => req('PATCH',  `/cred-host-notes/${id}`, data),
  deleteCredHostNote: (id: string)           => req('DELETE', `/cred-host-notes/${id}`),

  // Search & presence
  search:      (q: string, pid?: string, limit = 40, offset = 0) => req('GET', `/search?q=${encodeURIComponent(q)}${pid ? '&pid=' + pid : ''}&limit=${limit}&offset=${offset}`),
  listSavedSearches:   ()           => req('GET',    '/saved-searches'),
  createSavedSearch:   (data: unknown)       => req('POST',   '/saved-searches', data),
  deleteSavedSearch:   (id: string)          => req('DELETE', `/saved-searches/${id}`),
  getPresence: ()        => req('GET', '/presence'),
  getWorkerStatus: ()    => req('GET', '/worker/status'),
  listModules: ()        => req('GET', '/modules'),
  listConnectors: ()     => req('GET', '/connectors'),

  // Finding templates
  listFindingTemplates:        ()       => req('GET',    '/finding-templates'),
  listCustomFindingTemplates:  ()       => req('GET',    '/finding-templates/custom'),
  createCustomFindingTemplate: (data: unknown)   => req('POST',   '/finding-templates/custom', data),
  deleteCustomFindingTemplate: (id: string)   => req('DELETE', `/finding-templates/custom/${id}`),
  exportFindingTemplates:      ()       => download('/finding-templates/export'),
  importFindingTemplates:      (file: File)   => upload('/finding-templates/import', file),

  // Snippets
  listSnippets:        ()           => req('GET',    '/snippets'),
  listCustomSnippets:  ()           => req('GET',    '/snippets/custom'),
  createCustomSnippet: (data: unknown)       => req('POST',   '/snippets/custom',     data),
  updateCustomSnippet: (id: string, data: unknown)   => req('PATCH',  `/snippets/custom/${id}`, data),
  deleteCustomSnippet: (id: string)          => req('DELETE', `/snippets/custom/${id}`),
  exportSnippets:      ()           => download('/snippets/export'),
  importSnippets:      (file: File) => upload('/snippets/import', file),
  exportKB:            (pid?: string)        => download(`/kb/export${pid ? '?pid=' + pid : ''}`),
  importKB:            (file: File, pid?: string)  => upload(`/kb/import${pid ? '?pid=' + pid : ''}`, file),
  exportPlaybooks:     ()           => download('/playbooks/custom/export'),
  importPlaybooks:     (file: File) => upload('/playbooks/custom/import', file),
  listOperationPacks:  ()           => req('GET',    '/playbooks/packs'),
  createOperationPack: (data: unknown)       => req('POST',   '/playbooks/packs', data),
  deleteOperationPack: (packId: string)      => req('DELETE', `/playbooks/packs/${packId}`),

  // BloodHound server-side import
  importBloodHound: (pid: string, file: File) => upload(`/projects/${pid}/import/bloodhound`, file),

  // MITRE ATT&CK
  getMitreCoverage:  (pid: string) => req('GET', `/projects/${pid}/mitre/coverage`),
  downloadReportPDF: async (pid: string): Promise<Blob> => {
    const res = await fetch(`/api/projects/${pid}/report/pdf`, { credentials: 'include' });
    if (!res.ok) throw new Error(`PDF generation failed: ${res.status}`);
    return res.blob();
  },
  downloadReportHTML: async (pid: string): Promise<{ blob: Blob; filename: string }> => {
    const res = await fetch(`/api/projects/${pid}/report/html`, { credentials: 'include' });
    if (!res.ok) throw new Error(`HTML export failed: ${res.status}`);
    const cd = res.headers.get('Content-Disposition') || '';
    const match = /filename="([^"]+)"/.exec(cd);
    return { blob: await res.blob(), filename: match ? match[1] : `report_${pid}.html` };
  },

  // Batch import & project export/import
  batchImport:   (pid: string, data: unknown) => req('POST', `/import/${pid}`, data),
  exportProject: async (pid: string): Promise<{ blob: Blob; password: string | null }> => {
    const res = await fetch(`/api/export/${pid}`, { credentials: 'include' });
    if (!res.ok) throw new Error(await res.text());
    const blob = await res.blob();
    const password = res.headers.get('X-Zip-Password') || null;
    return { blob, password };
  },
  importProject: (file: File)      => upload('/import_project', file),

  // Topology
  topologyPreview: (pid: string, formData: FormData) => {
    return fetch(`/api/projects/${pid}/topology/preview`, {
      method: 'POST', body: formData,
      credentials: 'include',
    }).then(async res => {
      if (!res.ok) throw new Error(await res.text());
      return res.json() as Promise<unknown>;
    });
  },
  topologyApply:         (pid: string, data: unknown)    => req('POST', `/projects/${pid}/topology/apply`,          data),
  topologyRebuildLayout: (pid: string, data: unknown)    => req('POST', `/projects/${pid}/topology/rebuild-layout`, data),
  topologyAutoBuild:     (pid: string, data: unknown)    => req('POST', `/projects/${pid}/topology/auto-build`,     data),
  topologySmartBuild:    (pid: string, data: unknown)    => req('POST', `/projects/${pid}/topology/smart-build`,    data),
  topologyLateralPaths:  (pid: string, fromHostId: string, depth = 3) => req('GET', `/projects/${pid}/topology/lateral-paths?from_host_id=${fromHostId}&depth=${depth}`),
  getTopology:           (pid: string)          => req('GET',  `/projects/${pid}/topology`),
  getTopologySources:    (pid: string)          => req('GET',  `/projects/${pid}/topology/sources`),

  // Pivot observations
  listPivots:            (pid: string)          => req('GET',  `/projects/${pid}/pivots`),
  createPivot:           (pid: string, data: unknown)    => req('POST', `/projects/${pid}/pivots`, data),
  updatePivot:           (pid: string, pivotId: string, data: unknown) => req('PATCH', `/projects/${pid}/pivots/${pivotId}`, data),
  deletePivot:           (pid: string, pivotId: string) => req('DELETE', `/projects/${pid}/pivots/${pivotId}`),
  collectPivots:         (pid: string, data: unknown)    => req('POST', `/projects/${pid}/pivots/collect`, data),

  // Project members
  getProjectMembers:       (pid: string)             => req('GET',    `/projects/${pid}/members`),
  getProjectAvailableUsers:(pid: string)             => req('GET',    `/projects/${pid}/available-users`),
  addProjectMember:        (pid: string, data: unknown)       => req('POST',   `/projects/${pid}/members`,            data),
  bulkAddProjectMembers:   (pid: string, data: unknown)       => req('POST',   `/projects/${pid}/members/bulk`,       data),
  updateProjectMember:     (pid: string, uid: string, data: unknown)  => req('PATCH',  `/projects/${pid}/members/${uid}`,     data),
  removeProjectMember:     (pid: string, uid: string)        => req('DELETE', `/projects/${pid}/members/${uid}`),
  transferOwnership:       (pid: string, data: unknown)       => req('POST',   `/projects/${pid}/transfer-ownership`, data),
  getMyProjectPermissions: (pid: string)             => req('GET',    `/projects/${pid}/permissions/me`),

  // CSV exports
  exportHostsCsv:    (pid: string) => download(`/projects/${pid}/export/hosts.csv`),
  exportFindingsCsv: (pid: string) => download(`/projects/${pid}/export/findings.csv`),
  exportCredsCsv:    (pid: string) => download(`/projects/${pid}/export/creds.csv`),

  // Project templates
  listProjectTemplates:  ()           => req('GET',  '/project-templates'),
  applyProjectTemplate:  (templateId: string) => req('POST', `/project-templates/${templateId}/apply`),

  // Bulk host import
  bulkImportHosts: (data: unknown) => req('POST', '/hosts/bulk', data),

  // Scans (nmap/nuclei/cme via attacker SSH)
  runNmapScan:    (pid: string, data: unknown) => req('POST', `/projects/${pid}/scans/nmap`,   data),
  runNucleiScan:  (pid: string, data: unknown) => req('POST', `/projects/${pid}/scans/nuclei`, data),
  runCmeScan:     (pid: string, data: unknown) => req('POST', `/projects/${pid}/scans/cme`,    data),
  runDonpapiScan: (pid: string, data: unknown) => req('POST', `/projects/${pid}/scans/donpapi`, data),

  // Webhooks (C2)
  getProjectWebhook:        (pid: string)  => req('GET',  `/projects/${pid}/webhook`),
  regenerateProjectWebhook: (pid: string)  => req('POST', `/projects/${pid}/webhook/regenerate`),

  // C2 integrations
  listC2Integrations:    ()              => req('GET',    '/admin/c2'),
  createC2Integration:   (data: unknown)          => req('POST',   '/admin/c2',            data),
  updateC2Integration:   (id: string, data: unknown)      => req('PATCH',  `/admin/c2/${id}`,      data),
  deleteC2Integration:   (id: string)            => req('DELETE', `/admin/c2/${id}`),
  testC2Integration:     (id: string)            => req('POST',   `/admin/c2/${id}/test`),
  syncC2ToProject:       (id: string, pid: string)       => req('POST',   `/admin/c2/${id}/sync/${pid}`),
  listC2ForProject:      (pid: string)           => req('GET',    `/admin/c2/for-project/${pid}`),
  getC2LiveSessions:     (pid: string)           => req('GET',    `/admin/c2/sessions/${pid}`),
  getC2HostActions:      (pid: string, hostId: string)   => req('GET',    `/admin/c2/host-actions/${pid}/${hostId}`),
  listC2Bofs:            (id: string, pid: string)       => req('GET',    `/admin/c2/${id}/bofs/${pid}`),
  executeC2HostAction:   (pid: string, data: unknown)     => req('POST',   `/admin/c2/execute/${pid}`, data),
  getC2AgentTasks:       (pid: string, integrationId: string, agentId: string, limit = 30) => req('GET', `/admin/c2/agent-tasks/${pid}?integration_id=${encodeURIComponent(integrationId)}&agent_id=${encodeURIComponent(agentId)}&limit=${encodeURIComponent(limit)}`),

  // Collections
  listCollections:   (pid: string)          => req('GET',    `/projects/${pid}/collections`),
  createCollection:  (pid: string, data: unknown)    => req('POST',   `/projects/${pid}/collections`,          data),
  updateCollection:  (pid: string, id: string, data: unknown)=> req('PATCH',  `/projects/${pid}/collections/${id}`,    data),
  deleteCollection:  (pid: string, id: string)       => req('DELETE', `/projects/${pid}/collections/${id}`),
  resolveCollection: (pid: string, id: string)       => req('GET',    `/projects/${pid}/collections/${id}/resolve`),
  previewCollection: (pid: string, filters: unknown) => req('POST',   `/projects/${pid}/collections/preview`,  filters),

  // Bulk actions
  bulkExec:      (pid: string, data: unknown)           => req('POST', `/projects/${pid}/bulk-exec`,                data),
  validateCred:  (pid: string, credId: string, data: unknown)   => req('POST', `/projects/${pid}/creds/${credId}/validate`, data),
  getCredMatrix: (pid: string)                 => req('GET',  `/projects/${pid}/cred-matrix`),

  // Jobs
  listJobs:   (pid: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][])).toString();
    return req('GET', `/projects/${pid}/jobs${qs ? '?' + qs : ''}`);
  },
  getJob:          (pid: string, jobId: string) => req('GET',    `/projects/${pid}/jobs/${jobId}`),
  streamJobOutput: (pid: string, jobId: string) => `/api/projects/${pid}/jobs/${jobId}/output-stream`,
  deleteJob:  (pid: string, jobId: string) => req('DELETE', `/projects/${pid}/jobs/${jobId}`),
  cancelJob:  (pid: string, jobId: string) => req('PATCH',  `/projects/${pid}/jobs/${jobId}/cancel`),
  rerunJob:   (pid: string, jobId: string) => req('POST',   `/projects/${pid}/jobs/${jobId}/rerun`),
  retryJob:   (pid: string, jobId: string) => req('POST',   `/projects/${pid}/jobs/${jobId}/retry`),

  // Playbooks
  listPlaybooks: () => req('GET', '/playbooks'),
  listPlaybookStepTemplates: () => req('GET', '/playbooks/step-templates'),
  validatePlaybook: (data: unknown) => req('POST', '/playbooks/validate', data),
  createCustomPlaybook: (data: unknown) => req('POST', '/playbooks/custom', data),
  updateCustomPlaybook: (id: string, data: unknown) => req('PATCH', `/playbooks/custom/${id}`, data),
  deleteCustomPlaybook: (id: string) => req('DELETE', `/playbooks/custom/${id}`),
  runPlaybook: (pid: string, playbookId: string, data: unknown) => req('POST', `/projects/${pid}/playbooks/${encodeURIComponent(playbookId)}/run`, data),
  batchRunPlaybook: (pid: string, playbookId: string, data: unknown) => req('POST', `/projects/${pid}/playbooks/${encodeURIComponent(playbookId)}/batch-run`, data),
  listPlaybookRuns: (pid: string, params: Record<string, ParamValue> = {}) => {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][])).toString();
    return req('GET', `/projects/${pid}/playbook-runs${qs ? '?' + qs : ''}`);
  },
  getPlaybookRun: (pid: string, runId: string) => req('GET', `/projects/${pid}/playbook-runs/${runId}`),
  cancelPlaybookRun: (pid: string, runId: string) => req('POST', `/projects/${pid}/playbook-runs/${runId}/cancel`),
  rerunPlaybookRun: (pid: string, runId: string) => req('POST', `/projects/${pid}/playbook-runs/${runId}/rerun`),

  // Notifications
  getNotificationConfig:  ()      => req('GET',  '/notifications/config'),
  saveNotificationConfig: (data: unknown)  => req('PUT',  '/notifications/config', data),
  testNotification:       ()      => req('POST', '/notifications/test'),
  getTelegramChatIds:     ()      => req('GET',  '/notifications/telegram/chat-id'),

  // Scheduled playbooks
  listSchedules:    (pid: string)           => req('GET',    `/scheduled-playbooks?pid=${encodeURIComponent(pid)}`),
  createSchedule:   (data: unknown)          => req('POST',   '/scheduled-playbooks',        data),
  updateSchedule:   (id: string, data: unknown)      => req('PATCH',  `/scheduled-playbooks/${id}`,  data),
  deleteSchedule:   (id: string)             => req('DELETE', `/scheduled-playbooks/${id}`),
  triggerSchedule:  (id: string)             => req('POST',   `/scheduled-playbooks/${id}/trigger`),


  // AI
  getAIStatus:       ()                => req('GET',  '/ai/status'),
  getAIConfig:       ()                => req('GET',  '/ai/config'),
  saveAIConfig:      (data: unknown)            => req('PUT',  '/ai/config', data),
  aiChat:            (pid: string, data: unknown)       => req('POST', `/projects/${pid}/ai/chat`, data),

  // Import scanners
  importNessus:      (pid: string, file: File)       => upload(`/projects/${pid}/import/nessus`, file),
  importBurp:        (pid: string, file: File)       => upload(`/projects/${pid}/import/burp`, file),

  // Attack graph
  getAttackGraph:    (pid: string)             => req('GET',  `/projects/${pid}/attack-graph`),

  // Knowledge base
  listKBArticles:    (params: Record<string, string | number | null> = {})       => { const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][])).toString(); return req('GET', `/kb${qs ? '?' + qs : ''}`); },
  getKBArticles:     (params: Record<string, string | number | null> = {})       => { const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null) as [string, string][])).toString(); return req('GET', `/kb${qs ? '?' + qs : ''}`); },
  getKBArticle:      (id: string)              => req('GET',  `/kb/${id}`),
  createKBArticle:   (data: unknown)            => req('POST', '/kb', data),
  updateKBArticle:   (id: string, data: unknown)         => req('PATCH', `/kb/${id}`, data),
  deleteKBArticle:   (id: string)              => req('DELETE', `/kb/${id}`),
  seedMitreKB:       ()               => req('POST', '/kb/seed/mitre'),
};

/** Returns the URL unchanged — cookie auth handles authentication for download links. */
export function downloadUrl(url: string | null | undefined): string {
  return url || '';
}
