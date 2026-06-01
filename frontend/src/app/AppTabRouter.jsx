/**
 * AppTabRouter — renders the correct view for the active tab.
 *
 * All views are passed the props they need; entity data comes from Zustand
 * store and CRUD actions come from useEntityCRUD (passed as `crud` prop).
 */
import PropTypes from 'prop-types';
import { Suspense, useMemo, useCallback } from 'react';
import { api } from '../api.js';
import lazyWithReload from '../utils/lazyWithReload.js';
import { useProjectStore } from '../store/useProjectStore.js';

// Eagerly loaded
import ProjectsView from '../views/ProjectsView.jsx';
import OverviewView from '../views/OverviewView.jsx';

// Lazily loaded
const NotesView        = lazyWithReload(() => import('../views/NotesView.jsx'));
const HostsView        = lazyWithReload(() => import('../views/HostsView.jsx'));
const CredsView        = lazyWithReload(() => import('../views/CredsView.jsx'));
const NetworkView      = lazyWithReload(() => import('../views/NetworkView.jsx'));
const FindingsView     = lazyWithReload(() => import('../views/FindingsView.jsx'));
const ObjectivesView   = lazyWithReload(() => import('../views/ObjectivesView.jsx'));
const AttackPathView   = lazyWithReload(() => import('../views/AttackPathView.jsx'));
const AttackGraphView  = lazyWithReload(() => import('../views/AttackGraphView.jsx'));
const LootView         = lazyWithReload(() => import('../views/LootView.jsx'));
const ScopeView        = lazyWithReload(() => import('../views/ScopeView.jsx'));
const ChecklistView    = lazyWithReload(() => import('../views/ChecklistView.jsx'));
const TimelineView     = lazyWithReload(() => import('../views/TimelineView.jsx'));
const CheatsheetView   = lazyWithReload(() => import('../views/CheatsheetView.jsx'));
const ScansView        = lazyWithReload(() => import('../views/ScansView.jsx'));
const JobsView         = lazyWithReload(() => import('../views/JobsView.jsx'));
const PlaybooksView    = lazyWithReload(() => import('../views/PlaybooksView.jsx'));
const KBView           = lazyWithReload(() => import('../views/KBView.jsx'));
const ReportView       = lazyWithReload(() => import('../views/ReportView.jsx'));
const AdminView        = lazyWithReload(() => import('../views/AdminView.jsx'));
const UserSettingsView = lazyWithReload(() => import('../views/UserSettingsView.jsx'));

export default function AppTabRouter({
  tab, setTab,
  accent, accentGreen, fontSize,
  animateLinks,
  selectedProject, setSelectedProject,
  currentUser, setCurrentUser,
  onlineUsers,
  jobs, setJobs,
  jobsFilter, setJobsFilter,
  presence,
  markLocalOp,
  refreshHosts, refreshNetworks,
  sendFocus,
  setImportProjectId,
  crud,
}) {
  const {
    projects, notes, hosts, creds, networks,
    findings, objectives, attackPaths, attackSteps,
    loots, scopes, hostActivities,
    setProjects, setNotes, setHosts, setCreds, setNetworks,
    setFindings, setObjectives, setAttackPaths, setAttackSteps,
    setLoots, setScopes, setHostActivities,
  } = useProjectStore();

  const acc = accent;
  const green = accentGreen;
  const fs = fontSize;

  const selectedProjectHosts = useMemo(
    () => hosts.filter(h => h.pid === selectedProject),
    [hosts, selectedProject],
  );
  const selectedProjectNetworks = useMemo(
    () => networks.filter(n => n.pid === selectedProject),
    [networks, selectedProject],
  );

  const updateProject = useCallback(async (id, patch) => {
    const p = await api.updateProject(id, patch);
    setProjects(prev => prev.map(x => x.id === id ? p : x));
    return p;
  }, [setProjects]);

  const refreshAllData = useCallback(async () => {
    const [p, n, h, c, nets, f, obj, aps, ass, lts, scs, acts] = await Promise.all([
      api.getProjects(), api.getNotes(), api.getHosts(), api.getCreds(),
      api.getNetworks(), api.getFindings(), api.getObjectives(),
      api.getAttackPaths(), api.getAttackSteps(), api.getLoots(),
      api.getScopes(), api.getHostActivities(),
    ]);
    setProjects(p); setNotes(n); setHosts(h); setCreds(c); setNetworks(nets);
    setFindings(f); setObjectives(obj); setAttackPaths(aps); setAttackSteps(ass);
    setLoots(lts); setScopes(scs); setHostActivities(acts);
  }, [setProjects, setNotes, setHosts, setCreds, setNetworks, setFindings, setObjectives, setAttackPaths, setAttackSteps, setLoots, setScopes, setHostActivities]);

  const fallback = (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 11 }}>
      Loading…
    </div>
  );

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', minWidth: 0 }}>
      <Suspense fallback={fallback}>
        {tab === 'projects' && (
          <ProjectsView
            projects={projects} notes={notes} hosts={hosts} creds={creds} scopes={scopes}
            selectedProject={selectedProject}
            onSelect={p => { setSelectedProject(p); setTab('notes'); }}
            accent={acc}
            onAdd={crud.addProject}
            onAddScope={crud.addScope}
            onUpdate={updateProject}
            onDelete={crud.deleteProject}
            onImport={pid => setImportProjectId(pid)}
            onProjectImported={async (result) => {
              await refreshAllData();
              setSelectedProject(result.project_id);
            }}
          />
        )}
        {tab === 'overview' && (
          <OverviewView
            selectedProject={selectedProject} projects={projects}
            hosts={hosts} creds={creds} findings={findings}
            notes={notes} objectives={objectives}
            timelineEvents={[]} checklistItems={[]}
            accent={acc} onTabChange={setTab}
          />
        )}
        {tab === 'user-settings' && (
          <UserSettingsView accent={acc} currentUser={currentUser} onUserUpdated={setCurrentUser} />
        )}
        {tab === 'notes' && (
          <NotesView notes={notes} onAdd={crud.addNote} onUpdate={crud.updateNote} onDelete={crud.deleteNote}
            projects={projects} selectedProject={selectedProject} accent={acc} fs={fs}
            presence={presence} onFocus={sendFocus} username={currentUser?.username} />
        )}
        {tab === 'hosts' && (
          <HostsView hosts={hosts} creds={creds} hostActivities={hostActivities}
            onAdd={crud.addHost} onUpdate={crud.updateHost} onDelete={crud.deleteHost}
            onAddActivity={crud.addHostActivity} onUpdateActivity={crud.updateHostActivity} onDeleteActivity={crud.deleteHostActivity}
            projects={projects} selectedProject={selectedProject} accent={acc} fs={fs}
            onAddCred={crud.addCred}
            onImport={() => setImportProjectId(selectedProject)} />
        )}
        {tab === 'creds' && (
          <CredsView creds={creds} onAdd={crud.addCred} onUpdate={crud.updateCred} onDelete={crud.deleteCred}
            selectedProject={selectedProject} accent={acc} hosts={hosts} fs={fs} />
        )}
        {tab === 'network' && selectedProject && (
          <NetworkView
            key={selectedProject}
            projectId={selectedProject} accent={acc} accentGreen={green}
            animateLinks={animateLinks}
            networks={selectedProjectNetworks}
            onCreateNetwork={crud.createNetwork}
            onUpdateNetwork={crud.updateNetwork}
            onDeleteNetwork={crud.deleteNetwork}
            onCreateHost={crud.addHost}
            onUpdateHost={crud.updateHost}
            onSyncHostByIp={crud.syncHostByIp}
            hosts={selectedProjectHosts}
            onAddActivity={crud.addHostActivity}
            onUpdateActivity={crud.updateHostActivity}
            onDeleteActivity={crud.deleteHostActivity}
            onRefreshHosts={refreshHosts}
            onRefreshNetworks={refreshNetworks}
            markLocalOp={markLocalOp}
            findings={findings.filter(f => f.pid === selectedProject)}
            objectives={objectives.filter(o => o.pid === selectedProject)}
            creds={creds.filter(c => c.pid === selectedProject)}
            attackSteps={attackSteps.filter(s => s.pid === selectedProject)}
          />
        )}
        {tab === 'findings' && (
          <FindingsView findings={findings} hosts={hosts}
            onAdd={crud.addFinding} onUpdate={crud.updateFinding} onDelete={crud.deleteFinding}
            selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'objectives' && (
          <ObjectivesView objectives={objectives} hosts={hosts}
            onAdd={crud.addObjective} onUpdate={crud.updateObjective} onDelete={crud.deleteObjective}
            selectedProject={selectedProject} accent={acc} currentUser={currentUser} />
        )}
        {tab === 'attackpath' && (
          <AttackPathView
            attackPaths={attackPaths} attackSteps={attackSteps}
            onCreatePath={crud.addAttackPath} onUpdatePath={crud.updateAttackPath} onDeletePath={crud.deleteAttackPath}
            onCreateStep={crud.addAttackStep} onUpdateStep={crud.updateAttackStep} onDeleteStep={crud.deleteAttackStep}
            selectedProject={selectedProject} accent={acc} hosts={hosts} />
        )}
        {tab === 'attackgraph' && selectedProject && (
          <AttackGraphView key={selectedProject} selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'loot' && (
          <LootView loots={loots} hosts={hosts}
            onAdd={crud.addLoot} onUpdate={crud.updateLoot} onDelete={crud.deleteLoot}
            selectedProject={selectedProject} accent={acc} fs={fs} />
        )}
        {tab === 'scope' && (
          <ScopeView scopes={scopes} hosts={hosts}
            onAdd={crud.addScope} onUpdate={crud.updateScope} onDelete={crud.deleteScope}
            selectedProject={selectedProject} accent={acc} fs={fs} />
        )}
        {tab === 'checklist' && <ChecklistView selectedProject={selectedProject} accent={acc} />}
        {tab === 'timeline'  && <TimelineView selectedProject={selectedProject} accent={acc} />}
        {tab === 'cheatsheet' && (
          <CheatsheetView accent={acc} hosts={hosts} creds={creds} selectedProject={selectedProject} />
        )}
        {tab === 'scans' && <ScansView selectedProject={selectedProject} accent={acc} />}
        {tab === 'jobs' && (
          <JobsView
            selectedProject={selectedProject} accent={acc}
            jobs={jobs.filter(j => j.pid === selectedProject)}
            onJobUpdate={j => setJobs(prev => prev.map(x => x.id === j.id ? j : x))}
            onJobDelete={id => setJobs(prev => prev.filter(x => x.id !== id))}
            initialFilter={jobsFilter}
            onFilterConsumed={() => setJobsFilter(null)}
          />
        )}
        {tab === 'playbooks' && (
          <PlaybooksView selectedProject={selectedProject} accent={acc}
            onNavigate={(to, filter) => { setTab(to); if (filter) setJobsFilter(filter); }} />
        )}
        {tab === 'kb' && (
          <KBView selectedProject={selectedProject} accent={acc} currentUser={currentUser}
            attackSteps={attackSteps.filter(s => s.pid === selectedProject)} />
        )}
        {tab === 'report' && (
          <ReportView
            projects={projects} notes={notes} hosts={hosts} creds={creds}
            findings={findings} hostActivities={hostActivities}
            attackPaths={attackPaths.filter(p => p.pid === selectedProject)}
            attackSteps={attackSteps.filter(s => s.pid === selectedProject)}
            selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'admin' && currentUser?.role === 'admin' && (
          <AdminView currentUser={currentUser} accent={acc} onlineUsers={onlineUsers} />
        )}
      </Suspense>
    </div>
  );
}

AppTabRouter.propTypes = {
  tab: PropTypes.string,
  setTab: PropTypes.func,
  accent: PropTypes.string,
  accentGreen: PropTypes.string,
  fontSize: PropTypes.number,
  animateLinks: PropTypes.bool,
  selectedProject: PropTypes.string,
  setSelectedProject: PropTypes.func,
  currentUser: PropTypes.object,
  setCurrentUser: PropTypes.func,
  onlineUsers: PropTypes.array,
  jobs: PropTypes.array,
  setJobs: PropTypes.func,
  jobsFilter: PropTypes.object,
  setJobsFilter: PropTypes.func,
  presence: PropTypes.object,
  markLocalOp: PropTypes.func,
  refreshHosts: PropTypes.func,
  refreshNetworks: PropTypes.func,
  sendFocus: PropTypes.func,
  setImportProjectId: PropTypes.func,
  crud: PropTypes.object,
};
