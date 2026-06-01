/**
 * Frontend module contract.
 *
 * A module is a plain object matching this shape:
 * {
 *   id:          string,           // unique identifier
 *   title:       string,           // display name
 *   version:     string,           // semver
 *   description: string,
 *   enabled:     boolean,
 *
 *   // Extension points (all optional):
 *   routes:       [{ path, component }],
 *   menuItems:    [{ id, label, icon, tab }],       // adds items to sidebar
 *   projectTabs:  [{ id, label, component }],        // adds tabs on project page
 *   hostTabs:     [{ id, label, component }],         // adds tabs in host card
 *   networkTabs:  [{ id, label, component }],         // adds tabs in network node panel
 *   reportSections: [{ id, label, component }],
 *   importers:    [{ id, label, accept, component }], // adds import UI
 *   dashboardWidgets: [{ id, component }],
 *   actions:      { hosts: [], findings: [], creds: [], networkNodes: [] },
 * }
 */

export const MODULE_SCHEMA = {
  id: '',
  title: '',
  version: '1.0.0',
  description: '',
  enabled: true,
  routes: [],
  menuItems: [],
  projectTabs: [],
  hostTabs: [],
  networkTabs: [],
  reportSections: [],
  importers: [],
  dashboardWidgets: [],
  actions: { hosts: [], findings: [], creds: [], networkNodes: [] },
};
