export const ACCESS_ROLES = [
  { id: 'local_admin', label: 'LA', title: 'Local Admin' },
  { id: 'domain_admin', label: 'DA', title: 'Domain Admin' },
  { id: 'rdp', label: 'RDP', title: 'RDP access' },
  { id: 'ssh', label: 'SSH', title: 'SSH access' },
  { id: 'winrm', label: 'WRM', title: 'WinRM access' },
  { id: 'no_rights', label: 'None', title: 'No rights' },
];

export const ACTIVITY_TYPES = {
  recon:   { label: 'Recon', color: '#5b8af5' },
  scan:    { label: 'Scan', color: '#6fc8f0' },
  exploit: { label: 'Exploit', color: '#e8574a' },
  privesc: { label: 'PrivEsc', color: '#f09a3a' },
  lateral: { label: 'Lateral', color: '#e8cc42' },
  postex:  { label: 'PostEx', color: '#39d353' },
  note:    { label: 'Note', color: '#808590' },
};

export const ACTIVITY_STATUS = {
  planned: { label: 'Planned', color: '#5b8af5' },
  running: { label: 'Running', color: '#f09a3a' },
  done:    { label: 'Done', color: '#39d353' },
  failed:  { label: 'Failed', color: '#cc2233' },
};

export const NETWORK_BACKGROUNDS = ['#07080b', '#0b1116', '#100c16', '#161008', '#0a1511', '#120a0f'];
export const REGION_FILL = ['#5b8af522', '#c07af022', '#39d35322', '#f09a3a22', '#e8574a22', '#6fc8f022'];
export const REGION_STROKE = ['#5b8af5', '#c07af0', '#39d353', '#f09a3a', '#e8574a', '#6fc8f0'];

export const ROLE_ICON = {
  unknown: 'server',
  workstation: 'monitor',
  server: 'server',
  domain_controller: 'crown',
  file_server: 'fileserver',
  web_server: 'globe',
  database: 'db',
  jump_host: 'jump',
  attacker: 'bolt',
  external: 'external',
  network_device: 'router',
  firewall: 'firewall',
  custom: 'settings',
};

export const ROLE_SHORT = {
  unknown: '?', workstation: 'WS', server: 'SRV', domain_controller: 'DC',
  file_server: 'FS', web_server: 'WEB', database: 'DB', jump_host: 'JMP',
  attacker: 'ATK', external: 'EXT', network_device: 'RT', firewall: 'FW', custom: '?',
};

export const EMPTY_ACTIVITY = { title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' };
export const INSPECTOR_TABS = ['details', 'activity', 'credentials'];
