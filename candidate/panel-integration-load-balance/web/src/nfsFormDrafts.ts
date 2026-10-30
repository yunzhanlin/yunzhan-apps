type Draft = Record<string, unknown>;
interface ServerConfig { bind_address: string; port: number; revision: number }
interface Entry { value: Draft; baseline: string }
export interface NFSDraftSubmission { section: string; revision: number; fingerprint: string }

const fields: Record<string, string[]> = {
  listener: ['bind_address', 'port', 'expected_revision', 'confirm'],
  export: ['resource_id', 'site_id', 'path', 'client_allow', 'read_only', 'expected_revision', 'confirm'],
  'export-remove': ['resource_id', 'expected_revision'],
  mount: ['resource_id', 'source', 'port', 'read_only'],
  unmount: ['resource_id'],
};
const serverSections = ['listener', 'export', 'export-remove'];
const fingerprint = (section: string, value: Draft) => JSON.stringify((fields[section] || []).filter(key => key !== 'confirm').map(key => value[key]));

/** In-memory drafts belong to one opened NFS installation and one operation. */
export class NFSFormDrafts {
  private entries = new Map<string, Entry>();
  private server?: ServerConfig;
  private active = '';
  constructor(private wrap: (value: Draft) => Draft = value => value) {}

  reset() { this.entries.clear(); this.server = undefined; this.active = ''; }

  private defaults(section: string): Draft {
    const revision = this.server?.revision ?? 0;
    switch (section) {
      case 'listener': return {bind_address: this.server?.bind_address ?? '127.0.0.1', port: this.server?.port ?? 2049, expected_revision: revision, confirm: ''};
      case 'export': return {resource_id: '', site_id: '', path: '', client_allow: '["127.0.0.1"]', read_only: true, expected_revision: revision, confirm: ''};
      case 'export-remove': return {resource_id: '', expected_revision: revision};
      case 'mount': return {resource_id: '', source: '', port: 2049, read_only: true};
      case 'unmount': return {resource_id: ''};
      default: return {};
    }
  }

  activate(section: string): Draft {
    const previous = this.entries.get(this.active);
    if (previous && 'confirm' in previous.value) previous.value.confirm = '';
    this.active = section;
    let entry = this.entries.get(section);
    if (!entry) {
      const value = this.wrap(this.defaults(section));
      entry = {value, baseline: fingerprint(section, value)};
      this.entries.set(section, entry);
    }
    if ('confirm' in entry.value) entry.value.confirm = '';
    return entry.value;
  }

  observe(value: unknown, acknowledged?: NFSDraftSubmission) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    const config = value as ServerConfig;
    if (typeof config.bind_address !== 'string' || !config.bind_address || !Number.isInteger(config.port) || config.port < 1024 || config.port > 65535 || !Number.isSafeInteger(config.revision) || config.revision < 0) return;
    this.server = {bind_address: config.bind_address, port: config.port, revision: config.revision};
    for (const section of serverSections) {
      const entry = this.entries.get(section);
      if (!entry) continue;
      const current = fingerprint(section, entry.value);
      const committed = acknowledged?.section === section && acknowledged.revision + 1 === config.revision && acknowledged.fingerprint === current;
      // A read must never silently rebase an edited or selected export over a newer revision.
      if (!committed && (current !== entry.baseline || section !== 'listener' && entry.value.resource_id)) continue;
      entry.value.expected_revision = config.revision;
      if (section === 'listener') Object.assign(entry.value, {bind_address: config.bind_address, port: config.port});
      if ('confirm' in entry.value) entry.value.confirm = '';
      entry.baseline = fingerprint(section, entry.value);
    }
  }

  submission(section: string, action: string): NFSDraftSubmission | undefined {
    if (action !== ({listener: 'server-config', export: 'export-save', 'export-remove': 'export-remove'} as Record<string, string>)[section]) return;
    const value = this.entries.get(section)?.value;
    if (value && Number.isSafeInteger(value.expected_revision) && Number(value.expected_revision) >= 0)
      return {section, revision: Number(value.expected_revision), fingerprint: fingerprint(section, value)};
  }

  select(row: Draft): string | undefined {
    const resource = row.resource_id ?? row.id;
    if (typeof resource !== 'string' || !/^[a-z][a-z0-9-]{2,31}$/.test(resource)) return;
    if ('clients' in row) {
      if (!Array.isArray(row.clients) || !row.clients.length || row.clients.some(client => typeof client !== 'string') || typeof row.read_only !== 'boolean' || typeof row.site_id !== 'string' || !/^[a-f0-9]{32}$/.test(row.site_id) || row.path !== undefined && typeof row.path !== 'string') return;
      const value = this.activate('export');
      Object.assign(value, {resource_id: resource, site_id: row.site_id, path: row.path ?? '', client_allow: JSON.stringify(row.clients, null, 2), read_only: row.read_only, expected_revision: this.server?.revision ?? 0, confirm: ''});
      const removal = this.entries.get('export-remove') ?? {value: this.wrap(this.defaults('export-remove')), baseline: ''};
      Object.assign(removal.value, {resource_id: resource, expected_revision: this.server?.revision ?? 0});
      this.entries.set('export-remove', removal);
      return 'export';
    }
    const value = this.activate('unmount');
    value.resource_id = resource;
    return 'unmount';
  }
}
