/**
 * Fixed server-side catalog of inventory ("table" kind) FIM sources. Clients only ever
 * send a source id; the SQL and the key/value columns come from here, so no free SQL
 * can reach an agent.
 *
 * Rules for every source:
 *  - the SELECT list is exactly keyColumns followed by valueColumns (checked by selftest);
 *  - key columns identify an item (never a pid); value columns are what "modified" compares;
 *  - volatile columns (pids, timestamps, counters, memory, live process state) are never
 *    selected, so the item hash only changes on real configuration change.
 *
 * `verified`:
 *  - 'linux-osquery-5.0.1' : the SQL ran against real osqueryd 5.0.1 on Linux and the result
 *    columns matched (see src/test/utils/fimCatalog.selftest.ts, which re-runs them when
 *    osqueryd is installed).
 *  - 'unverified' : Windows-only tables that could not be executed here; written from the
 *    osquery schema. Shown as "needs Windows agent support - verify" in the UI.
 *
 * Extension hook: a source with requiresExtension=true targets a table provided by an
 * osquery EXTENSION (not stock osquery), e.g. vajra_registry_acl(key_path, principal,
 * ace_type, access_mask, inherited). It stays disabled in the UI unless an operator
 * explicitly enables it (the agent must load the extension or the scan returns an error).
 */
import type { FimOsPlatform, FimSeverity } from './fimLogic';

export interface FimCatalogSource {
  id: string;
  label: string;
  platform: FimOsPlatform;
  description: string;
  category: string;
  severity: FimSeverity;
  sql: string;
  keyColumns: string[];
  valueColumns: string[];
  /** Suggested scan interval (secs). */
  intervalHint: number;
  notes?: string;
  verified: 'linux-osquery-5.0.1' | 'unverified';
  requiresExtension?: boolean;
}

const L = 'linux-osquery-5.0.1' as const;
const U = 'unverified' as const;
const HOUR = 3600;
const DAY = 86400;

export const FIM_CATALOG: FimCatalogSource[] = [
  // ---------------------------------------------------------------- Linux
  { id: 'users', label: 'Local users', platform: 'linux', category: 'accounts', severity: 'high', verified: L, intervalHint: HOUR,
    description: 'Accounts in /etc/passwd: uid, gid, home directory and shell.',
    sql: 'SELECT username, uid, gid, description, directory, shell FROM users',
    keyColumns: ['username'], valueColumns: ['uid', 'gid', 'description', 'directory', 'shell'] },
  { id: 'groups', label: 'Local groups', platform: 'linux', category: 'accounts', severity: 'medium', verified: L, intervalHint: HOUR,
    description: 'Groups in /etc/group.',
    sql: 'SELECT groupname, gid FROM groups', keyColumns: ['groupname'], valueColumns: ['gid'] },
  { id: 'user_groups', label: 'Group memberships', platform: 'linux', category: 'accounts', severity: 'high', verified: L, intervalHint: HOUR,
    description: 'Which user belongs to which group.',
    sql: 'SELECT u.username AS username, g.groupname AS groupname, g.gid AS gid FROM user_groups ug JOIN users u ON u.uid = ug.uid JOIN groups g ON g.gid = ug.gid',
    keyColumns: ['username', 'groupname'], valueColumns: ['gid'] },
  { id: 'sudoers', label: 'sudo rules', platform: 'linux', category: 'accounts', severity: 'critical', verified: L, intervalHint: HOUR,
    description: 'Rules from /etc/sudoers and /etc/sudoers.d (needs root).',
    sql: 'SELECT source, header, rule_details FROM sudoers', keyColumns: ['source', 'header', 'rule_details'], valueColumns: [],
    notes: 'Each rule is its own item, so edits show as one removed + one added rule.' },
  { id: 'authorized_keys', label: 'SSH authorized keys', platform: 'linux', category: 'accounts', severity: 'critical', verified: L, intervalHint: HOUR,
    description: 'Public keys allowed to log in for each user.',
    sql: 'SELECT key_file, key, algorithm FROM authorized_keys', keyColumns: ['key_file', 'key'], valueColumns: ['algorithm'] },
  { id: 'listening_ports', label: 'Listening ports', platform: 'linux', category: 'network', severity: 'high', verified: L, intervalHint: 900,
    description: 'Sockets in LISTEN state with the owning process name and path (never the pid).',
    sql: 'SELECT lp.protocol AS protocol, lp.port AS port, lp.address AS address, p.name AS process, p.path AS process_path FROM listening_ports lp LEFT JOIN processes p ON p.pid = lp.pid WHERE lp.port <> 0',
    keyColumns: ['protocol', 'port', 'address'], valueColumns: ['process', 'process_path'],
    notes: 'protocol is the IP protocol number (6 = TCP, 17 = UDP). Ephemeral client ports are not listed.' },
  { id: 'kernel_modules', label: 'Kernel modules', platform: 'linux', category: 'kernel', severity: 'high', verified: L, intervalHint: HOUR,
    description: 'Loaded kernel modules and their size.',
    sql: 'SELECT name, size, status FROM kernel_modules', keyColumns: ['name'], valueColumns: ['size', 'status'] },
  { id: 'crontab', label: 'Cron jobs', platform: 'linux', category: 'persistence', severity: 'high', verified: L, intervalHint: HOUR,
    description: 'Entries in system and user crontabs.',
    sql: 'SELECT path, minute, hour, day_of_month, month, day_of_week, command FROM crontab',
    keyColumns: ['path', 'minute', 'hour', 'day_of_month', 'month', 'day_of_week', 'command'], valueColumns: [] },
  { id: 'systemd_units', label: 'systemd units', platform: 'linux', category: 'persistence', severity: 'high', verified: L, intervalHint: HOUR,
    description: 'Unit files, their load state (loaded/masked/not-found) and owner. Run state (active/sub state) is deliberately not compared.',
    sql: 'SELECT id, fragment_path, load_state, source_path, user FROM systemd_units', keyColumns: ['id'], valueColumns: ['fragment_path', 'load_state', 'source_path', 'user'] },
  { id: 'startup_items', label: 'Startup items', platform: 'linux', category: 'persistence', severity: 'high', verified: L, intervalHint: HOUR,
    description: 'Autostart entries and init scripts.',
    sql: 'SELECT name, path, source, args, type, status, username FROM startup_items',
    keyColumns: ['name', 'path', 'source'], valueColumns: ['args', 'type', 'status', 'username'] },
  { id: 'deb_packages', label: 'Installed packages (dpkg)', platform: 'linux', category: 'software', severity: 'medium', verified: L, intervalHint: 6 * HOUR,
    description: 'Debian/Ubuntu packages and versions.',
    sql: 'SELECT name, arch, version, revision FROM deb_packages', keyColumns: ['name', 'arch'], valueColumns: ['version', 'revision'],
    notes: 'A desktop install has ~2,000-3,000 packages; the result must stay below the osquery line limit.' },
  { id: 'rpm_packages', label: 'Installed packages (rpm)', platform: 'linux', category: 'software', severity: 'medium', verified: L, intervalHint: 6 * HOUR,
    description: 'RPM packages and versions.',
    sql: 'SELECT name, arch, version, release FROM rpm_packages', keyColumns: ['name', 'arch'], valueColumns: ['version', 'release'] },
  { id: 'apt_sources', label: 'APT repositories', platform: 'linux', category: 'software', severity: 'high', verified: L, intervalHint: 6 * HOUR,
    description: 'Configured package repositories.',
    sql: 'SELECT source, base_uri, release, components, name FROM apt_sources', keyColumns: ['source', 'base_uri', 'release'], valueColumns: ['components', 'name'] },
  { id: 'iptables', label: 'Firewall rules (iptables)', platform: 'linux', category: 'network', severity: 'high', verified: L, intervalHint: HOUR,
    description: 'iptables rules and chain policies (needs root). Packet/byte counters are not compared.',
    sql: 'SELECT filter_name, chain, target, protocol, src_ip, src_mask, dst_ip, dst_mask, src_port, dst_port, iniface, outiface, policy FROM iptables',
    keyColumns: ['filter_name', 'chain', 'target', 'protocol', 'src_ip', 'src_mask', 'dst_ip', 'dst_mask', 'src_port', 'dst_port', 'iniface', 'outiface'], valueColumns: ['policy'] },
  { id: 'mounts', label: 'Mounted filesystems', platform: 'linux', category: 'system', severity: 'medium', verified: L, intervalHint: HOUR,
    description: 'Mount points, device, filesystem type and mount flags (usage figures are not compared).',
    sql: 'SELECT path, device, type, flags FROM mounts', keyColumns: ['path'], valueColumns: ['device', 'type', 'flags'] },
  { id: 'suid_bin', label: 'SUID/SGID binaries', platform: 'linux', category: 'system', severity: 'high', verified: L, intervalHint: DAY,
    description: 'Binaries with the set-uid/set-gid bit anywhere on the system.',
    sql: 'SELECT path, username, groupname, permissions FROM suid_bin', keyColumns: ['path'], valueColumns: ['username', 'groupname', 'permissions'],
    notes: 'Scans the whole filesystem; use a daily interval.' },
  { id: 'ssh_configs', label: 'SSH client config', platform: 'linux', category: 'accounts', severity: 'medium', verified: L, intervalHint: HOUR,
    description: 'Options in users\' ~/.ssh/config.',
    sql: 'SELECT ssh_config_file, block, option FROM ssh_configs', keyColumns: ['ssh_config_file', 'block', 'option'], valueColumns: [] },
  { id: 'selinux_settings', label: 'SELinux settings', platform: 'linux', category: 'system', severity: 'high', verified: L, intervalHint: HOUR,
    description: 'SELinux boolean and mode settings (empty where SELinux is absent).',
    sql: 'SELECT scope, key, value FROM selinux_settings', keyColumns: ['scope', 'key'], valueColumns: ['value'] },
  { id: 'certificates_linux', label: 'Trusted CA certificates', platform: 'linux', category: 'system', severity: 'high', verified: L, intervalHint: 6 * HOUR,
    description: 'Certificates in the system trust store.',
    sql: "SELECT sha1, path, common_name, issuer FROM certificates WHERE path LIKE '/etc/ssl/certs/%'", keyColumns: ['sha1', 'path'], valueColumns: ['common_name', 'issuer'],
    notes: 'The bundle file lists every CA; expect a few hundred items.' },

  // -------------------------------------------------------------- Windows (UNVERIFIED: no Windows agent available to test)
  { id: 'users_win', label: 'Local users', platform: 'windows', category: 'accounts', severity: 'high', verified: U, intervalHint: HOUR,
    description: 'Local accounts keyed by SID.',
    sql: 'SELECT uuid, username, description, directory, type FROM users', keyColumns: ['uuid'], valueColumns: ['username', 'description', 'directory', 'type'] },
  { id: 'groups_win', label: 'Local groups', platform: 'windows', category: 'accounts', severity: 'medium', verified: U, intervalHint: HOUR,
    description: 'Local groups keyed by SID.',
    sql: 'SELECT group_sid, groupname, comment FROM groups', keyColumns: ['group_sid'], valueColumns: ['groupname', 'comment'] },
  { id: 'user_groups_win', label: 'Group memberships', platform: 'windows', category: 'accounts', severity: 'high', verified: U, intervalHint: HOUR,
    description: 'Which user belongs to which group (e.g. local Administrators).',
    sql: 'SELECT u.username AS username, g.groupname AS groupname FROM user_groups ug JOIN users u ON u.uid = ug.uid JOIN groups g ON g.gid = ug.gid',
    keyColumns: ['username', 'groupname'], valueColumns: [] },
  { id: 'services', label: 'Services', platform: 'windows', category: 'persistence', severity: 'high', verified: U, intervalHint: HOUR,
    description: 'Service definitions: start type, binary path and account. Running status is deliberately not compared.',
    sql: 'SELECT name, display_name, service_type, start_type, path, module_path, user_account FROM services',
    keyColumns: ['name'], valueColumns: ['display_name', 'service_type', 'start_type', 'path', 'module_path', 'user_account'] },
  { id: 'scheduled_tasks', label: 'Scheduled tasks', platform: 'windows', category: 'persistence', severity: 'high', verified: U, intervalHint: HOUR,
    description: 'Task Scheduler tasks and their actions.',
    sql: 'SELECT name, action, path, enabled, hidden FROM scheduled_tasks', keyColumns: ['name'], valueColumns: ['action', 'path', 'enabled', 'hidden'] },
  { id: 'startup_items_win', label: 'Startup items', platform: 'windows', category: 'persistence', severity: 'high', verified: U, intervalHint: HOUR,
    description: 'Run keys and startup folders.',
    sql: 'SELECT name, path, source, args, type, status, username FROM startup_items',
    keyColumns: ['name', 'path', 'source'], valueColumns: ['args', 'type', 'status', 'username'] },
  { id: 'programs', label: 'Installed software', platform: 'windows', category: 'software', severity: 'medium', verified: U, intervalHint: 6 * HOUR,
    description: 'Programs from Add/Remove Programs.',
    sql: 'SELECT name, identifying_number, version, publisher, install_location FROM programs',
    keyColumns: ['name', 'identifying_number'], valueColumns: ['version', 'publisher', 'install_location'] },
  { id: 'patches', label: 'Installed patches', platform: 'windows', category: 'software', severity: 'medium', verified: U, intervalHint: 6 * HOUR,
    description: 'Installed hotfixes.',
    sql: 'SELECT hotfix_id, description, installed_by FROM patches', keyColumns: ['hotfix_id'], valueColumns: ['description', 'installed_by'] },
  { id: 'drivers', label: 'Drivers', platform: 'windows', category: 'kernel', severity: 'high', verified: U, intervalHint: 6 * HOUR,
    description: 'Installed device drivers.',
    sql: 'SELECT device_id, device_name, image, service, version, provider, signed FROM drivers',
    keyColumns: ['device_id'], valueColumns: ['device_name', 'image', 'service', 'version', 'provider', 'signed'] },
  { id: 'listening_ports_win', label: 'Listening ports', platform: 'windows', category: 'network', severity: 'high', verified: U, intervalHint: 900,
    description: 'Sockets in LISTEN state with the owning process (never the pid).',
    sql: 'SELECT lp.protocol AS protocol, lp.port AS port, lp.address AS address, p.name AS process, p.path AS process_path FROM listening_ports lp LEFT JOIN processes p ON p.pid = lp.pid WHERE lp.port <> 0',
    keyColumns: ['protocol', 'port', 'address'], valueColumns: ['process', 'process_path'] },
  { id: 'certificates_win', label: 'Certificate stores', platform: 'windows', category: 'system', severity: 'high', verified: U, intervalHint: 6 * HOUR,
    description: 'Certificates in the machine certificate stores.',
    sql: "SELECT sha1, store_location, store, subject, issuer FROM certificates WHERE store_location = 'LocalMachine'",
    keyColumns: ['sha1', 'store_location', 'store'], valueColumns: ['subject', 'issuer'] },
  { id: 'wmi_cli_event_consumers', label: 'WMI command-line consumers', platform: 'windows', category: 'persistence', severity: 'critical', verified: U, intervalHint: HOUR,
    description: 'WMI event consumers that run commands (a common persistence technique).',
    sql: 'SELECT relative_path, name, command_line_template, executable_path FROM wmi_cli_event_consumers',
    keyColumns: ['relative_path'], valueColumns: ['name', 'command_line_template', 'executable_path'] },
  { id: 'wmi_event_filters', label: 'WMI event filters', platform: 'windows', category: 'persistence', severity: 'critical', verified: U, intervalHint: HOUR,
    description: 'WMI event filters (the trigger half of WMI persistence).',
    sql: 'SELECT relative_path, name, query, query_language FROM wmi_event_filters',
    keyColumns: ['relative_path'], valueColumns: ['name', 'query', 'query_language'] },
  { id: 'wmi_filter_consumer_binding', label: 'WMI filter-consumer bindings', platform: 'windows', category: 'persistence', severity: 'critical', verified: U, intervalHint: HOUR,
    description: 'Bindings that connect WMI filters to consumers.',
    sql: 'SELECT consumer, filter FROM wmi_filter_consumer_binding', keyColumns: ['consumer', 'filter'], valueColumns: [] },
  { id: 'appcompat_shims', label: 'Application compatibility shims', platform: 'windows', category: 'persistence', severity: 'high', verified: U, intervalHint: 6 * HOUR,
    description: 'Installed AppCompat shims (used for persistence/injection).',
    sql: 'SELECT sdb_id, executable, path, description, type FROM appcompat_shims', keyColumns: ['sdb_id', 'executable'], valueColumns: ['path', 'description', 'type'] },
  { id: 'windows_security_products', label: 'Security products', platform: 'windows', category: 'posture', severity: 'high', verified: U, intervalHint: HOUR,
    description: 'Registered antivirus/firewall products and their state (timestamps are not compared).',
    sql: 'SELECT type, name, state FROM windows_security_products', keyColumns: ['type', 'name'], valueColumns: ['state'] },
  { id: 'bitlocker_info', label: 'BitLocker', platform: 'windows', category: 'posture', severity: 'high', verified: U, intervalHint: 6 * HOUR,
    description: 'BitLocker protection per volume (encryption percentage is not compared).',
    sql: 'SELECT drive_letter, protection_status, conversion_status, encryption_method, lock_status FROM bitlocker_info',
    keyColumns: ['drive_letter'], valueColumns: ['protection_status', 'conversion_status', 'encryption_method', 'lock_status'] },
  { id: 'secureboot', label: 'Secure Boot', platform: 'windows', category: 'posture', severity: 'high', verified: U, intervalHint: 6 * HOUR,
    description: 'Secure Boot state.',
    sql: "SELECT 'secureboot' AS setting, secure_boot, setup_mode FROM secureboot", keyColumns: ['setting'], valueColumns: ['secure_boot', 'setup_mode'] },
  // Extension hook (disabled unless explicitly enabled; the agent must load the extension).
  { id: 'registry_acl_ext', label: 'Registry key ACLs (extension)', platform: 'windows', category: 'persistence', severity: 'high', verified: U, intervalHint: 6 * HOUR,
    requiresExtension: true,
    description: 'ACL entries on registry keys. Stock osquery does not expose these; needs the vajra_registry_acl extension table.',
    sql: 'SELECT key_path, principal, ace_type, access_mask, inherited FROM vajra_registry_acl',
    keyColumns: ['key_path', 'principal', 'ace_type'], valueColumns: ['access_mask', 'inherited'] },
];

const BY_ID = new Map(FIM_CATALOG.map((s) => [s.id, s]));
export const getCatalogSource = (id: string): FimCatalogSource | undefined => BY_ID.get(id);

/** Public metadata: never exposes SQL. */
export function catalogMetadata(platform?: FimOsPlatform) {
  return FIM_CATALOG.filter((s) => !platform || s.platform === platform).map((s) => ({
    id: s.id, label: s.label, platform: s.platform, description: s.description, category: s.category,
    severity: s.severity, keyColumns: s.keyColumns, valueColumns: s.valueColumns, intervalHint: s.intervalHint,
    notes: s.notes ?? null, verified: s.verified === 'unverified' ? false : true, requiresExtension: !!s.requiresExtension,
  }));
}
