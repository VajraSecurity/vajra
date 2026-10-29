import type { FimEntryKind, FimOsPlatform } from './fimLogic';
import { getRegCatalogEntry } from './fimRegistryCatalog';

export interface FimTemplate {
  id: string;
  name: string;
  description: string;
  osPlatform: FimOsPlatform;
  paths: ({ kind?: FimEntryKind; path?: string; source?: string; severity: 'low' | 'medium' | 'high' | 'critical'; category: string; ignore: string[]; hash: boolean } & Record<string, unknown>)[];
  scanIntervalSecs: number;
  realtime: boolean;
  /** Template content version; policies created from an older version can be upgraded on request. */
  version?: number;
}

// Entry sizing: osquery drops any single result line > ~1 MiB (~2,500 files), so every
// entry must plausibly stay below that. File counts measured with
// `osqueryd -S --json "select count(*) from file where path like '<dir>/%%'"` on a
// desktop Ubuntu box: /usr/bin 4482 and /usr/lib 14225 (/lib/modules 146338,
// /usr/lib/x86_64-linux-gnu 4806) are TOO BIG and are therefore NOT scanned
// recursively; /usr/sbin 659, /usr/libexec 276, /usr/lib/systemd 968, /boot 329,
// /usr/local/bin 3, /var/www 1026 are fine. Critical /usr/bin binaries are listed
// individually instead.
type Sev = 'low' | 'medium' | 'high' | 'critical';
const p = (path: string, severity: Sev, category: string, ignore: string[] = []) =>
  ({ path, severity, category, ignore, hash: true });
// Item kinds (the server fills label/prefix/columns from the catalog on save).
const x = (path: string, severity: Sev = 'high', category = 'acl') => ({ kind: 'xattr' as const, path, severity, category, ignore: [] as string[], hash: false });
const acl = (path: string, severity: Sev = 'high', category = 'acl') => ({ kind: 'acl' as const, path, severity, category, ignore: [] as string[], hash: false });
const tbl = (source: string, severity: Sev, category: string) => ({ kind: 'table' as const, source, severity, category, ignore: [] as string[], hash: false });
/**
 * Registry v2 entry taken from the built-in registry catalog (value allow-lists, deny-lists,
 * anchor, hive scoping, host-side redaction): the same definition the per-node coverage uses.
 */
const regV2 = (id: string) => {
  const c = getRegCatalogEntry(id);
  if (!c) throw new Error(`fimTemplates: unknown registry catalog id ${id}`);
  return {
    kind: 'registry' as const, path: c.path, severity: c.severity, category: c.category, label: c.label, ignore: [] as string[], hash: false,
    entryKey: c.id, values: [...c.values], ignoreValues: [...c.ignoreValues], redactValues: [...c.redactValues],
    includeSubkeys: c.values.length === 0, anchor: true, hiveScoped: c.path.toUpperCase().startsWith('HKEY_USERS\\%\\'),
  };
};

export const FIM_TEMPLATES: FimTemplate[] = [
  {
    id: 'linux-cis-system',
    name: 'Linux: system config & auth (CIS)',
    description: 'Core system configuration and authentication files (CIS-aligned).',
    osPlatform: 'linux',
    paths: [
      p('/etc/passwd', 'critical', 'auth'), p('/etc/shadow', 'critical', 'auth'), p('/etc/group', 'high', 'auth'),
      p('/etc/gshadow', 'high', 'auth'), p('/etc/sudoers', 'critical', 'auth'), p('/etc/sudoers.d/%%', 'critical', 'auth'),
      p('/etc/pam.d/%%', 'high', 'auth'), p('/etc/security/%%', 'high', 'auth'), p('/etc/login.defs', 'medium', 'auth'),
      p('/etc/hosts', 'medium', 'config'), p('/etc/resolv.conf', 'medium', 'config', ['/etc/resolv.conf.*']),
      p('/etc/fstab', 'medium', 'config'), p('/etc/sysctl.conf', 'medium', 'config'), p('/etc/sysctl.d/%%', 'medium', 'config'),
      p('/etc/audit/%%', 'high', 'audit'),
    ],
    scanIntervalSecs: 3600, realtime: true,
  },
  {
    id: 'linux-ssh-persistence',
    name: 'Linux: SSH & persistence',
    description: 'SSH configuration and common persistence locations (cron, systemd, rc, profile).',
    osPlatform: 'linux',
    paths: [
      p('/etc/ssh/%%', 'critical', 'ssh'), p('/root/.ssh/%%', 'critical', 'ssh'), p('/home/%/.ssh/%%', 'critical', 'ssh'),
      p('/etc/crontab', 'high', 'persistence'), p('/etc/cron.d/%%', 'high', 'persistence'),
      p('/etc/cron.daily/%%', 'high', 'persistence'), p('/var/spool/cron/%%', 'high', 'persistence'),
      p('/etc/systemd/system/%%', 'high', 'persistence'), p('/usr/lib/systemd/system/%%', 'medium', 'persistence'),
      p('/etc/rc.local', 'high', 'persistence'), p('/etc/profile', 'medium', 'persistence'),
      p('/etc/profile.d/%%', 'medium', 'persistence'), p('/etc/ld.so.preload', 'critical', 'persistence'),
    ],
    scanIntervalSecs: 1800, realtime: true,
  },
  {
    id: 'linux-binaries-libs',
    name: 'Linux: binaries & libraries',
    description: 'System binaries and shared libraries; detects trojaned or replaced executables.',
    osPlatform: 'linux',
    paths: [
      p('/usr/sbin/%%', 'high', 'binary'), p('/usr/local/bin/%%', 'high', 'binary'),
      p('/usr/local/sbin/%%', 'high', 'binary'), p('/usr/libexec/%%', 'medium', 'binary'),
      p('/usr/lib/systemd/%%', 'high', 'persistence'), p('/boot/%%', 'high', 'boot'),
      p('/bin/bash', 'high', 'binary'), p('/bin/sh', 'high', 'binary'), p('/usr/bin/sudo', 'critical', 'binary'),
      p('/usr/bin/su', 'critical', 'binary'), p('/usr/bin/passwd', 'critical', 'binary'),
      p('/usr/bin/ssh', 'high', 'binary'), p('/usr/bin/sshd', 'high', 'binary'),
      p('/usr/bin/crontab', 'high', 'binary'), p('/usr/bin/systemctl', 'high', 'binary'),
      p('/usr/bin/curl', 'medium', 'binary'), p('/usr/bin/wget', 'medium', 'binary'),
    ],
    scanIntervalSecs: 21600, realtime: false,
  },
  {
    id: 'windows-system-drivers',
    name: 'Windows: system & drivers',
    description: 'Windows system directories, drivers and hosts file.',
    osPlatform: 'windows',
    paths: [
      p('C:\\Windows\\System32\\drivers\\etc\\%', 'high', 'config'), p('C:\\Windows\\System32\\drivers\\%', 'high', 'driver'),
      p('C:\\Windows\\System32\\cmd.exe', 'high', 'binary'),
      p('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'high', 'binary'), p('C:\\Windows\\System32\\WindowsPowerShell\\%%', 'high', 'binary'),
      p('C:\\Windows\\System32\\Tasks\\%%', 'high', 'persistence'),
    ],
    scanIntervalSecs: 3600, realtime: true,
  },
  {
    id: 'windows-startup-persistence',
    name: 'Windows: startup & persistence',
    description: 'Startup folders and common persistence locations.',
    osPlatform: 'windows',
    paths: [
      p('C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\%', 'high', 'persistence'),
      p('C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%', 'high', 'persistence'),
      p('C:\\Windows\\System32\\Tasks\\%%', 'high', 'persistence'),
      p('C:\\Windows\\Tasks\\%', 'medium', 'persistence'),
      p('C:\\Windows\\System32\\wbem\\Repository\\%', 'medium', 'persistence'),
    ],
    scanIntervalSecs: 1800, realtime: true,
  },
  {
    id: 'web-server-content-linux',
    name: 'Web server content (Linux)',
    description: 'Web roots and web server configuration (PCI-DSS 11.5 style tamper detection).',
    osPlatform: 'linux',
    paths: [
      p('/var/www/%%', 'high', 'web', ['/var/www/%/cache/%%', '/var/www/%/logs/%%']),
      p('/etc/nginx/%%', 'high', 'web'), p('/etc/apache2/%%', 'high', 'web'), p('/etc/httpd/%%', 'high', 'web'),
      p('/usr/share/nginx/html/%%', 'high', 'web'),
    ],
    scanIntervalSecs: 900, realtime: true,
  },
  // ------------------------------------------------------------------ beyond files (Linux)
  {
    id: 'linux-accounts-access',
    name: 'Linux: accounts & access',
    description: 'Users, groups, memberships, sudo rules and SSH authorized keys, plus the account files themselves.',
    osPlatform: 'linux',
    paths: [
      tbl('users', 'high', 'accounts'), tbl('groups', 'medium', 'accounts'), tbl('user_groups', 'high', 'accounts'),
      tbl('sudoers', 'critical', 'accounts'), tbl('authorized_keys', 'critical', 'accounts'),
      p('/etc/passwd', 'critical', 'auth'), p('/etc/shadow', 'critical', 'auth'), p('/etc/group', 'high', 'auth'), p('/etc/sudoers', 'critical', 'auth'),
    ],
    scanIntervalSecs: 3600, realtime: true,
  },
  {
    id: 'linux-network-exposure',
    name: 'Linux: network exposure',
    description: 'Listening ports (with the owning process) and firewall rules.',
    osPlatform: 'linux',
    paths: [tbl('listening_ports', 'high', 'network'), tbl('iptables', 'high', 'network')],
    scanIntervalSecs: 900, realtime: false,
  },
  {
    id: 'linux-kernel-packages',
    name: 'Linux: kernel, modules & packages',
    description: 'Loaded kernel modules, installed packages (dpkg and rpm) and APT repositories.',
    osPlatform: 'linux',
    paths: [tbl('kernel_modules', 'high', 'kernel'), tbl('deb_packages', 'medium', 'software'), tbl('rpm_packages', 'medium', 'software'), tbl('apt_sources', 'high', 'software')],
    scanIntervalSecs: 21600, realtime: false,
  },
  {
    id: 'linux-tasks-services',
    name: 'Linux: scheduled tasks & services',
    description: 'Cron jobs, systemd units and startup items - the usual persistence places.',
    osPlatform: 'linux',
    paths: [tbl('crontab', 'high', 'persistence'), tbl('systemd_units', 'high', 'persistence'), tbl('startup_items', 'high', 'persistence')],
    scanIntervalSecs: 3600, realtime: false,
  },
  {
    id: 'linux-acls-capabilities',
    name: 'Linux: ACLs & capabilities',
    description: 'POSIX ACLs, file capabilities and SELinux labels (extended attributes) on sensitive directories.',
    osPlatform: 'linux',
    // Extended attributes only produce rows for files that HAVE one, so even /etc/%% stays small
    // (measured: 0 rows on a stock desktop). /usr/bin/%% is avoided because walking it is slow.
    paths: [x('/etc/%%'), x('/usr/sbin/%%'), x('/usr/local/bin/%%'), x('/etc/ssh/%%', 'critical', 'ssh'), x('/root/.ssh/%%', 'critical', 'ssh'), x('/home/%/.ssh/%%', 'critical', 'ssh')],
    scanIntervalSecs: 21600, realtime: false,
  },
  {
    id: 'linux-directories-permissions',
    name: 'Linux: directories & permissions',
    description: 'Directory and file ownership/mode changes. Entries ending in / track the directory itself; directories inside a pattern are tracked automatically. On Windows use NTFS ACL entries for directory permissions.',
    osPlatform: 'linux',
    // /etc/%% is not used: it holds >2,500 entries on a desktop (measured 4018).
    paths: [
      p('/etc/ssh/%%', 'critical', 'ssh'), p('/etc/sudoers.d/%%', 'critical', 'auth'), p('/etc/pam.d/%%', 'high', 'auth'),
      p('/etc/cron.d/%%', 'high', 'persistence'), p('/etc/systemd/system/%%', 'high', 'persistence'),
      p('/var/spool/cron/%%', 'high', 'persistence'), p('/home/%/.ssh/%%', 'critical', 'ssh'),
      // A trailing '/' tracks the directory ITSELF (its own mode/owner), not its contents.
      p('/etc/ssh/', 'critical', 'ssh'), p('/etc/sudoers.d/', 'critical', 'auth'), p('/root/.ssh/', 'critical', 'ssh'),
    ],
    scanIntervalSecs: 3600, realtime: true,
  },
  // ---------------------------------------------------------------- beyond files (Windows)
  // Registry, NTFS ACL and the Windows catalog tables are UNVERIFIED (no Windows agent here).
  {
    // Template v2 (FIM_REGISTRY_DESIGN §1.6 / §3.15 step 1). v1 baselined whole keys and raised false
    // drift on every boot (Lsa\LsaPid), logoff (Winlogon\LastLogOffEndTimePerfCounter) and update
    // (Session Manager\PendingFileRenameOperations), duplicated every per-user value through the
    // S-1-5-18 alias of .DEFAULT, and had realtime off. v2 uses value allow-lists, skips S-1-5-18,
    // keeps anchors so deleted keys are seen, redacts Winlogon passwords on the host and enables
    // real-time. Existing v1 policies are not touched; the UI offers "Update to v2" (rev bump, then
    // Initialize). NOT HKLM\SYSTEM\CurrentControlSet\Services\% unfiltered (~6,900 rows / 1 MiB).
    id: 'windows-registry-persistence',
    name: 'Windows: registry persistence',
    description: 'Run/RunOnce, Winlogon, IFEO, AppInit_DLLs, LSA, Session Manager, Active Setup, startup folders and environment, with value allow-lists (needs Windows agent support - verify).',
    osPlatform: 'windows',
    version: 2,
    paths: [
      regV2('reg.run.hklm'), regV2('reg.runonce.hklm'), regV2('reg.run.hku'), regV2('reg.runonce.hku'),
      regV2('reg.winlogon'), regV2('reg.ifeo'), regV2('reg.appinit'), regV2('reg.lsa'), regV2('reg.sessmgr'),
      regV2('reg.activesetup'), regV2('reg.policies.run.hklm'), regV2('reg.shellfolders.startup'),
      regV2('reg.usershellfolders.startup'), regV2('reg.env.machine'), regV2('reg.env.user'),
    ],
    scanIntervalSecs: 3600, realtime: true,
  },
  {
    id: 'windows-accounts',
    name: 'Windows: accounts',
    description: 'Local users, groups and group memberships (needs Windows agent support - verify).',
    osPlatform: 'windows',
    paths: [tbl('users_win', 'high', 'accounts'), tbl('groups_win', 'medium', 'accounts'), tbl('user_groups_win', 'high', 'accounts')],
    scanIntervalSecs: 3600, realtime: false,
  },
  {
    id: 'windows-services-tasks-wmi',
    name: 'Windows: services, tasks & WMI persistence',
    description: 'Services, scheduled tasks, startup items and WMI event consumers/filters/bindings (needs Windows agent support - verify).',
    osPlatform: 'windows',
    paths: [
      tbl('services', 'high', 'persistence'), tbl('scheduled_tasks', 'high', 'persistence'), tbl('startup_items_win', 'high', 'persistence'),
      tbl('wmi_cli_event_consumers', 'critical', 'persistence'), tbl('wmi_event_filters', 'critical', 'persistence'),
      tbl('wmi_filter_consumer_binding', 'critical', 'persistence'), tbl('appcompat_shims', 'high', 'persistence'),
    ],
    scanIntervalSecs: 3600, realtime: false,
  },
  {
    id: 'windows-software-patches',
    name: 'Windows: installed software & patches',
    description: 'Installed programs, hotfixes and drivers (needs Windows agent support - verify).',
    osPlatform: 'windows',
    paths: [tbl('programs', 'medium', 'software'), tbl('patches', 'medium', 'software'), tbl('drivers', 'high', 'kernel')],
    scanIntervalSecs: 21600, realtime: false,
  },
  {
    id: 'windows-security-posture',
    name: 'Windows: security posture',
    description: 'Security products, BitLocker, Secure Boot, listening ports and trusted certificates (needs Windows agent support - verify).',
    osPlatform: 'windows',
    paths: [
      tbl('windows_security_products', 'high', 'posture'), tbl('bitlocker_info', 'high', 'posture'), tbl('secureboot', 'high', 'posture'),
      tbl('listening_ports_win', 'high', 'network'), tbl('certificates_win', 'high', 'system'),
    ],
    scanIntervalSecs: 3600, realtime: false,
  },
  {
    id: 'windows-acls-critical',
    name: 'Windows: ACLs on critical paths',
    description: 'NTFS permissions of critical folders and binaries (exact paths; needs Windows agent support - verify).',
    osPlatform: 'windows',
    paths: [
      acl('C:\\Windows'), acl('C:\\Windows\\System32'), acl('C:\\Windows\\SysWOW64'), acl('C:\\Windows\\System32\\drivers'),
      acl('C:\\Windows\\System32\\drivers\\etc'), acl('C:\\Windows\\System32\\Tasks'),
      acl('C:\\Windows\\System32\\cmd.exe'), acl('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'),
      acl('C:\\Program Files'), acl('C:\\Program Files (x86)'),
      acl('C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp', 'critical', 'persistence'),
    ],
    scanIntervalSecs: 21600, realtime: false,
  },
];
