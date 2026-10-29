/**
 * Built-in Windows registry catalog (layer L0) for per-node registry coverage.
 * Source: docs/FIM_REGISTRY_DESIGN.md §2 (vajra_server repo). Versioned: bump
 * REG_CATALOG_VERSION whenever an entry is added, removed or changes what it scans; the
 * reconcile job then re-resolves every node (new Essential entries -> pending publish;
 * removed ids stay effective until an admin applies, §4.6).
 *
 * Tiers nest: essential ⊂ recommended ⊂ comprehensive. Every Essential entry and the agent
 * self-protection entries are PROTECTED (disable / narrow / exclude / lower severity only
 * with an approved two-person waiver). `optInOnly` entries belong to no tier (explicit add).
 *
 * `verified`: true only where the design has real rows from a Windows agent export ([V]).
 * Everything else is an estimate from Windows knowledge ([U]) and is shown as UNVERIFIED in
 * the UI until a probe on a Windows agent replaces the numbers (design step 6, assumption A2).
 * Estimates (rows/bytes) are per host per full scan; `anchorRows` estimates the extra anchor
 * rows of a pattern ending in '%' (one per child key).
 *
 * Every entry is validated by normalizeRegistryEntryV2 and its SQL generated in
 * src/test/utils/fimRegistry.selftest.ts, so a typo here fails CI.
 */
import type { FimSeverity } from './fimLogic';

export const REG_CATALOG_VERSION = 1;

export type RegTier = 'essential' | 'recommended' | 'comprehensive';
export const REG_TIERS: RegTier[] = ['essential', 'recommended', 'comprehensive'];
export const REG_TIER_RANK: Record<RegTier, number> = { essential: 0, recommended: 1, comprehensive: 2 };

export interface RegCatalogEntry {
  id: string;
  tier: RegTier;
  optInOnly: boolean;
  path: string;
  values: string[];
  ignoreValues: string[];
  redactValues: string[];
  label: string;
  category: string;
  severity: FimSeverity;
  attack: string[];
  est: { rows: number; bytes: number };
  anchorRows: number;
  noise: 'none' | 'low' | 'medium' | 'high';
  verified: boolean;
  protected: boolean;
  realtimeRequired: boolean;
  /** Catalog-only pattern exemptions (validated in the selftest). */
  allowRecursive: boolean;
  maxWildcards: number;
  notes: string | null;
}

/**
 * Windows service names of the osquery agent(s) for the self-protection entries (§2.4).
 * Design open question Q3 (the plgx agent's service name) is unanswered, so only the stock
 * osqueryd name is built in; operators add theirs with FIM_REG_AGENT_SERVICES=name1,name2.
 */
export const FIM_REG_DEFAULT_AGENT_SERVICES = ['osqueryd'];
function agentServices(): string[] {
  const extra = (process.env.FIM_REG_AGENT_SERVICES ?? '').split(',').map((s) => s.trim()).filter((s) => /^[A-Za-z0-9_.-]{1,64}$/.test(s));
  return [...new Set([...FIM_REG_DEFAULT_AGENT_SERVICES, ...extra])];
}

const L = 'HKEY_LOCAL_MACHINE\\';
const U = 'HKEY_USERS\\%\\';
const CV = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion';
const NT = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';
const CCS = 'SYSTEM\\CurrentControlSet';
const WOW = 'SOFTWARE\\WOW6432Node\\Microsoft';
const ROW_BYTES = 190; // measured ~155 B/row + osquery envelope; used when only a row count is known

interface Opt {
  values?: string[]; ignore?: string[]; redact?: string[]; rows?: number; bytes?: number; anchorRows?: number;
  noise?: RegCatalogEntry['noise']; verified?: boolean; optIn?: boolean; realtimeRequired?: boolean;
  allowRecursive?: boolean; maxWildcards?: number; notes?: string; protected?: boolean;
}

function e(id: string, tier: RegTier, path: string, label: string, category: string, severity: FimSeverity, attack: string[], o: Opt = {}): RegCatalogEntry {
  const rows = o.rows ?? 0;
  return {
    id, tier, optInOnly: o.optIn === true, path, values: o.values ?? [], ignoreValues: o.ignore ?? [], redactValues: o.redact ?? [],
    label, category, severity, attack, est: { rows, bytes: o.bytes ?? rows * ROW_BYTES }, anchorRows: o.anchorRows ?? (path.endsWith('%') ? 10 : 1),
    noise: o.noise ?? 'low', verified: o.verified === true, protected: o.protected ?? tier === 'essential',
    realtimeRequired: o.realtimeRequired === true, allowRecursive: o.allowRecursive === true, maxWildcards: o.maxWildcards ?? 3, notes: o.notes ?? null,
  };
}

const LSA_VALUES = ['Authentication Packages', 'Security Packages', 'Notification Packages', 'RunAsPPL', 'RunAsPPLBoot', 'LmCompatibilityLevel',
  'NoLmHash', 'LimitBlankPasswordUse', 'DisableRestrictedAdmin', 'DisableDomainCreds', 'RestrictAnonymous', 'RestrictAnonymousSAM',
  'EveryoneIncludesAnonymous', 'ForceGuest', 'DsrmAdminLogonBehavior'];
const WINLOGON_VALUES = ['Shell', 'Userinit', 'Taskman', 'AppSetup', 'GinaDLL', 'System', 'VMApplet', 'UIHost', 'ShellInfrastructure',
  'AutoAdminLogon', 'DefaultPassword', 'AltDefaultPassword', 'CachedLogonsCount'];
const SESSMGR_VALUES = ['BootExecute', 'SetupExecute', 'Execute', 'S0InitialCommand', 'BootShell', 'SafeDllSearchMode', 'ProtectionMode',
  'GlobalFlag', 'ExcludeFromKnownDlls'];
const IFEO_VALUES = ['Debugger', 'GlobalFlag', 'VerifierDlls', 'VerifierFlags'];
const SECURITY_SERVICES = ['WinDefend', 'WdFilter', 'WdBoot', 'WdNisSvc', 'WdNisDrv', 'Sense', 'MDCoreSvc', 'SecurityHealthService', 'wscsvc',
  'mpssvc', 'BFE', 'EventLog', 'Sysmon64', 'SysmonDrv'];

function buildCatalog(): RegCatalogEntry[] {
  const out: RegCatalogEntry[] = [
    // ------------------------------------------------------------------ §2.1 Essential (protected)
    e('reg.run.hklm', 'essential', `${L}${CV}\\Run`, 'Run (machine)', 'persistence', 'critical', ['T1547.001'], { rows: 2, bytes: 381, verified: true }),
    e('reg.runonce.hklm', 'essential', `${L}${CV}\\RunOnce`, 'RunOnce (machine)', 'persistence', 'high', ['T1547.001'], { rows: 1, bytes: 420, verified: true, noise: 'medium', notes: 'Installers write RunOnce values (e.g. msedge_cleanup_{...}).' }),
    e('reg.runonceex.hklm', 'essential', `${L}${CV}\\RunOnceEx\\%`, 'RunOnceEx (machine)', 'persistence', 'critical', ['T1547.001'], { rows: 0, anchorRows: 2 }),
    e('reg.run.wow', 'essential', `${L}${WOW}\\Windows\\CurrentVersion\\Run`, 'Run (32-bit view)', 'persistence', 'critical', ['T1547.001'], { rows: 10 }),
    e('reg.runonce.wow', 'essential', `${L}${WOW}\\Windows\\CurrentVersion\\RunOnce`, 'RunOnce (32-bit view)', 'persistence', 'high', ['T1547.001'], { rows: 3, noise: 'medium' }),
    e('reg.run.hku', 'essential', `${U}${CV}\\Run`, 'Run (per user)', 'persistence', 'critical', ['T1547.001'], { rows: 4, bytes: 1070, verified: true, noise: 'medium', notes: 'OneDrive / Edge auto-launch values are rewritten on updates; they are deliberately NOT ignored by name (masquerading is cheap).' }),
    e('reg.runonce.hku', 'essential', `${U}${CV}\\RunOnce`, 'RunOnce (per user)', 'persistence', 'high', ['T1547.001'], { rows: 0, bytes: 2, verified: true }),
    e('reg.policies.run.hklm', 'essential', `${L}${CV}\\Policies\\Explorer\\Run`, 'Policies Explorer Run (machine)', 'persistence', 'critical', ['T1547.001'], { rows: 0, bytes: 2, verified: true }),
    e('reg.policies.run.hku', 'essential', `${U}${CV}\\Policies\\Explorer\\Run`, 'Policies Explorer Run (per user)', 'persistence', 'critical', ['T1547.001']),
    e('reg.runservices', 'essential', `${L}${CV}\\RunServices`, 'RunServices (legacy)', 'persistence', 'high', ['T1547.001']),
    e('reg.runservicesonce', 'essential', `${L}${CV}\\RunServicesOnce`, 'RunServicesOnce (legacy)', 'persistence', 'high', ['T1547.001']),
    e('reg.winlogon', 'essential', `${L}${NT}\\Winlogon`, 'Winlogon helpers', 'persistence', 'critical', ['T1547.004', 'T1552.002'], { values: WINLOGON_VALUES, redact: ['DefaultPassword', 'AltDefaultPassword'], rows: 9, bytes: 1575, verified: true, notes: 'DefaultPassword / AltDefaultPassword are redacted on the host (presence and length only).' }),
    e('reg.winlogon.hku', 'essential', `${U}${NT}\\Winlogon`, 'Winlogon shell (per user)', 'persistence', 'critical', ['T1547.004'], { values: ['Shell'] }),
    e('reg.ifeo', 'essential', `${L}${NT}\\Image File Execution Options\\%`, 'Image File Execution Options', 'persistence', 'critical', ['T1546.012', 'T1546.008'], { values: IFEO_VALUES, rows: 2, anchorRows: 60, notes: 'Key verified; value filter unverified (36 rows / 7.7 KB unfiltered).' }),
    e('reg.ifeo.wow', 'essential', `${L}${WOW}\\Windows NT\\CurrentVersion\\Image File Execution Options\\%`, 'Image File Execution Options (32-bit view)', 'persistence', 'critical', ['T1546.012'], { values: IFEO_VALUES, anchorRows: 20 }),
    e('reg.silentprocessexit', 'essential', `${L}${NT}\\SilentProcessExit\\%`, 'SilentProcessExit', 'persistence', 'critical', ['T1546.012'], { anchorRows: 0 }),
    e('reg.appinit', 'essential', `${L}${NT}\\Windows`, 'AppInit_DLLs', 'persistence', 'critical', ['T1546.010'], { values: ['AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs', 'IconServiceLib'], rows: 4, bytes: 692, verified: true }),
    e('reg.appinit.wow', 'essential', `${L}${WOW}\\Windows NT\\CurrentVersion\\Windows`, 'AppInit_DLLs (32-bit view)', 'persistence', 'critical', ['T1546.010'], { values: ['AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs'], rows: 3 }),
    e('reg.lsa', 'essential', `${L}${CCS}\\Control\\Lsa`, 'LSA packages and hardening', 'credential', 'critical', ['T1547.002', 'T1547.005', 'T1556.002', 'T1003.001', 'T1562.010'], { values: LSA_VALUES, rows: 14, bytes: 2180, verified: true, notes: 'LsaPid (new every boot) is not in the allow-list.' }),
    e('reg.lsa.osconfig', 'essential', `${L}${CCS}\\Control\\Lsa\\OSConfig`, 'LSA OSConfig security packages', 'credential', 'critical', ['T1547.005'], { values: ['Security Packages'], rows: 1 }),
    e('reg.securityproviders', 'essential', `${L}${CCS}\\Control\\SecurityProviders`, 'Security providers (SSP)', 'credential', 'critical', ['T1547.005'], { values: ['SecurityProviders'], rows: 1 }),
    e('reg.wdigest', 'essential', `${L}${CCS}\\Control\\SecurityProviders\\WDigest`, 'WDigest clear-text credentials', 'credential', 'critical', ['T1003.001'], { values: ['UseLogonCredential', 'Negotiate'], rows: 2 }),
    e('reg.netprovider.order', 'essential', `${L}${CCS}\\Control\\NetworkProvider\\Order`, 'Network provider order (NPPSpy)', 'credential', 'critical', ['T1556.008'], { values: ['ProviderOrder'], rows: 1 }),
    e('reg.sessmgr', 'essential', `${L}${CCS}\\Control\\Session Manager`, 'Session Manager boot execution', 'persistence', 'critical', ['T1547.001', 'T1574.001'], { values: SESSMGR_VALUES, rows: 5, bytes: 845, verified: true, notes: 'PendingFileRenameOperations is deliberately excluded (changes on every update).' }),
    e('reg.appcertdlls', 'essential', `${L}${CCS}\\Control\\Session Manager\\AppCertDlls`, 'AppCertDlls', 'persistence', 'critical', ['T1546.009']),
    e('reg.knowndlls', 'essential', `${L}${CCS}\\Control\\Session Manager\\KnownDLLs`, 'KnownDLLs', 'hijack', 'high', ['T1574.001'], { rows: 35, bytes: 5120 }),
    e('reg.env.machine', 'essential', `${L}${CCS}\\Control\\Session Manager\\Environment`, 'System environment (Path, COR_PROFILER, ...)', 'hijack', 'high', ['T1574.007', 'T1574.012'], { ignore: ['NUMBER_OF_PROCESSORS', 'PROCESSOR_LEVEL', 'PROCESSOR_IDENTIFIER', 'PROCESSOR_REVISION'], rows: 11, bytes: 2100, verified: true, noise: 'medium' }),
    e('reg.env.user', 'essential', `${U}Environment`, 'User environment (logon scripts, COR_PROFILER)', 'persistence', 'high', ['T1037.001', 'T1574.012', 'T1574.007'], { rows: 16, bytes: 2841, verified: true }),
    e('reg.svc.image', 'essential', `${L}${CCS}\\Services\\%`, 'Service binaries (ImagePath, ServiceDll, FailureCommand)', 'persistence', 'critical', ['T1543.003'], { values: ['ImagePath', 'ServiceDll', 'FailureCommand'], rows: 663, bytes: 126135, anchorRows: 671, verified: true, noise: 'medium', notes: 'Driver/software updates rewrite ImagePath. The unfiltered Services subtree (6,924 rows / 1 MiB) is never used.' }),
    e('reg.svc.servicedll', 'essential', `${L}${CCS}\\Services\\%\\Parameters`, 'Service DLLs (svchost Parameters)', 'persistence', 'critical', ['T1543.003', 'T1574'], { values: ['ServiceDll', 'ServiceMain'], rows: 390, bytes: 70000, anchorRows: 389 }),
    ...SECURITY_SERVICES.map((svc) => e(`reg.svc.security.start.${svc.toLowerCase()}`, 'essential', `${L}${CCS}\\Services\\${svc}`, `Security service start type: ${svc}`, 'defense-evasion', 'critical', ['T1562.001', 'T1562.002', 'T1562.004'], { values: ['Start'], rows: 1 })),
    e('reg.defender.exclusions', 'essential', `${L}SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\%`, 'Defender exclusions', 'defense-evasion', 'critical', ['T1562.001'], { rows: 20, anchorRows: 5, notes: 'Readability by SYSTEM on current builds is unverified (design Q4).' }),
    e('reg.defender.policy.exclusions', 'essential', `${L}SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\%`, 'Defender exclusions (policy)', 'defense-evasion', 'critical', ['T1562.001'], { rows: 20, anchorRows: 5 }),
    e('reg.defender.policy', 'essential', `${L}SOFTWARE\\Policies\\Microsoft\\Windows Defender`, 'Defender policy (DisableAntiSpyware, ...)', 'defense-evasion', 'critical', ['T1562.001'], { rows: 10 }),
    e('reg.defender.policy.rtp', 'essential', `${L}SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection`, 'Defender real-time protection policy', 'defense-evasion', 'critical', ['T1562.001'], { rows: 10 }),
    e('reg.defender.policy.spynet', 'essential', `${L}SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet`, 'Defender cloud protection policy', 'defense-evasion', 'critical', ['T1562.001'], { rows: 10 }),
    e('reg.defender.features', 'essential', `${L}SOFTWARE\\Microsoft\\Windows Defender\\Features`, 'Defender tamper protection', 'defense-evasion', 'critical', ['T1562.001'], { values: ['TamperProtection', 'TamperProtectionSource'], rows: 2 }),
    e('reg.amsi.providers', 'essential', `${L}SOFTWARE\\Microsoft\\AMSI\\Providers`, 'AMSI providers', 'defense-evasion', 'critical', ['T1562.001'], { rows: 3 }),
    e('reg.uac', 'essential', `${L}${CV}\\Policies\\System`, 'UAC settings', 'privilege-escalation', 'high', ['T1548.002', 'T1550.002'], { values: ['EnableLUA', 'ConsentPromptBehaviorAdmin', 'PromptOnSecureDesktop', 'LocalAccountTokenFilterPolicy', 'FilterAdministratorToken', 'EnableInstallerDetection'], rows: 6 }),
    e('reg.select', 'essential', `${L}SYSTEM\\Select`, 'Control set selection (Select)', 'defense-evasion', 'high', ['T1112', 'T1562'], { values: ['Current', 'Default', 'LastKnownGood', 'Failed'], rows: 4, notes: 'Also tells the worker which ControlSetNNN is CurrentControlSet for real-time events.' }),
    e('reg.minint', 'essential', `${L}${CCS}\\Control`, 'MiniNt (event logging disabled)', 'defense-evasion', 'critical', ['T1562.002'], { values: ['MiniNt'], notes: 'The MiniNt SUBKEY existing means event logging is disabled.' }),

    // ------------------------------------------------------------------ §2.2 Recommended
    e('reg.activesetup', 'recommended', `${L}SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\%`, 'Active Setup StubPath', 'persistence', 'high', ['T1547.014'], { values: ['StubPath'], rows: 7, bytes: 1733, anchorRows: 40, verified: true }),
    e('reg.activesetup.wow', 'recommended', `${L}${WOW}\\Active Setup\\Installed Components\\%`, 'Active Setup StubPath (32-bit view)', 'persistence', 'high', ['T1547.014'], { values: ['StubPath'], rows: 5, anchorRows: 20 }),
    e('reg.shellfolders.startup', 'recommended', `${L}${CV}\\Explorer\\Shell Folders`, 'Common Startup folder', 'persistence', 'high', ['T1547.001'], { values: ['Common Startup'], rows: 1, bytes: 241, verified: true }),
    e('reg.usershellfolders.startup.hklm', 'recommended', `${L}${CV}\\Explorer\\User Shell Folders`, 'Common Startup folder (User Shell Folders)', 'persistence', 'high', ['T1547.001'], { values: ['Common Startup'], rows: 1 }),
    e('reg.usershellfolders.startup', 'recommended', `${U}${CV}\\Explorer\\User Shell Folders`, 'Startup folder (per user)', 'persistence', 'high', ['T1547.001'], { values: ['Startup'], rows: 5, bytes: 1442, verified: true }),
    e('reg.winload.hku', 'recommended', `${U}${NT}\\Windows`, 'Windows Load/Run (per user)', 'persistence', 'critical', ['T1547.001'], { values: ['Load', 'Run'] }),
    e('reg.cmd.autorun', 'recommended', `${L}SOFTWARE\\Microsoft\\Command Processor`, 'cmd.exe AutoRun (machine)', 'persistence', 'high', ['T1546'], { values: ['AutoRun'] }),
    e('reg.cmd.autorun.hku', 'recommended', `${U}SOFTWARE\\Microsoft\\Command Processor`, 'cmd.exe AutoRun (per user)', 'persistence', 'high', ['T1546'], { values: ['AutoRun'] }),
    e('reg.netsh', 'recommended', `${L}SOFTWARE\\Microsoft\\NetSh`, 'Netsh helper DLLs', 'persistence', 'high', ['T1546.007'], { rows: 15, bytes: 2048 }),
    e('reg.timeproviders', 'recommended', `${L}${CCS}\\Services\\W32Time\\TimeProviders\\%`, 'Time providers', 'persistence', 'high', ['T1547.003'], { values: ['DllName', 'Enabled'], rows: 9, anchorRows: 4 }),
    e('reg.printmonitors', 'recommended', `${L}${CCS}\\Control\\Print\\Monitors\\%`, 'Port monitors', 'persistence', 'high', ['T1547.010'], { values: ['Driver'], rows: 8, anchorRows: 8 }),
    e('reg.printprocessors', 'recommended', `${L}${CCS}\\Control\\Print\\Environments\\Windows x64\\Print Processors\\%`, 'Print processors', 'persistence', 'high', ['T1547.012'], { values: ['Driver'], rows: 3, anchorRows: 3 }),
    e('reg.netprovider.dll', 'recommended', `${L}${CCS}\\Services\\%\\NetworkProvider`, 'Network provider DLLs', 'credential', 'high', ['T1556.008'], { values: ['ProviderPath'], rows: 5, anchorRows: 5 }),
    e('reg.safeboot.minimal', 'recommended', `${L}${CCS}\\Control\\SafeBoot\\Minimal\\%`, 'SafeBoot minimal services', 'defense-evasion', 'high', ['T1562.009'], { rows: 120, bytes: 15360, anchorRows: 60 }),
    e('reg.safeboot.network', 'recommended', `${L}${CCS}\\Control\\SafeBoot\\Network\\%`, 'SafeBoot network services', 'defense-evasion', 'high', ['T1562.009'], { rows: 160, bytes: 20480, anchorRows: 80 }),
    e('reg.safeboot.root', 'recommended', `${L}${CCS}\\Control\\SafeBoot`, 'SafeBoot AlternateShell', 'defense-evasion', 'high', ['T1562.009'], { values: ['AlternateShell'], rows: 1 }),
    ...['ms-settings', 'mscfile', 'Folder', 'exefile', 'Launcher.SystemSettings'].map((c) => e(`reg.uacbypass.${c.toLowerCase()}`, 'recommended', `${U}SOFTWARE\\Classes\\${c}\\shell\\open\\command`, `UAC bypass handler: ${c}`, 'privilege-escalation', 'critical', ['T1548.002'], { realtimeRequired: true, notes: 'Created and deleted within seconds (fodhelper / eventvwr / sdclt): needs real-time events to be seen reliably.' })),
    ...['exefile', 'batfile', 'cmdfile', 'comfile', 'htafile', 'piffile', 'scrfile', 'VBSFile', 'JSFile', 'regfile'].map((c) => e(`reg.fileassoc.${c.toLowerCase()}`, 'recommended', `${L}SOFTWARE\\Classes\\${c}\\shell\\open\\command`, `File association: ${c}`, 'persistence', 'high', ['T1546.001'], { values: ['(Default)'], rows: 1, notes: 'The default value is matched by the name "(Default)" (unverified).' })),
    e('reg.screensaver', 'recommended', `${U}Control Panel\\Desktop`, 'Screensaver', 'persistence', 'medium', ['T1546.002'], { values: ['SCRNSAVE.EXE', 'ScreenSaveActive', 'ScreenSaverIsSecure'], rows: 9 }),
    e('reg.officetest', 'recommended', `${U}SOFTWARE\\Microsoft\\Office test\\Special\\Perf`, 'Office test DLL', 'persistence', 'high', ['T1137.002'], { noise: 'none' }),
    e('reg.aedebug', 'recommended', `${L}${NT}\\AeDebug`, 'JIT debugger (AeDebug)', 'persistence', 'high', ['T1546'], { values: ['Debugger', 'Auto'], rows: 2 }),
    e('reg.aedebug.wow', 'recommended', `${L}${WOW}\\Windows NT\\CurrentVersion\\AeDebug`, 'JIT debugger (32-bit view)', 'persistence', 'high', ['T1546'], { values: ['Debugger', 'Auto'], rows: 2 }),
    e('reg.tasks.sd', 'recommended', `${L}${NT}\\Schedule\\TaskCache\\Tree\\%%`, 'Scheduled task security descriptors (Tarrask)', 'persistence', 'high', ['T1053.005'], { values: ['SD', 'Id', 'Index'], rows: 900, bytes: 300000, anchorRows: 60, allowRecursive: true, noise: 'medium', notes: 'Must be measured on a node before relying on it (estimate 150-300 KB). Recursive pattern allowed for this catalog entry only.' }),
    e('reg.rdp', 'recommended', `${L}${CCS}\\Control\\Terminal Server`, 'RDP enablement', 'lateral-movement', 'high', ['T1021.001', 'T1112'], { values: ['fDenyTSConnections', 'fSingleSessionPerUser', 'AllowRemoteRPC'], rows: 3 }),
    e('reg.rdp.tcp', 'recommended', `${L}${CCS}\\Control\\Terminal Server\\WinStations\\RDP-Tcp`, 'RDP listener settings', 'lateral-movement', 'high', ['T1021.001'], { values: ['PortNumber', 'UserAuthentication', 'SecurityLayer', 'MinEncryptionLevel', 'fInheritInitialProgram', 'InitialProgram'], rows: 6 }),
    e('reg.rdp.startup', 'recommended', `${L}${CCS}\\Control\\Terminal Server\\Wds\\rdpwd`, 'RDP startup programs', 'persistence', 'high', ['T1547'], { values: ['StartupPrograms'], rows: 1 }),
    ...['DomainProfile', 'StandardProfile', 'PublicProfile'].map((p) => e(`reg.firewall.profiles.${p.toLowerCase()}`, 'recommended', `${L}${CCS}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\${p}`, `Firewall ${p}`, 'defense-evasion', 'high', ['T1562.004'], { values: ['EnableFirewall', 'DoNotAllowExceptions', 'DisableNotifications', 'DefaultInboundAction'], rows: 4 })),
    e('reg.firewall.policy', 'recommended', `${L}SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\%`, 'Firewall policy', 'defense-evasion', 'high', ['T1562.004'], { values: ['EnableFirewall', 'DefaultInboundAction'], rows: 6, anchorRows: 3 }),
    ...[['scriptblock', 'ScriptBlockLogging'], ['module', 'ModuleLogging'], ['transcription', 'Transcription']].map(([id, k]) => e(`reg.psh.${id}`, 'recommended', `${L}SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\${k}`, `PowerShell ${k} policy`, 'defense-evasion', 'medium', ['T1562.002', 'T1562.003'], { rows: 2 })),
    e('reg.amsi.hku', 'recommended', `${U}SOFTWARE\\Microsoft\\Windows Script\\Settings`, 'AMSI for Windows Script Host (per user)', 'defense-evasion', 'high', ['T1562.001'], { values: ['AmsiEnable'], noise: 'none' }),
    ...['EventLog-Security', 'EventLog-System', 'EventLog-Application', 'DefenderApiLogger', 'DefenderAuditLogger'].map((n) => e(`reg.eventlog.autologger.${n.toLowerCase()}`, 'recommended', `${L}${CCS}\\Control\\WMI\\Autologger\\${n}`, `Event log autologger: ${n}`, 'defense-evasion', 'high', ['T1562.002'], { values: ['Start', 'Enabled'], rows: 2 })),
    e('reg.defender.asr', 'recommended', `${L}SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules`, 'Defender ASR rules', 'defense-evasion', 'medium', ['T1562.001'], { rows: 16 }),
    e('reg.svc.objectname', 'recommended', `${L}${CCS}\\Services\\%`, 'Service accounts (ObjectName)', 'persistence', 'medium', ['T1543.003'], { values: ['ObjectName'], rows: 252, bytes: 40000, anchorRows: 0, verified: true, notes: 'Same key pattern as reg.svc.image: merged into one entry (values united).' }),

    // ------------------------------------------------------------------ §2.3 Comprehensive
    e('reg.com.hku', 'comprehensive', `${U}SOFTWARE\\Classes\\CLSID\\%\\InprocServer32`, 'Per-user COM InprocServer32 (hijack)', 'persistence', 'high', ['T1546.015'], { values: ['(Default)', 'ThreadingModel'], rows: 600, bytes: 120000, anchorRows: 600, notes: 'Must be measured (OneDrive / Teams register per-user COM). Never the HKLM CLSID tree.' }),
    e('reg.com.hku.localserver', 'comprehensive', `${U}SOFTWARE\\Classes\\CLSID\\%\\LocalServer32`, 'Per-user COM LocalServer32', 'persistence', 'high', ['T1546.015'], { values: ['(Default)'], rows: 50, anchorRows: 50 }),
    e('reg.svc.start.all', 'comprehensive', `${L}${CCS}\\Services\\%`, 'Service start/type (all services)', 'persistence', 'medium', ['T1543.003', 'T1562'], { values: ['Start', 'Type'], rows: 1342, bytes: 181000, anchorRows: 0, verified: true, noise: 'medium' }),
    e('reg.svc.security', 'comprehensive', `${L}${CCS}\\Services\\%\\Security`, 'Service security descriptors', 'defense-evasion', 'high', ['T1574.011', 'T1564'], { values: ['Security'], rows: 173, bytes: 100000, anchorRows: 173 }),
    e('reg.svc.failureactions', 'comprehensive', `${L}${CCS}\\Services\\%`, 'Service failure actions', 'persistence', 'low', ['T1543.003'], { values: ['FailureActions'], rows: 235, bytes: 58000, anchorRows: 0, verified: true }),
    e('reg.pendingrename', 'comprehensive', `${L}${CCS}\\Control\\Session Manager`, 'PendingFileRenameOperations', 'defense-evasion', 'low', ['T1112', 'T1070'], { values: ['PendingFileRenameOperations'], rows: 1, bytes: 4096, verified: true, noise: 'high', optIn: true, notes: 'Changes on every update: opt-in only, review with real-time actor attribution.' }),
    e('reg.bho', 'comprehensive', `${L}${CV}\\Explorer\\Browser Helper Objects\\%`, 'Browser helper objects', 'persistence', 'medium', ['T1176'], { rows: 5, anchorRows: 5 }),
    e('reg.bho.wow', 'comprehensive', `${L}${WOW}\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\%`, 'Browser helper objects (32-bit view)', 'persistence', 'medium', ['T1176'], { rows: 5, anchorRows: 5 }),
    e('reg.shellext.ssodl', 'comprehensive', `${L}${CV}\\Explorer\\ShellServiceObjectDelayLoad`, 'ShellServiceObjectDelayLoad', 'persistence', 'medium', ['T1546'], { rows: 10 }),
    e('reg.shellext.sts', 'comprehensive', `${L}${CV}\\Explorer\\SharedTaskScheduler`, 'SharedTaskScheduler', 'persistence', 'medium', ['T1546'], { rows: 10 }),
    e('reg.shellext.seh', 'comprehensive', `${L}${CV}\\Explorer\\ShellExecuteHooks`, 'ShellExecuteHooks', 'persistence', 'medium', ['T1546'], { rows: 10 }),
    ...[['getsigned', 'CryptSIPDllGetSignedDataMsg'], ['verify', 'CryptSIPDllVerifyIndirectData']].flatMap(([id, k]) => [
      e(`reg.sip.${id}`, 'comprehensive', `${L}SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\${k}\\%`, `SIP provider: ${k}`, 'defense-evasion', 'high', ['T1553.003'], { values: ['Dll', 'FuncName'], rows: 80, anchorRows: 40 }),
      e(`reg.sip.${id}.wow`, 'comprehensive', `${L}${WOW}\\Cryptography\\OID\\EncodingType 0\\${k}\\%`, `SIP provider: ${k} (32-bit view)`, 'defense-evasion', 'high', ['T1553.003'], { values: ['Dll', 'FuncName'], rows: 80, anchorRows: 40 }),
    ]),
    e('reg.trustproviders', 'comprehensive', `${L}SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\%`, 'Trust providers', 'defense-evasion', 'high', ['T1553.003'], { values: ['$DLL', '$Function'], rows: 40, anchorRows: 20 }),
    e('reg.credproviders', 'comprehensive', `${L}${CV}\\Authentication\\Credential Providers\\%`, 'Credential providers', 'credential', 'high', ['T1556'], { rows: 60, anchorRows: 30 }),
    e('reg.apppaths', 'comprehensive', `${L}${CV}\\App Paths\\%`, 'App Paths', 'hijack', 'medium', ['T1574'], { values: ['(Default)', 'Path'], rows: 250, anchorRows: 120, noise: 'medium' }),
    e('reg.accessibility.ats', 'comprehensive', `${L}${NT}\\Accessibility\\ATs\\%`, 'Accessibility tools', 'persistence', 'high', ['T1546.008'], { values: ['StartExe'], rows: 15, anchorRows: 15 }),
    e('reg.winlogon.gpext', 'comprehensive', `${L}${NT}\\Winlogon\\GPExtensions\\%`, 'Group Policy client extensions', 'persistence', 'medium', ['T1484.001'], { values: ['DllName'], rows: 40, anchorRows: 40 }),
    e('reg.gp.scripts', 'comprehensive', `${L}${CV}\\Group Policy\\Scripts\\%%`, 'Group Policy scripts', 'persistence', 'medium', ['T1037.003', 'T1037.004'], { rows: 20, anchorRows: 2, allowRecursive: true }),
    e('reg.winsock', 'comprehensive', `${L}${CCS}\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\%`, 'Winsock namespace providers', 'persistence', 'high', ['T1546'], { values: ['LibraryPath'], rows: 20, anchorRows: 10 }),
    e('reg.winsock64', 'comprehensive', `${L}${CCS}\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64\\%`, 'Winsock namespace providers (64-bit)', 'persistence', 'high', ['T1546'], { values: ['LibraryPath'], rows: 20, anchorRows: 10 }),
    e('reg.winsock.autodial', 'comprehensive', `${L}${CCS}\\Services\\WinSock2\\Parameters`, 'Winsock AutodialDLL', 'persistence', 'high', ['T1546'], { values: ['AutodialDLL'], rows: 1 }),
    e('reg.lsaext', 'comprehensive', `${L}${CCS}\\Control\\LsaExtensionConfig\\LsaSrv`, 'LSA extensions', 'credential', 'high', ['T1547.008'], { values: ['Extensions'], rows: 1 }),
    e('reg.wbem.autorecover', 'comprehensive', `${L}SOFTWARE\\Microsoft\\Wbem\\CIMOM`, 'WMI Autorecover MOFs', 'persistence', 'medium', ['T1546.003'], { values: ['Autorecover MOFs'], rows: 1, bytes: 4096 }),
    e('reg.office.addins', 'comprehensive', `${U}SOFTWARE\\Microsoft\\Office\\%\\%\\Addins\\%`, 'Office add-ins (per user)', 'persistence', 'medium', ['T1137.006'], { values: ['LoadBehavior', 'Manifest', 'FriendlyName'], rows: 60, anchorRows: 30, maxWildcards: 4, notes: 'Four wildcard levels (catalog-only exemption). Must be measured.' }),
    e('reg.dns.plugin', 'comprehensive', `${L}${CCS}\\Services\\DNS\\Parameters`, 'DNS server plugin DLL (domain controllers)', 'persistence', 'critical', ['T1574'], { values: ['ServerLevelPluginDll'], rows: 1 }),
    e('reg.winrm', 'comprehensive', `${L}SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service`, 'WinRM service policy', 'lateral-movement', 'medium', ['T1021.006'], { values: ['AllowBasic', 'AllowUnencryptedTraffic', 'AllowAutoConfig'], rows: 3 }),
    e('reg.systemrestore', 'comprehensive', `${L}SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore`, 'System Restore policy', 'impact', 'medium', ['T1490'], { values: ['DisableSR', 'DisableConfig'], rows: 2 }),
    e('reg.startupapproved', 'comprehensive', `${U}${CV}\\Explorer\\StartupApproved\\Run`, 'StartupApproved (per user)', 'defense-evasion', 'low', ['T1562.001'], { rows: 10, notes: 'Changes when a user toggles startup apps in Task Manager.' }),
    e('reg.bootverify', 'comprehensive', `${L}${CCS}\\Control\\BootVerificationProgram`, 'Boot verification program', 'persistence', 'high', ['T1547'], { values: ['ImagePath'] }),
    e('reg.firewall.rules', 'comprehensive', `${L}${CCS}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules`, 'Firewall rules (large, noisy)', 'defense-evasion', 'medium', ['T1562.004'], { rows: 900, bytes: 512000, optIn: true, noise: 'high', notes: 'Not recommended: Store apps change it constantly (300-500 KB). Opt-in only.' }),
  ];
  // §2.4 agent self-protection (Essential, protected): one exact-key entry per agent service.
  for (const svc of agentServices()) {
    out.push(e(`reg.self.${svc.toLowerCase()}`, 'essential', `${L}${CCS}\\Services\\${svc}`, `Agent self-protection: ${svc}`, 'defense-evasion', 'critical', ['T1562.001', 'T1543.003'], { values: ['ImagePath', 'Start', 'ObjectName', 'FailureActions'], rows: 4 }));
  }
  return out;
}

export const REG_CATALOG: readonly RegCatalogEntry[] = Object.freeze(buildCatalog());
const BY_ID = new Map(REG_CATALOG.map((c) => [c.id, c]));

export function getRegCatalogEntry(id: string): RegCatalogEntry | undefined {
  return BY_ID.get(id);
}

/** Catalog entries included by a tier (tiers nest; opt-in-only entries never). */
export function regTierEntries(tier: RegTier): RegCatalogEntry[] {
  return REG_CATALOG.filter((c) => !c.optInOnly && REG_TIER_RANK[c.tier] <= REG_TIER_RANK[tier]);
}

/** Estimated anchor bytes for one entry. */
export function anchorBytes(c: Pick<RegCatalogEntry, 'path' | 'anchorRows'>): number {
  return c.anchorRows * (c.path.length + 60);
}

/**
 * Catalog entries whose VALUES are commands / module names (autostart, hijack, privilege
 * escalation handlers, credential packages): visible by design - only their own redactValues are
 * hidden. Environment variables and configuration-like entries (RDP, WinRM, firewall, logging,
 * ...) hold arbitrary data and get the credential-name rules (spec v3). The list is enforced by a test.
 */
export const VISIBLE_BY_DESIGN_CATEGORIES = ['persistence', 'hijack', 'privilege-escalation', 'credential'];
export const NOT_VISIBLE_BY_DESIGN_IDS = ['reg.env.machine', 'reg.env.user'];
export function catalogVisibleByDesign(c: { id: string; category: string }): boolean {
  return VISIBLE_BY_DESIGN_CATEGORIES.includes(c.category) && !NOT_VISIBLE_BY_DESIGN_IDS.includes(c.id);
}
