/** Network/vulnerability scanning literal constants (no env). */

/**
 * Filesystem path scan output files are written to when VAJRA_SCAN_DIR is not
 * set. Relative to process.cwd(), joined with path.join by each caller.
 */
export const SCAN_OUTPUT_DIR_DEFAULT = 'storage/scans';

/** Max number of concurrent nmap/nuclei scans allowed before a launch request is rejected with 429. */
export const MAX_CONCURRENT_NETWORK_SCANS = 50;

/** Poll interval (ms) used to recheck a resumed-after-restart scan's process/output-file state until it finalizes. */
export const SCAN_RECOVERY_POLL_INTERVAL_MS = 10000;

/** Throttle (ms) between DB writes of in-progress nmap scan output/progress, to avoid hammering the DB on every stdout/stderr chunk. */
export const SCAN_PROGRESS_DB_FLUSH_INTERVAL_MS = 3000;

/** How long (ms) a cached scanner (Nessus/OpenVAS) client config is reused before being refetched/rebuilt. */
export const SCANNER_CONFIG_CACHE_TTL_MS = 60_000;

/** Valid `frequencyPreset` values for a recurring network scan schedule. */
export const SCAN_SCHEDULE_FREQUENCY_PRESETS = ['5min', '1h', '1d', 'custom'] as const;

/** Default `status` for a freshly-created network/nuclei scan history row, before it starts running. */
export const SCAN_STATUS_PENDING = 'PENDING';

/** Default GVM port_list_id used for OpenVAS target creation when the caller doesn't supply one. */
export const OPENVAS_DEFAULT_PORT_LIST_ID = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5';

/** Default GVM scanner_id used for OpenVAS task creation when the caller doesn't supply one. */
export const OPENVAS_DEFAULT_SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73';

/**
 * Static field defaults for GVM `create_target` requests, shared by createTarget
 * and quickScan. Per-request fields (name, hosts, comment, port_list_id,
 * ssh_credential_id, smb_credential_id) are layered on top by each caller.
 */
export const OPENVAS_DEFAULT_TARGET_PARAMS: Record<string, string> = {
  target_source: 'manual',
  'alive_tests:': 'Scan Config Default',
  exclude_hosts: '',
  allow_simultaneous_ips: '1',
  reverse_lookup_only: '0',
  reverse_lookup_unify: '0',
  hosts_ordering: '',
  port: '22',
  ssh_elevate_credential_id: '0',
  esxi_credential_id: '0',
  snmp_credential_id: '0',
  krb5_credential_id: '0',
};

/**
 * Static field defaults for GVM `create_task` requests, shared by createTask
 * and quickScan. Per-request fields (name, target_id, config_id, scanner_id,
 * comment) are layered on top by each caller.
 */
export const OPENVAS_DEFAULT_TASK_PARAMS: Record<string, string> = {
  scanner_type: '2',
  usage_type: 'scan',
  schedule_id: '0',
  in_assets: '1',
  apply_overrides: '1',
  min_qod: '70',
  alterable: '0',
  auto_delete: 'no',
  auto_delete_data: '5',
  hosts_ordering: '',
  max_checks: '4',
  max_hosts: '20',
  source_iface: '',
};
