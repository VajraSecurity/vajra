import { Request, Response } from 'express';
import { dbSourceConnection } from '../index';
import { promises as fs } from 'fs';
import path from 'path';

import ejs from 'ejs';

import { generateFrameworkReport, acquireReportBrowser, releaseReportBrowser } from './generateFrameworkReport';
import {
  generateFrameworkCharts,
  generateHistoryLine,
  generateOrgComparisonChart,
  generateSimpleDonut,
  generateMultiHistoryLine,
  generateSebiDomainChart,
  generateWeeklyAlertsBar,
  FRAMEWORK_COLORS,
  STATUS_COLOR_PASS,
  STATUS_COLOR_FAIL,
} from './generateCharts';
import { NODE_STATUS_ONLINE_THRESHOLD_SECONDS, COMPLIANCE_HISTORY_SNAPSHOT_LIMIT } from '../consts/database';
import { TEMPLATES_DIR, DEFAULT_LOCALE } from '../consts/server';
import { getLogger } from '../utils/logger';

const logger = getLogger('controllers.reports');

// Asset helpers

const ASSETS_ROOT = path.resolve(process.cwd(), '..', 'frontend');

let vajraLogoSvgCache: string | undefined;
let vajraLogoSvgLoaded = false;

async function getVajraLogoSvg(): Promise<string | undefined> {
  if (vajraLogoSvgLoaded) return vajraLogoSvgCache;
  try {
    vajraLogoSvgCache = await fs.readFile(path.join(ASSETS_ROOT, 'public', 'vajralogo.svg'), 'utf8');
  } catch (err) {
    logger.warn({ err }, 'Failed to load Vajra logo asset, report will render without it');
    vajraLogoSvgCache = undefined;
  }
  vajraLogoSvgLoaded = true;
  return vajraLogoSvgCache;
}

async function getDbOrError(res: Response) {
  const db = dbSourceConnection()?.[1];
  if (!db) {
    logger.warn({}, 'Report generation aborted: fleet database connection not available');
    res.status(500).json({ status: 'Error', message: 'Database connection not available' });
    return null;
  }
  return db;
}

// non_compliant_nodes_list is a free-form JSONB array whose element shape changed:
// current snapshots store { host_identifier, failed_checks }, while rows written before
// that carry the bare host-identifier string. Both shapes are live in the database, so
// both are read here.
function toHostIdentifier(entry: any): string | null {
  if (typeof entry === 'string') return entry || null;
  if (entry && typeof entry.host_identifier === 'string') return entry.host_identifier || null;
  return null;
}

// Snapshot provenance
//
// Every compliance figure in these reports is read out of the most recent stored
// snapshot; none of it is measured while the PDF is rendered. Printed under the
// generation date alone, a months-old sweep reads as a current measurement, so the
// snapshot's own timestamp and its age at render time are carried into both
// templates alongside the generation date.
//
// CONTROL_LOGIC_REVISED_AT marks the last change to how a control is evaluated: the
// three-state 'true' | 'false' | 'not_assessed' verdict and the endpoint EDR-presence
// rules landed together on 2026-09-03. A snapshot written before that was produced by
// the previous logic, which scored an unassessed control as a failure, so its figures
// are not comparable with a current sweep and the reports say so rather than printing
// them as today's posture. Update this whenever control evaluation changes again.
const CONTROL_LOGIC_REVISED_AT = Math.floor(Date.UTC(2026, 8, 3) / 1000);

// CMPL-DB-05: the non-compliant endpoint inventory in section D was unbounded - one row
// per non-compliant host, with no LIMIT and no time bound, all of it rendered into the PDF.
// It is capped here, and both the cap and the true total are carried into the template so a
// truncated list is printed as a truncated list rather than as a complete one. The endpoint
// list is ordered worst-score-first, so the cap keeps the rows an auditor needs.
//
// This does not address the other half of the same finding: the query reads no caller RBAC
// scope, so a scoped Group Admin's download still covers the whole fleet. That needs the
// node-scope helpers and belongs with whoever owns RBAC; it is reported, not fixed here.
const MAX_NON_COMPLIANT_REPORT_ROWS = 500;

function describeAge(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? '' : 's'}`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? '' : 's'}`;
}

// snapshot_at is stored in seconds. A row with no usable timestamp yields nulls
// rather than a fabricated age, and a timestamp ahead of the report clock is
// reported as unknown age rather than as brand new.
function snapshotProvenance(snapshotAt: any, now: Date) {
  const revisedOn = new Date(CONTROL_LOGIC_REVISED_AT * 1000).toLocaleDateString(DEFAULT_LOCALE);
  const ts = Number(snapshotAt);
  if (!Number.isFinite(ts) || ts <= 0) {
    return {
      snapshot_taken_on: null,
      snapshot_age_text: null,
      snapshot_age_days: null,
      snapshot_predates_control_logic: null,
      control_logic_revised_on: revisedOn,
    };
  }
  const ageSeconds = Math.floor(now.getTime() / 1000) - ts;
  return {
    snapshot_taken_on: new Date(ts * 1000).toLocaleString(DEFAULT_LOCALE),
    snapshot_age_text: ageSeconds < 0 ? null : describeAge(ageSeconds),
    snapshot_age_days: ageSeconds < 0 ? null : Math.floor(ageSeconds / 86400),
    snapshot_predates_control_logic: ts < CONTROL_LOGIC_REVISED_AT,
    control_logic_revised_on: revisedOn,
  };
}

// SEBI CSCRF guidelines (41 total, 5 hidden, 10 structurally unmeasurable, 26 active)

// 2026-09-07: '27' removed to stay in lockstep with the frontend register, which un-hid it
// the same day once control 27 ("User logins and session activities are tracked...") gained a
// real evaluator reading the Logon advanced-audit subcategory — the same probe its IRDAI twin
// (key 15, byte-identical label) already reads. Leaving it here made the PDF drop a control the
// UI renders, which is exactly the divergence the comment below warns against.
// '7'/'32' added 2026-09-07: out-of-framework (no CSCRF clause at all) — kept in lockstep with
// HIDDEN_GUIDELINES in frontend/.../constants/sebiHotGuidelines.ts, where the full rationale lives.
const SEBI_HIDDEN = new Set(['7', '14', '32', '37', '40']);

// SEBI_STRUCTURALLY_UNMEASURABLE — Class A controls, confirmed by the 2026-09-03 live-sweep
// verification pass (see the compliance-controls-removal task doctrine). Byte-duplicate twin
// of STRUCTURALLY_UNMEASURABLE_SEBI_KEYS in frontend/.../constants/sebiHotGuidelines.ts — keep
// the two in lockstep or the PDF and the UI register will disagree about which controls exist.
//
// Class A = STRUCTURALLY UNMEASURABLE. Every code path for this key in
//   utils/sebiComplianceChecks.ts resolves unconditionally to notAssessed() — there is no
//   branch, on any host, on any run, that can ever produce a measured pass or fail, because no
//   evidence source exists for it. This is distinct from Class B (a control with a real,
//   reachable pass/fail branch that merely had zero assessed hosts on one particular sweep,
//   e.g. SEBI 17 and 33, which were checked and confirmed Class B, not included here).
//
// SEBI_HIDDEN above is a separate, pre-existing "hidden/dead evaluator" bucket (14/27/37/40)
// and is not folded into this set: both sets are excluded from SEBI_GUIDELINES below, but they
// are different findings and are kept named separately for the same reason the frontend does.
const SEBI_STRUCTURALLY_UNMEASURABLE = new Set([
  '9', '13', '18', '19', '20', '21', '29', '31', '35', '41',
]);

const SEBI_ALL_GUIDELINES: Record<string, { label: string; tooltip: string }> = {
  // 2026-09-04: narrowed from a "prioritized for monitoring" DETECTION/RESPONSE claim to
  // the administrative-flagging capability that actually exists — see the matching
  // WHY-comment in frontend/.../constants/sebiHotGuidelines.ts control 1.
  '1':  { label: 'Critical assets and sensitive systems are explicitly identified in Vajra.', tooltip: 'ID.AM.S1, DE.CM.S4' },
  '2':  { label: 'A complete inventory of installed software, libraries, and versions is maintained for this system.', tooltip: 'ID.AM.S2, PR.IP.S16' },
  // 2026-09-04: narrowed to the fields this control actually reads (vendor/model/CPU/RAM/
  // core count) and dropped the storage/firmware/tamper-detection claims the evaluator
  // never measures — see sebiHotGuidelines.ts control 3.
  '3':  { label: 'A hardware asset inventory (vendor, model, CPU, RAM, core count) is maintained for this system.', tooltip: 'ID.AM.S1, ID.AM.S5' },
  '4':  { label: 'Audit-log generation is enabled for authentication, access, privilege-change, and system-modification events.', tooltip: 'RS.CO.S3, Vajra-authored mapping — not a SEBI clause' },
  '5':  { label: 'Configuration changes to systems and software are tracked and logged.', tooltip: 'PR.IP.S3, PR.IP.S4, PR.IP.S6' },
  '6':  { label: 'An EDR/anti-malware protection is installed and enabled on this system.', tooltip: 'PR.IP.S7, PR.IP.S8' },
  '7':  { label: 'Strong password rules (minimum length, complexity, etc.) are configured on this system.', tooltip: 'Vajra-authored mapping — not a SEBI clause' },
  '8':  { label: 'Only approved IP addresses and network ports are allowed through firewall policies.', tooltip: 'PR.IP.S3, PR.IP.S4' },
  '9':  { label: 'This system is configured to block known malicious IP addresses and domains.', tooltip: 'PR.IP.S5, PR.IP.S6' },
  // 2026-09-04: narrowed from a rogue/unauthorized-device DETECTION claim to the
  // USB-connection-event logging that's actually measured — see sebiHotGuidelines.ts
  // control 10 (network-wide rogue-device detection is out of scope, disclosed there).
  '10': { label: 'USB and other removable-device connection events on this system are logged for administrator review.', tooltip: 'ID.AM.S5, Vajra-authored mapping — not a SEBI clause' },
  '11': { label: 'An EDR (Endpoint Detection & Response) solution is installed and actively running.', tooltip: 'PR.IP.S7, PR.IP.S8' },
  '12': { label: 'Access to USB drives and removable media is restricted.', tooltip: 'PR.DS.S1, PR.DS.S2, PR.IP.S14' },
  '13': { label: 'Unnecessary services, ports, protocols, and software are disabled on endpoints.', tooltip: 'PR.IP.S9, PR.IP.S10' },
  '14': { label: 'Remote access is restricted to approved devices through MAC-based controls.', tooltip: 'Vajra-authored mapping — not a SEBI clause' },
  '15': { label: 'Operating system quality and security patches are applied within Vajra\'s default recency window.', tooltip: 'PR.MA.S1, PR.MA.S2, PR.MA.S3' },
  '16': { label: 'Automated alerts are generated by Vajra\'s detection pipeline for this system.', tooltip: 'DE.CM.S2, DE.CM.S3' },
  '17': { label: 'Critical systems are continuously monitored in real time for threats and incidents.', tooltip: 'DE.CM.S4, DE.CM.S5' },
  '18': { label: 'CPU, memory, disk, and bandwidth utilization are monitored with threshold alerts.', tooltip: 'PR.IP.S11, PR.IP.S12' },
  '19': { label: 'Cybersecurity incidents are reported to CERT-In within mandated timelines.', tooltip: 'RS.CO.S1, RS.CO.S2' },
  '20': { label: 'Authentication, application, system, and network logs are collected centrally for investigation.', tooltip: 'Vajra-authored mapping — not a SEBI clause' },
  '21': { label: 'Every cybersecurity incident is documented with timeline, impact, root cause, and remediation.', tooltip: 'RS.CO.S3, Vajra-authored mapping — not a SEBI clause' },
  // 2026-09-04: narrowed from an unauthorized-change MONITORING claim to the inventory
  // capability that's actually measured (no diff/baseline logic exists) — see
  // sebiHotGuidelines.ts control 22.
  '22': { label: 'Storage devices attached to this system are inventoried and reported.', tooltip: 'ID.AM.S6, PR.DS.S1, PR.DS.S2' },
  // 2026-09-04: narrowed from a rogue-AP/unauthorized-device DETECTION claim to a
  // telemetry-capability claim — see the matching WHY-comment in
  // frontend/src/features/Nodes/NodesView/constants/sebiHotGuidelines.ts control 23.
  '23': { label: 'Wi-Fi connection and saved-profile status on this system is collected and reported.', tooltip: 'ID.AM.S2, ID.AM.S4, PR.IP.S1' },
  '24': { label: 'Changes to OS, applications, and network settings are tracked and logged.', tooltip: 'PR.IP.S3, PR.IP.S4, PR.IP.S6' },
  '25': { label: 'The update and patch history of installed software is visible in Vajra.', tooltip: 'PR.IP.S16, PR.MA.S3' },
  '26': { label: 'Endpoint encryption is enabled and verified for data at rest.', tooltip: 'PR.DS.S1, PR.DS.S2' },
  '27': { label: 'User logins and session activities are tracked to detect suspicious behavior.', tooltip: 'PR.AA.S8, PR.AA.S9' },
  '28': { label: 'An inventory of installed antivirus, EDR, and firewall software is maintained for this system, showing their operational status.', tooltip: 'PR.IP.S8, PR.IP.S7' },
  '29': { label: 'All local user accounts on this system are listed, including their privilege levels and last login times.', tooltip: 'Vajra-authored mapping — not a SEBI clause' },
  // 2026-09-04: dropped "reviewed for unauthorized services" — the evaluator's own
  // comment states no authorized/unauthorized port classification is performed. See
  // sebiHotGuidelines.ts control 30.
  '30': { label: 'Active network connections and listening ports on this system are regularly collected.', tooltip: 'DE.CM.S1, PR.IP.S9' },
  '31': { label: 'A real-time inventory of all running processes and services on this system is maintained to help spot suspicious activity.', tooltip: 'DE.CM.S1, PR.IP.S10' },
  '32': { label: 'System uptime and last reboot time are tracked for this system to spot unexpected reboots or prolonged uptimes.', tooltip: 'Vajra-authored mapping — not a SEBI clause' },
  '33': { label: 'The status of the local firewall and its key rules is collected from this system for compliance checks.', tooltip: 'PR.IP.S3, PR.IP.S4' },
  '34': { label: 'Disk encryption status for system and data volumes is reported for this system, showing if built-in OS encryption is enabled.', tooltip: 'PR.DS.S1, PR.DS.S2' },
  '35': { label: 'Time synchronization status is monitored for this system, including NTP configuration and last sync time.', tooltip: 'PR.IP.S13, Vajra-authored mapping — not a SEBI clause' },
  '36': { label: 'Software installations on this system are tracked and reported.', tooltip: 'PR.IP.S16, Vajra-authored mapping — not a SEBI clause' },
  '37': { label: 'The status of endpoint backup solutions (if any) is reported for this system.', tooltip: 'PR.DS.S3, PR.DS.S4' },
  '38': { label: 'The status of Bluetooth and other wireless interfaces on this system is collected and reported.', tooltip: 'PR.IP.S1, ID.AM.S4' },
  '39': { label: 'All installed browser extensions and plugins on this system are inventoried and reported.', tooltip: 'PR.IP.S16, Vajra-authored mapping — not a SEBI clause' },
  '40': { label: 'The status of local DNS settings and any custom DNS servers on this system is collected and reported.', tooltip: 'PR.IP.S6, Vajra-authored mapping — not a SEBI clause' },
  '41': { label: 'All scheduled software updates and patch jobs on this system are tracked and reported for compliance.', tooltip: 'PR.MA.S2, PR.IP.S16' },
};

const SEBI_GUIDELINES = Object.fromEntries(
  Object.entries(SEBI_ALL_GUIDELINES).filter(
    ([key]) => !SEBI_HIDDEN.has(key) && !SEBI_STRUCTURALLY_UNMEASURABLE.has(key),
  ),
);

// IRDAI guidelines (31 total, 4 hidden, 9 structurally unmeasurable, 18 active)
//
// Standard Reference strings are the Annexure III Area plus Control No (1-347) of the
// catalogue that ships with the product at frontend/public/IRDAI.json; every number below
// was read back out of that file and matched to its Area before being written here.
// Annexure III has no sub-clause codes, so no identifier of any other shape is used.
//
// This map previously carried 'Vajra-authored mapping - not an IRDAI clause' on all 30
// rows, which the PDF register printed against controls that do cite a real clause - and
// which the UI register (NodesViewIRDAIHotCompliance) contradicted for 16 of them. Denying
// that a clause exists is as much a misstatement as inventing one, so the label is kept
// only where the whole catalogue was searched and nothing covers the control: 4
// (endpoint configuration-change logging) and 29 (protecting audit logs from modification
// or deletion). Four further controls cite the closest clauses Annexure III does contain
// and say so in the reference itself rather than implying an exact match.

// '4'/'10' added 2026-09-07: out-of-framework (no Annexure III clause at all) — kept in lockstep
// with HIDDEN_GUIDELINES in frontend/.../NodesViewIRDAIHotCompliance.tsx.
const IRDAI_HIDDEN = new Set(['4', '10', '25', '30']);

// IRDAI_STRUCTURALLY_UNMEASURABLE — Class A controls, confirmed by the 2026-09-03 live-sweep
// verification pass (see the compliance-controls-removal task doctrine). No equivalent named
// export exists yet in NodesViewIRDAIHotCompliance.tsx (the frontend register's own Class A
// set was not present there as of this pass); this list is taken directly from that
// verification pass's confirmed findings, including the correction that added IRDAI/29 (a
// real, visible, unconditionally-notAssessed control the original scoping list omitted) and
// excluded IRDAI/14 and IRDAI/26 (both Class B — they have real reachable pass/fail branches
// and were simply data-empty on the one sweep reviewed).
//
// IRDAI_HIDDEN above is a separate, pre-existing "hidden/dead evaluator" bucket (25/30) and is
// not folded into this set for the same reason SEBI keeps its two buckets apart.
//
// 2026-09-04: key 7 reclassified out of this set to Class B — see the matching WHY-comment on
// the frontend's STRUCTURALLY_UNMEASURABLE_IRDAI_KEYS in NodesViewIRDAIHotCompliance.tsx. Its
// evaluator now ports SEBI control 8's wildcard-scope logic over the same
// windows_firewall_rules data instead of unconditionally returning not-assessed.
const IRDAI_STRUCTURALLY_UNMEASURABLE = new Set([
  '8', '11', '16', '19', '22', '23', '27', '28', '29',
]);

const IRDAI_ALL_GUIDELINES: Record<string, { label: string; tooltip: string }> = {
  '1':  { label: 'A complete inventory of installed software, libraries, and versions is maintained for this system.', tooltip: 'Annexure III: ID.AM 106, ID.AM 107, PR.IP 194' },
  '2':  { label: 'A hardware asset inventory (vendor, model, CPU, RAM, core count) is maintained for this system.', tooltip: 'Annexure III: ID.AM 106' },
  '3':  { label: 'Audit-log generation is enabled for authentication, access, privilege-change, and system-modification events.', tooltip: 'Annexure III: PR.AC 145, DE.CM 2, DE.CM 35' },
  '4':  { label: 'Configuration changes to systems and software are tracked and logged.', tooltip: 'Vajra-authored mapping — not an IRDAI clause' },
  '5':  { label: 'An EDR/anti-malware protection is installed and enabled on this system.', tooltip: 'Annexure III: PR.PT 214' },
  '6':  { label: 'Strong password rules (minimum length, complexity, etc.) are configured on this system.', tooltip: 'Annexure III: PR.AC 149, PR.DS 173' },
  '7':  { label: 'Only approved IP addresses and network ports are allowed through firewall policies.', tooltip: 'Annexure III: DE.CM 7, DE.CM 23' },
  '8':  { label: 'This system is configured to block known malicious IP addresses and domains.', tooltip: 'Annexure III: DE.CM 23, DE.CM 76' },
  '9':  { label: 'An EDR (Endpoint Detection & Response) solution is installed and actively running.', tooltip: 'Annexure III: PR.PT 214' },
  // Tooltip synced to match the frontend register (NodesViewIRDAIHotCompliance.tsx): the two
  // previously disagreed on whether any Annexure III clause backs this control at all.
  '10': { label: 'Access to USB drives and removable media is restricted.', tooltip: 'Vajra-authored mapping — not an IRDAI clause' },
  '11': { label: 'Unnecessary services, ports, protocols, and software are disabled on endpoints.', tooltip: 'Annexure III: PR.DS 170' },
  '12': { label: 'Operating system patches are applied within a 30-day recency window.', tooltip: 'Annexure III: PR.MA 205, PR.MA 210' },
  '13': { label: 'Automated alerts are generated by Vajra\'s detection pipeline for this system.', tooltip: 'Annexure III: DE.CM 5' },
  '14': { label: 'Critical systems are continuously monitored in real time for threats and incidents.', tooltip: 'Annexure III: ID.AM 105, DE.CM 84, DE.CM 2' },
  '15': { label: 'User logins and session activities are tracked to detect suspicious behavior.', tooltip: 'Annexure III: DE.CM 5, DE.CM 54' },
  // Tooltip synced to match the frontend register.
  '16': { label: 'The list of local user accounts and their privilege levels is regularly reviewed.', tooltip: 'Annexure III: PR.AC 151' },
  '17': { label: 'Default credentials for all system accounts are changed and strong passwords enforced.', tooltip: 'Annexure III: PR.AC 149' },
  '18': { label: 'The update and patch history of installed software is visible in Vajra.', tooltip: 'Annexure III: PR.MA 210' },
  '19': { label: 'All local firewall rules and status are collected and reviewed for unauthorized changes.', tooltip: 'Annexure III: DE.CM 7' },
  '20': { label: 'Endpoint antivirus/EDR client is installed and reporting healthy status.', tooltip: 'Annexure III: PR.PT 214' },
  '21': { label: 'Removable media (USB, external drives) usage logs are collected and reviewed.', tooltip: 'Annexure III: PR.DS 177, DE.CM 2 (nearest applicable clauses)' },
  '22': { label: 'All running processes and services are inventoried and checked for unauthorized software.', tooltip: 'Annexure III: DE.CM 9, PR.PT 217' },
  '23': { label: 'The system time is synchronized with a trusted NTP source.', tooltip: 'Annexure III: DE.CM 99' },
  '24': { label: 'Failed login attempts and account lockouts are logged and alerted.', tooltip: 'Annexure III: PR.AC 157, DE.CM 54' },
  '25': { label: 'All scheduled tasks and startup programs are reviewed for unauthorized entries.', tooltip: 'Annexure III: PR.IP 193, PR.IP 197 (nearest applicable clauses)' },
  '26': { label: 'The BIOS/firmware version and configuration are checked for compliance.', tooltip: 'Annexure III: PR.PT 216 (nearest applicable clause)' },
  // Tooltip synced to match the frontend register.
  '27': { label: 'All installed applications are checked against an authorized software list.', tooltip: 'Annexure III: ID.AM 107, PR.IP 193' },
  '28': { label: 'The system is isolated from the network when a major threat is detected.', tooltip: 'Annexure III: ID.AM 111, RS.MI 238 (nearest applicable clauses)' },
  '29': { label: 'Audit logs are protected from unauthorized modification or deletion.', tooltip: 'Vajra-authored mapping — not an IRDAI clause' },
  '30': { label: 'A process exists to restore system state from backup in case of incident.', tooltip: 'Annexure III: RS.RP 241, RS.RP 243, RS.RP 244' },
  // 2026-09-07: key 31 added to mirror the frontend register (NodesViewIRDAIHotCompliance.tsx),
  // which gained a data-at-rest encryption control on the same date. Until then the IRDAI
  // register carried no encryption control at all while SEBI measured the same hosts' BitLocker
  // state on controls 26 and 34. Mirrored here so the PDF report does not drop the control and
  // under-report the IRDAI 'Controls Evaluated' count, the way key 4.2 was dropped from the
  // CERT-In map below. Snapshots taken before that date carry no pass rate for this key.
  '31': { label: 'Endpoint storage volumes are encrypted at rest with protection active.', tooltip: 'Annexure III: PR.DS 170, PR.DS 177' },
};

const IRDAI_GUIDELINES = Object.fromEntries(
  Object.entries(IRDAI_ALL_GUIDELINES).filter(
    ([key]) => !IRDAI_HIDDEN.has(key) && !IRDAI_STRUCTURALLY_UNMEASURABLE.has(key),
  ),
);

// CERT-In guidelines (13 controls total, 3 structurally unmeasurable, 10 active - of which 3
// active controls are answered by operator attestation rather than an automated check).
// Keyed by the checklist marker the compliance snapshot stores, so control_pass_rates
// rows resolve to a guideline.
//
// 3.4, 4.2 and 5.10 have no automated check in the CERT-In register
// (frontend constants/certinPendingPoints.ts documents why for each), so the snapshot
// carries an administrator's Yes/No answer applied to every endpoint in scope rather
// than a measured per-host result. 4.2 was missing from this map entirely, which
// dropped it from the report and from the 'Controls Evaluated' count without saying so;
// it is listed here and flagged, like its two peers, as operator-attested.
const CERTIN_GUIDELINES: Record<string, { label: string; tooltip: string; attested?: boolean }> = {
  '1.4':  { label: 'Whether inventory of authorized hardware and software is maintained.', tooltip: 'CERT-In 1.4' },
  '1.10': { label: 'Whether host firewall is configured in all systems to restrict lateral movement within the same network segment.', tooltip: 'CERT-In 1.10' },
  '1.12': { label: 'Is Network firewall configured and network access configured as per requirements of official work.', tooltip: 'CERT-In 1.12' },
  '2.6':  { label: 'Whether there are tools in the WLAN platform to identify rogue Access Points or those spoofing corporate SSIDs.', tooltip: 'CERT-In 2.6' },
  '3.3':  { label: 'Whether OS update is set to auto-update from a trusted source.', tooltip: 'CERT-In 3.3' },
  '3.4':  { label: 'Whether Government enterprise Antivirus/EDR client is installed on official desktops/laptops and configured for auto-update.', tooltip: 'CERT-In 3.4', attested: true },
  '3.7':  { label: 'Whether security of password is enforced as per the guidelines.', tooltip: 'CERT-In 3.7' },
  '3.8':  { label: 'Whether it is ensured to allow only authorized USB storage devices and external storage devices.', tooltip: 'CERT-In 3.8' },
  '4.1':  { label: 'Whether logging is enabled on all ICT systems as per the guidelines.', tooltip: 'CERT-In 4.1' },
  '4.2':  { label: 'Whether logs of all ICT systems are retained for a rolling period of 180 days.', tooltip: 'CERT-In 4.2', attested: true },
  '5.8':  { label: 'Whether unwanted or unused OS components, services, ports, applications are uninstalled or disabled.', tooltip: 'CERT-In 5.8' },
  '5.10': { label: 'Whether enterprise level Antivirus/EDR client recommended by CERT-In and NIC-CERT is installed on all servers.', tooltip: 'CERT-In 5.10', attested: true },
  '5.11': { label: 'Whether provision is made to update Antivirus client and server with the latest patches/updates.', tooltip: 'CERT-In 5.11' },
};

// CERTIN_STRUCTURALLY_UNMEASURABLE — Class A controls, confirmed by the 2026-09-03 live-sweep
// verification pass (see the compliance-controls-removal task doctrine). Byte-duplicate twin
// of STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS in
// frontend/.../constants/certinPendingPoints.ts — keep the two in lockstep.
//
// Class A = STRUCTURALLY UNMEASURABLE. Every code path for this key in
//   utils/certinComplianceChecks.ts resolves unconditionally to notAssessed() — there is no
//   branch, on any host, on any run, that can produce a measured pass or fail, because no
//   evidence source exists for it. This is distinct from the 3.4/4.2/5.10 operator-attested
//   controls above (which have no automated check by design and are answered manually - a
//   valid, disclosed figure, not a removal candidate) and from CERT-In 3.3 (Class B: it has a
//   real, reachable, fleet-history-evidenced fail branch and was simply data-empty on the one
//   sweep reviewed - excluded from this set).
const CERTIN_STRUCTURALLY_UNMEASURABLE = new Set(['1.12', '2.6', '5.8']);

const CERTIN_ACTIVE_GUIDELINES = Object.fromEntries(
  Object.entries(CERTIN_GUIDELINES).filter(([key]) => !CERTIN_STRUCTURALLY_UNMEASURABLE.has(key)),
);

// Common framework PDF generator

async function generateFrameworkPdf(
  req: Request,
  res: Response,
  tableName: string,
  guidelines: Record<string, { label: string; tooltip: string; attested?: boolean }>,
  frameworkName: string,
  frameworkSubtitle: string,
  frameworkColor: string,
  filename: string,
  extraChartsGen?: (snapshot: any, controls: any[]) => Promise<Record<string, string | undefined>>,
) {
  const db = await getDbOrError(res);
  if (!db) return;

  const [rows, histRows] = await Promise.all([
    db.query(`
      SELECT id, snapshot_at, total_nodes, windows_hosts, windows_with_results,
             avg_compliance_percent, fully_compliant_nodes,
             strong_count, moderate_count, needs_attention_count, control_pass_rates, source,
             fully_compliant_nodes_list, non_compliant_nodes_list
      FROM ${tableName}
      ORDER BY id DESC LIMIT 1
    `),
    db.query(`
      SELECT snapshot_at, avg_compliance_percent, windows_with_results
      FROM ${tableName}
      ORDER BY id DESC LIMIT ${COMPLIANCE_HISTORY_SNAPSHOT_LIMIT}
    `),
  ]).catch((err) => {
    logger.error({ err, tableName, stage: 'fetch_snapshot' }, 'Framework compliance report generation failed while querying compliance snapshot');
    throw err;
  });

  const snapshot = rows?.[0];
  if (!snapshot) {
    logger.info({ tableName, filename }, 'Framework compliance report generation aborted: no compliance snapshot found');
    return res.status(404).json({ status: 'Error', message: 'No compliance snapshot found' });
  }

  // Resolve non-compliant node rows from stored snapshot data if available,
  // otherwise fall back to re-deriving from the compliance_results table.
  //
  // A failure in either query used to be swallowed into an empty array, which the report
  // then printed as "0 endpoints not fully compliant" - a clean fleet, indistinguishable
  // from a real one, on the live path for CERT-In. Both catches now raise a flag instead:
  // the count is reported as unavailable and section D prints an explicit banner in place
  // of the table, rather than an absence of evidence being rendered as evidence of absence.
  let nodeRows: any[];
  let node_inventory_unavailable = false;
  // Which of the two situations the banner in section D should describe: a query that
  // failed, or a snapshot that stored an empty endpoint list its own headline figures
  // contradict. Both leave the inventory unusable; they are not the same finding.
  let node_inventory_unavailable_reason: 'query_failed' | 'snapshot_list_empty_unreconciled' | null = null;
  let node_metadata_unavailable  = false;
  // Whether section D's rows are the ones the snapshot itself recorded, or were rebuilt
  // from the per-host results table afterwards. A rebuilt row is a different measurement,
  // taken at a different time, and section D says so rather than presenting it as part of
  // the snapshot.
  let node_rows_source: 'snapshot' | 'derived' | null = null;
  // The number of non-compliant endpoints found, which is NOT nodeRows.length once the
  // list is capped for rendering (see MAX_NON_COMPLIANT_REPORT_ROWS). Stays null while the
  // inventory could not be built at all.
  let non_compliant_total: number | null = null;

  const storedNonCompliant: any[] | null = Array.isArray(snapshot.non_compliant_nodes_list)
    ? snapshot.non_compliant_nodes_list
    : null;

  // Read here as well as in section B below, because whether an empty stored list is
  // credible depends on them: a sweep that found no non-compliant endpoint must also have
  // found every endpoint it assessed fully compliant.
  const snapshotAssessedHosts: number | null = Number.isFinite(Number(snapshot.windows_with_results))
    ? Number(snapshot.windows_with_results)
    : null;
  const snapshotCompliantHosts: number | null =
    snapshot.fully_compliant_nodes != null && Number.isFinite(Number(snapshot.fully_compliant_nodes))
      ? Number(snapshot.fully_compliant_nodes)
      : null;

  if (storedNonCompliant && storedNonCompliant.length > 0) {
    node_rows_source = 'snapshot';
    const totalControls = Object.keys(guidelines).length;
    non_compliant_total = storedNonCompliant.length;
    // Scores come entirely from the stored entry, so the list is scored, ordered and
    // capped before any database lookup: node metadata is then fetched only for the rows
    // this report actually prints.
    const scoredStored = storedNonCompliant
      .map((item: any) => {
        const hostIdentifier = toHostIdentifier(item);
        // Legacy snapshots stored this list as bare host-identifier strings, with no record of
        // which controls the host failed. A missing failed_checks array is therefore an absence
        // of evidence, not a count of zero: deriving a score from it produced a 100 % row in a
        // table of non-compliant endpoints. Such rows are listed with no score at all.
        const hasFailedChecks = Array.isArray(item?.failed_checks);
        const failedCount  = hasFailedChecks ? item.failed_checks.length : null;
        // The richer entry may also record which controls went unassessed on that host,
        // either as a list or as a count. Where it does, those controls leave both the
        // numerator and the denominator, exactly as they do in the re-derived branch
        // below. Where it does not, the count is unknown - not zero - and the score is
        // an upper bound, because every control the host was not measured on is sitting
        // in the numerator. It is printed as such rather than as a plain percentage.
        const notAssessedCount = !hasFailedChecks
          ? null
          : Array.isArray(item?.not_assessed_checks)
            ? item.not_assessed_checks.length
            : (item?.not_assessed_count != null && Number.isFinite(Number(item.not_assessed_count)))
              ? Math.max(0, Number(item.not_assessed_count))
              : null;
        const assessedCount = failedCount != null
          ? Math.max(0, totalControls - (notAssessedCount ?? 0))
          : null;
        const passedCount  = assessedCount != null ? Math.max(0, assessedCount - failedCount!) : null;
        return {
          host_identifier: hostIdentifier,
          passed_count:  passedCount,
          total_count:   assessedCount,
          // Null where the stored entry records only which controls the host failed:
          // that is an unknown count, not a count of none.
          not_assessed_count: notAssessedCount,
          score_recorded: failedCount != null,
          // An entry recording that every control went unassessed on the host leaves no
          // denominator, so no score is printed for it rather than a 0 % or a 100 %.
          score_is_upper_bound: failedCount != null && notAssessedCount == null,
          compliance_pct: passedCount != null && assessedCount != null && assessedCount > 0
            ? Math.round((passedCount / assessedCount) * 100)
            : null,
          failed_checks: hasFailedChecks ? item.failed_checks : [],
        };
      })
      .sort((a: any, b: any) => (a.compliance_pct ?? 101) - (b.compliance_pct ?? 101))
      .slice(0, MAX_NON_COMPLIANT_REPORT_ROWS);

    const hostIds = scoredStored.map((r: any) => r.host_identifier).filter(Boolean) as string[];
    const metaRows = await db.query(
      `SELECT host_identifier, hostname, address, os_name, os_platform, last_seen
       FROM nodes WHERE host_identifier = ANY($1)`,
      [hostIds],
    ).catch((err) => {
      // Not "continuing without it": without this lookup every printed row loses its
      // hostname, address, OS and last-seen time. The report says so rather than showing
      // a table of blanks that reads like missing endpoints.
      node_metadata_unavailable = true;
      logger.warn({ err, tableName }, 'Failed to fetch node metadata for non-compliant hosts; report will state that endpoint metadata is unavailable');
      return [] as any[];
    });
    const metaMap = new Map<string, any>(metaRows.map((n: any) => [n.host_identifier, n]));
    nodeRows = scoredStored.map((row: any) => {
      const meta = row.host_identifier ? (metaMap.get(row.host_identifier) ?? {}) : {};
      return {
        ...row,
        hostname:    meta.hostname    ?? null,
        address:     meta.address     ?? null,
        os_name:     meta.os_name     ?? null,
        os_platform: meta.os_platform ?? null,
        last_seen:   meta.last_seen   ?? null,
      };
    });
  } else if (storedNonCompliant) {
    // The snapshot stored the list and it is empty. That is a claim - "no endpoint was
    // less than fully compliant" - and it is only credible when the same snapshot also
    // records every assessed endpoint as fully compliant. Where it does not (the live
    // CERT-In snapshot records 6 fully compliant out of 8 assessed alongside an empty
    // list), the list is missing evidence, not evidence of a clean fleet.
    //
    // The previous code fell through to the re-derivation below in that case, which rebuilt
    // section D out of the per-framework results table - rows measured up to two months
    // before the snapshot, for a subset of the fleet - and printed them under the
    // snapshot's own headline. An unreconciled empty list is reported as an evidence gap
    // instead: no endpoint list is shown, and no endpoint is stated to be compliant or
    // non-compliant on the strength of it.
    const listReconciles = snapshotCompliantHosts != null
      && snapshotAssessedHosts != null
      && snapshotCompliantHosts >= snapshotAssessedHosts;
    if (listReconciles) {
      node_rows_source = 'snapshot';
      non_compliant_total = 0;
      nodeRows = [];
    } else {
      node_inventory_unavailable = true;
      node_inventory_unavailable_reason = 'snapshot_list_empty_unreconciled';
      nodeRows = [];
      logger.warn(
        { tableName, snapshotAssessedHosts, snapshotCompliantHosts },
        'Compliance snapshot stores an empty non-compliant endpoint list that its own fully-compliant count contradicts; report will state that the endpoint inventory is unavailable rather than deriving one from older per-host rows',
      );
    }
  } else {
    node_rows_source = 'derived';
    const resultsTable = tableName.replace('_historical_compliance', '_compliance_results');
    // Restrict every count below to the framework's active guideline keys, mirroring the
    // `guidelines[r.key] !== undefined` filter applied to control_pass_rates a few lines
    // below for this same snapshot. Without it, Class-A (structurally-unmeasurable) keys
    // and any hidden-evaluator keys sitting in compliance_data - which this report excludes
    // everywhere else - would count toward passed_count/assessed_count/non_compliant_total
    // here, inflating a host's derived score with controls the fleet was never scored on.
    const activeGuidelineKeys = Object.keys(guidelines);
    nodeRows = await db.query(`
      WITH latest AS (
        -- CMPL-DB-01: this was SELECT DISTINCT ON (host_identifier) ... ORDER BY
        -- host_identifier, id DESC over the whole per-framework compliance_results table.
        -- That table is never purged, so every historical row in it was sequentially
        -- scanned and sorted on every report download. Driving the lookup off the node
        -- list with a LATERAL takes each host's newest row straight off the index that already
        -- exists for it - idx_cr_host_unixtime and its sebi_/irdai_/certin_ twins, all
        -- (host_identifier, unixtime DESC) - with no schema change.
        --
        -- Caveat: the ordering key changes from id DESC to (unixtime DESC, id DESC).
        -- unixtime is stamped server-side at insert (node_certin_compliance.ts,
        -- org_compliance_snapshot.ts), so it advances with id; the two orders can differ
        -- only when one host has two snapshots inside the same second, and the trailing
        -- id DESC tiebreak then selects exactly the row the old ordering selected.
        --
        -- DISTINCT on the driver keeps the row count identical to the previous form even
        -- if the externally-managed nodes table ever holds a duplicate host_identifier.
        --
        -- CMPL-DB-06: compliance scope is deliberately Windows-only (see the client-side
        -- os_platform/os_name filters in Compliance/index.tsx and the *HotCompliance.tsx
        -- views) but this CTE previously had no OS predicate at all, so a non-Windows host
        -- with a stray row in this framework's compliance_results table - or simply present
        -- in nodes with no row, scoring assessed_count = 0 - was driven through
        -- latest/scored and could land in the non-compliant list and non_compliant_total
        -- below. The predicate mirrors the one already applied to the sibling fleet-wide
        -- query later in this file (the windows_nodes COUNT(*) FILTER) so a host counts
        -- as Windows here exactly when it counts as Windows there.
        SELECT n.host_identifier, l.unixtime, l.compliance_data
        FROM (
          SELECT DISTINCT host_identifier FROM nodes
          WHERE LOWER(COALESCE(os_platform,'')) LIKE '%windows%' OR LOWER(COALESCE(os_name,'')) LIKE '%windows%'
        ) n
        CROSS JOIN LATERAL (
          SELECT r.unixtime, r.compliance_data
          FROM ${resultsTable} r
          WHERE r.host_identifier = n.host_identifier
          ORDER BY r.unixtime DESC, r.id DESC
          LIMIT 1
        ) l
      ),
      -- MATERIALIZED (CMPL-DB-02): inlined, Postgres re-expands each of these
      -- jsonb_array_elements subqueries once per referencing expression - the select
      -- list, the WHERE filter and the ORDER BY - running eleven SubPlans per host rather
      -- than four. The rows produced are byte-identical either way; only how many times
      -- the identical subqueries run changes.
      scored AS MATERIALIZED (
        SELECT
          host_identifier,
          unixtime,
          -- Every count in this CTE is further gated to item->>'command_key' = ANY($1) -
          -- the framework's currently-active guideline keys - so a host's derived score
          -- reflects only the controls this report shows anywhere else in it.
          (SELECT COUNT(*)::int FROM jsonb_array_elements(compliance_data::jsonb) AS item WHERE item->>'output' = 'true' AND item->>'command_key' = ANY($1::text[])) AS passed_count,
          -- A control the agent could not assess is neither a pass nor a fail, so it must leave the
          -- denominator entirely: scoring it as a failure fabricates non-compliance the evidence does
          -- not support. Legacy rows written before the three-state verdict landed carry only
          -- 'true'/'false', so assessed_count equals total_count for them and their score is unchanged.
          (SELECT COUNT(*)::int FROM jsonb_array_elements(compliance_data::jsonb) AS item WHERE item->>'output' IN ('true', 'false') AND item->>'command_key' = ANY($1::text[])) AS assessed_count,
          (SELECT COUNT(*)::int FROM jsonb_array_elements(compliance_data::jsonb) AS item WHERE item->>'output' = 'not_assessed' AND item->>'command_key' = ANY($1::text[])) AS not_assessed_count,
          (SELECT COUNT(*)::int FROM jsonb_array_elements(compliance_data::jsonb) AS item WHERE item->>'command_key' = ANY($1::text[])) AS total_count
        FROM latest
      )
      SELECT
        n.hostname,
        n.address,
        n.os_name,
        n.os_platform,
        n.last_seen,
        n.enrolled_on,
        n.critical,
        s.unixtime AS assessed_at,
        s.passed_count,
        s.assessed_count,
        s.not_assessed_count,
        s.total_count,
        -- CMPL-DB-05: the returned list is capped below, so the true size of the result
        -- set is carried out beside it and the report states "showing N of M" instead of
        -- presenting a truncated list as a complete one. A window function is evaluated
        -- after WHERE and before ORDER BY/LIMIT, so this counts every non-compliant host.
        COUNT(*) OVER ()::int AS non_compliant_total,
        CASE WHEN s.assessed_count > 0
          THEN ROUND((s.passed_count::numeric / s.assessed_count) * 100)
          ELSE NULL
        END AS compliance_pct
      FROM scored s
      JOIN nodes n ON n.host_identifier = s.host_identifier
      -- A host whose controls were all unassessed has nothing to report against, so it is listed
      -- (assessed_count = 0 yields a NULL percentage) rather than silently counted as compliant.
      WHERE s.passed_count < s.assessed_count OR s.assessed_count = 0
      ORDER BY compliance_pct ASC NULLS LAST
      LIMIT ${MAX_NON_COMPLIANT_REPORT_ROWS}
    `, [activeGuidelineKeys]).catch((err) => {
      // Previously returned [] and let the report print a compliant fleet. The flag makes
      // the failure visible in the PDF instead.
      node_inventory_unavailable = true;
      node_inventory_unavailable_reason = 'query_failed';
      logger.error({ err, tableName }, 'Failed to derive non-compliant node list from compliance results; report will state that the endpoint inventory is unavailable');
      return [] as any[];
    });
    if (!node_inventory_unavailable) {
      non_compliant_total = nodeRows.length > 0
        ? Number(nodeRows[0].non_compliant_total)
        : 0;
    }
  }

  // Filter controls first so charts can show only the relevant controls
  const allControls: any[] = snapshot.control_pass_rates ?? [];
  // The host population the per-control counts below are measured against; see
  // notAssessedHosts. Null - never 0 - when the snapshot does not record it.
  const respondingHosts: number | null = Number.isFinite(Number(snapshot.windows_with_results))
    ? Number(snapshot.windows_with_results)
    : null;
  const controls = allControls
    .filter((r: any) => guidelines[r.key] !== undefined)
    .map((r: any) => {
      const eligible = Number(r.eligibleHosts);
      const pass     = Number(r.passHosts);
      const fail     = Number(r.failHosts);
      // Hosts on which the control was actually decided one way or the other. Where the
      // snapshot records neither a pass nor a fail on a single host, the control was not
      // assessed anywhere: the stored pass rate is then 0 % only because the numerator is
      // an unmeasured zero over an eligible-host denominator, and printing it red states a
      // fleet-wide failure the sweep never observed. Such a control carries no pass rate at
      // all, which also keeps it out of the charts' pass-rate tiers and averages, both of
      // which already skip a null rate.
      const assessedHosts = Number.isFinite(pass) && Number.isFinite(fail) ? pass + fail : null;
      // Hosts the sweep covered but on which this control was neither passed nor failed.
      //
      // This was (eligible - pass - fail), which is identically zero for every row any of
      // the current writers produces: NodesViewSebiHotCompliance, NodesViewIRDAIHotCompliance
      // and features/Compliance all persist failHosts as (eligibleHosts - passHosts). The
      // column therefore printed 0 on every control of every snapshot - including the ones
      // the same row flags as 'Not assessed', where it asserted that no host was left
      // unassessed while the badge beside it said none was assessed at all.
      //
      // eligibleHosts is not the sweep's host population; it is the number of hosts that
      // reached a verdict on this particular control. The population is the snapshot's own
      // windows_with_results (hosts that answered the sweep for SEBI/IRDAI, hosts the sweep
      // targeted for CERT-In), so the hosts this control has no result for is that count
      // less the ones it decided. The eligible-based form is kept as a floor for snapshots
      // whose eligibleHosts exceeds the recorded population, so neither source of the
      // shortfall is dropped.
      //
      // Where the population is not recorded the count stays null and prints as unknown:
      // falling back to a zero would restate the same fabricated 'nothing was missed'.
      const notAssessedFromEligible = assessedHosts != null && Number.isFinite(eligible)
        ? Math.max(0, eligible - assessedHosts)
        : null;
      const notAssessedFromPopulation = assessedHosts != null && respondingHosts != null
        ? Math.max(0, respondingHosts - assessedHosts)
        : null;
      // A row written by the fleet-evidence helper records the unassessed host count itself
      // (complianceHelpers.evaluateFleetComplianceControl counts a host whose probe returned
      // nothing readable). Where the row carries that figure it is a measurement rather than
      // a derivation, so it is taken as a floor: it can only add hosts the two counts above
      // did not already account for, and can never reduce the shortfall to hide one.
      const notAssessedRecorded = Number.isFinite(Number(r.notAssessedHosts))
        ? Math.max(0, Number(r.notAssessedHosts))
        : null;
      const notAssessedHosts = (notAssessedFromPopulation != null || notAssessedRecorded != null)
        ? Math.max(notAssessedFromPopulation ?? 0, notAssessedFromEligible ?? 0, notAssessedRecorded ?? 0)
        : (notAssessedFromEligible != null && notAssessedFromEligible > 0 ? notAssessedFromEligible : null);
      const attested = guidelines[r.key]?.attested === true;
      const controlNotAssessed = !attested && assessedHosts === 0;
      return {
        ...r,
        passRatePct: controlNotAssessed ? null : r.passRatePct,
        assessedHosts,
        notAssessedHosts,
        controlNotAssessed,
        attested,
      };
    });

  // Controls present in the snapshot that this report has no guideline text for are
  // dropped from the table above; the count is carried through so the omission is stated
  // rather than left for the reader to notice.
  const controls_out_of_scope = Math.max(0, allControls.length - controls.length);

  // Mean per-node control pass rate, not the share of fully compliant endpoints.
  // Rendered under the 'Average Control Pass Rate per Endpoint' column header.
  const compliance_percent = Math.round(snapshot.avg_compliance_percent ?? 0);

  // The headline average and the per-control table are written by two different parts of
  // the compliance sweep and can disagree: a snapshot can carry a non-zero
  // avg_compliance_percent while not one row of control_pass_rates records a host that
  // passed. Neither figure can be recomputed from what is stored, so when they contradict
  // each other the report states the contradiction and prints both, instead of printing a
  // headline the table underneath refutes.
  //
  // The previous form of this guard required every control to record zero *eligible*
  // hosts. The live CERT-In snapshot does not have that shape: each control carries the
  // full swept host count as eligibleHosts while recording zero passes and zero fails,
  // so the guard never fired and a 98 % headline was printed over a table reading 0 % on
  // every row. What the two figures actually contradict is the pass count, so that is
  // what is tested: a positive headline average cannot coexist with a control table in
  // which no host passed any control - whether the remaining hosts are recorded as
  // failed or as never assessed. This catches a table with no passes in it at all; a
  // snapshot whose headline merely overstates a table that does record some passes is
  // not detectable from the stored data and is not claimed here.
  const controls_eligible_hosts = controls.reduce((sum: number, r: any) => sum + (Number(r.eligibleHosts) || 0), 0);
  const controls_pass_hosts     = controls.reduce((sum: number, r: any) => sum + (Number(r.passHosts) || 0), 0);
  // Whether the snapshot records pass counts at all, so the report can say "no host
  // passed any control" only where that is what the rows state, and "no control records
  // a pass count" where they are simply absent.
  const controls_pass_hosts_recorded = controls.some((r: any) => Number.isFinite(Number(r.passHosts)));
  // Null where any row omits failHosts: the assessed total is then unknown rather than
  // zero, and the report says so instead of printing a derived count.
  const controls_fail_hosts     = controls.every((r: any) => Number.isFinite(Number(r.failHosts)))
    ? controls.reduce((sum: number, r: any) => sum + Number(r.failHosts), 0)
    : null;
  const controls_assessed_hosts = controls_fail_hosts != null ? controls_pass_hosts + controls_fail_hosts : null;
  const headline_unreconciled   = controls.length > 0 && compliance_percent > 0 && controls_pass_hosts === 0;
  if (headline_unreconciled) {
    logger.warn(
      {
        tableName, compliance_percent, controls: controls.length,
        controls_eligible_hosts, controls_pass_hosts, controls_assessed_hosts,
      },
      'Compliance snapshot is internally inconsistent: non-zero average pass rate with no passing host in any control; report will state the inconsistency',
    );
  }

  // certin_historical_compliance stores total_nodes and windows_hosts with the meanings
  // transposed relative to sebi_/irdai_historical_compliance. Verified in the frontend
  // snapshot writers: NodesViewSebiHotCompliance/NodesViewIRDAIHotCompliance persist
  // totalNodes = windowsCandidates.length (Windows hosts in the fleet) and
  // windowsHosts = hostIds.length (hosts the sweep targeted), whereas
  // NodesViewCertInCompliance.buildFleetSnapshot persists totalNodes = the hosts the
  // sweep targeted and windowsHosts = windowsNodes, the Windows hosts in the fleet.
  // The schema cannot change and stored rows must not be rewritten, so the two are
  // swapped back here, for CERT-In only, on the way out.
  const certinColumnsTransposed = tableName === 'certin_historical_compliance';
  const fleetWindowsHosts = certinColumnsTransposed ? snapshot.windows_hosts : snapshot.total_nodes;
  const sweptWindowsHosts = certinColumnsTransposed ? snapshot.total_nodes : snapshot.windows_hosts;

  // What the 'Endpoints Assessed' column actually counts differs by framework: the SEBI
  // and IRDAI writers persist windows_with_results = successCount (hosts that answered),
  // the CERT-In writer persists the count of hosts the sweep targeted. The column is
  // labelled with its own meaning rather than being described as responding hosts for all.
  const assessed_basis = certinColumnsTransposed
    ? 'endpoints the latest sweep targeted - the CERT-In snapshot does not separately record which of them answered'
    : 'endpoints that were reachable during the latest sweep and returned results';

  const assessed_nodes    = Number(snapshot.windows_with_results ?? 0) || 0;
  const compliant_nodes   = snapshotCompliantHosts;
  // Null - not zero - when the endpoint inventory query failed: an unbuildable inventory is
  // an unknown count, and printing 0 there states that no endpoint is non-compliant.
  // Deliberately the total rather than nodeRows.length, which is capped for rendering.
  const non_compliant_cnt: number | null = node_inventory_unavailable
    ? null
    : (non_compliant_total ?? 0);
  // 'Fully Compliant' is read straight off the snapshot; 'Not Fully Compliant' is the
  // size of the endpoint inventory in section D, which is rebuilt from a different
  // source. They are not guaranteed to partition 'Endpoints Assessed', so the residual is
  // computed and disclosed rather than the columns being made to look like a total.
  const nodes_unaccounted = (compliant_nodes != null && non_compliant_cnt != null)
    ? assessed_nodes - compliant_nodes - non_compliant_cnt
    : null;

  // Build history points for line chart (oldest → newest)
  const toHistPt = (r: any) => ({
    label: new Date((r.snapshot_at ?? 0) * 1000).toLocaleDateString(DEFAULT_LOCALE, { month: 'short', day: 'numeric' }),
    score: Math.round(r.avg_compliance_percent ?? 0),
  });
  const historyData = [...(histRows ?? [])].reverse().map(toHistPt);

  const [vajra_logo_svg, frameCharts, extraCharts, history_line] = await Promise.all([
    getVajraLogoSvg(),
    generateFrameworkCharts(snapshot, controls, frameworkColor),
    extraChartsGen ? extraChartsGen(snapshot, controls) : Promise.resolve({}),
    generateHistoryLine(historyData, frameworkName, frameworkColor),
  ]).catch((err) => {
    logger.error({ err, tableName, stage: 'chart_generation' }, 'Framework compliance report generation failed while generating charts');
    throw err;
  });

  const charts = { ...frameCharts, ...extraCharts, history_line };

  const downloaded_by: string = (req as any).jwtPayload?.name ?? 'Unknown';

  // Every figure below is read out of this snapshot, not measured now; the report prints
  // when it was taken and how old it is next to the generation date.
  const now = new Date();
  const provenance = snapshotProvenance(snapshot.snapshot_at, now);
  if (provenance.snapshot_predates_control_logic) {
    logger.warn(
      { tableName, snapshotAt: snapshot.snapshot_at },
      'Latest compliance snapshot predates the current control-evaluation logic; report will disclose that its figures are not a current measurement',
    );
  }

  // Section D rows rebuilt from the per-host results table are separate measurements taken
  // at their own times, which can be far older than the snapshot they are printed under.
  // Each row carries when it was measured so the reader is not left to assume the snapshot
  // date applies to it; rows that came from the snapshot itself carry no such timestamp and
  // print nothing.
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const non_compliant_nodes = (nodeRows ?? []).map((row: any) => {
    const measuredAt = Number(row?.assessed_at);
    if (!Number.isFinite(measuredAt) || measuredAt <= 0) return row;
    return {
      ...row,
      measured_on: new Date(measuredAt * 1000).toLocaleDateString(DEFAULT_LOCALE),
      measured_age_text: measuredAt > nowSeconds ? null : describeAge(nowSeconds - measuredAt),
    };
  });
  const derivedMeasuredAt = node_rows_source === 'derived'
    ? non_compliant_nodes.map((row: any) => Number(row?.assessed_at)).filter((ts: number) => Number.isFinite(ts) && ts > 0)
    : [];
  const node_rows_newest_measured = derivedMeasuredAt.length > 0
    ? new Date(Math.max(...derivedMeasuredAt) * 1000).toLocaleDateString(DEFAULT_LOCALE)
    : null;
  const node_rows_oldest_measured = derivedMeasuredAt.length > 0
    ? new Date(Math.min(...derivedMeasuredAt) * 1000).toLocaleDateString(DEFAULT_LOCALE)
    : null;

  const templateData = {
    framework_name:     frameworkName,
    framework_subtitle: frameworkSubtitle,
    framework_color:    frameworkColor,
    organization:       'Your Organization',
    // Same clock reading the snapshot age is measured against, so the two agree.
    generated_on:       now.toLocaleDateString(DEFAULT_LOCALE),
    generated_datetime: now.toLocaleString(DEFAULT_LOCALE),
    downloaded_by,
    report_period:      'Current Assessment',
    total_checks:       Object.keys(guidelines).length,
    total_nodes:        assessed_nodes,
    // The derived fallback is only applied when the endpoint inventory was actually built:
    // subtracting an unavailable count would manufacture a fully-compliant figure out of a
    // failed query.
    compliant_nodes:        compliant_nodes
      ?? (non_compliant_cnt != null ? Math.max(0, assessed_nodes - non_compliant_cnt) : null),
    compliant_nodes_recorded: compliant_nodes != null,
    non_compliant_count:    non_compliant_cnt,
    non_compliant_nodes,
    // Section D renders at most MAX_NON_COMPLIANT_REPORT_ROWS rows; these three let the
    // template say which of the two it is showing.
    non_compliant_shown:     non_compliant_nodes.length,
    non_compliant_row_cap:   MAX_NON_COMPLIANT_REPORT_ROWS,
    non_compliant_truncated: non_compliant_cnt != null && non_compliant_nodes.length < non_compliant_cnt,
    node_inventory_unavailable,
    node_inventory_unavailable_reason,
    node_rows_source,
    node_rows_newest_measured,
    node_rows_oldest_measured,
    node_metadata_unavailable,
    nodes_unaccounted,
    assessed_basis,
    fleet_windows_hosts: Number.isFinite(Number(fleetWindowsHosts)) ? Number(fleetWindowsHosts) : null,
    swept_windows_hosts: Number.isFinite(Number(sweptWindowsHosts)) ? Number(sweptWindowsHosts) : null,
    compliance_percent,
    headline_unreconciled,
    controls_eligible_hosts,
    controls_pass_hosts,
    controls_pass_hosts_recorded,
    controls_fail_hosts,
    controls_assessed_hosts,
    controls_out_of_scope,
    controls,
    checks:             guidelines,
    ...provenance,
    charts,
    vajra_logo_svg,
  };

  const pdf = await generateFrameworkReport(templateData);
  // All three callers (SEBI/IRDAI/CERT-In) are registered under router.get in
  // compliance_pdf.ts, so this uses the same log level as generateOrgPdf's
  // equivalent success log below.
  logger.debug(
    {
      tableName, filename,
      nonCompliantCount: non_compliant_cnt,
      nonCompliantRowsRendered: nodeRows?.length ?? 0,
      nodeInventoryUnavailable: node_inventory_unavailable,
      nodeMetadataUnavailable: node_metadata_unavailable,
    },
    'Framework compliance report generated',
  );
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  return res.send(pdf);
}

// Route handlers

export async function generateSebiPdf(req: Request, res: Response) {
  try {
    return await generateFrameworkPdf(
      req, res, 'sebi_historical_compliance', SEBI_GUIDELINES,
      'SEBI CSCRF', 'Cyber Security and Cyber Resilience Framework', FRAMEWORK_COLORS.sebi,
      'sebi-compliance-report.pdf',
      (_snapshot, controls) =>
        generateSebiDomainChart(controls, SEBI_GUIDELINES)
          .then(domain_bar => ({ domain_bar })),
    );
  } catch (error) {
    logger.error({ err: error }, 'Failed to generate SEBI compliance report');
    return res.status(500).json({ status: 'Error', message: error instanceof Error ? error.message : 'Failed to generate SEBI report' });
  }
}

export async function generateIrdaiPdf(req: Request, res: Response) {
  try {
    return await generateFrameworkPdf(
      req, res, 'irdai_historical_compliance', IRDAI_GUIDELINES,
      'IRDAI', 'Insurance Regulatory and Development Authority Cyber Security Framework', FRAMEWORK_COLORS.irdai,
      'irdai-compliance-report.pdf',
    );
  } catch (error) {
    logger.error({ err: error }, 'Failed to generate IRDAI compliance report');
    return res.status(500).json({ status: 'Error', message: error instanceof Error ? error.message : 'Failed to generate IRDAI report' });
  }
}

export async function generateCertinPdf(req: Request, res: Response) {
  try {
    return await generateFrameworkPdf(
      req, res, 'certin_historical_compliance', CERTIN_ACTIVE_GUIDELINES,
      'CERT-In', 'Indian Computer Emergency Response Team Cyber Security Guidelines', FRAMEWORK_COLORS.certin,
      'certin-compliance-report.pdf',
    );
  } catch (error) {
    logger.error({ err: error }, 'Failed to generate CERT-In compliance report');
    return res.status(500).json({ status: 'Error', message: error instanceof Error ? error.message : 'Failed to generate CERT-In report' });
  }
}

// Overall Vajra compliance report

const ORG_TEMPLATE = path.join(TEMPLATES_DIR, 'org_report.html');

export async function generateOrgPdf(req: Request, res: Response) {
  try {
    const db = await getDbOrError(res);
    if (!db) return;

    const [
      orgSnap, sebiSnap, irdaiSnap, certinSnap,
      fleetRows, alertRows, auditRows,
      orgHistory, sebiHistory, irdaiHistory, certinHistory,
      weeklyAlertRows,
      sebiCountRows, irdaiCountRows, certinCountRows, orgCountRows,
    ] = await Promise.all([
      // CMPL-DB-08: these four reads were `SELECT *`, which pulls fully_compliant_nodes_list
      // and non_compliant_nodes_list across the wire on every org report. The org template
      // reads neither - only the score, coverage, tier counts and timestamp below.
      //
      // control_pass_rates is read back deliberately (one row per framework, not a scan):
      // the org report's headline score per framework cannot be checked against anything
      // else, and a snapshot whose control table records no passing host on any control
      // cannot have produced a positive average. Without these rows the org report printed
      // CERT-In at 98 % in green over exactly that contradiction, which the per-framework
      // PDF already refuses to print. See scoreUnreconciled below.
      //
      // historical_compliance deliberately has a shorter list: unlike the three framework
      // tables it has no fully_compliant_nodes column at all (see ormconfig-setup.ts
      // createHistoricalComplianceTable), which `SELECT *` hid by silently yielding
      // undefined. Naming it here would turn that into a query error, so it is left out
      // and the Vajra row's "compliant" figure stays null exactly as it was before.
      db.query(`
        SELECT snapshot_at, avg_compliance_percent, windows_with_results,
               strong_count, moderate_count, needs_attention_count, control_pass_rates
        FROM historical_compliance ORDER BY id DESC LIMIT 1
      `).catch((err) => {
        logger.error({ err, source: 'historical_compliance' }, 'Org report generation failed while fetching source data');
        throw err;
      }),
      db.query(`
        SELECT snapshot_at, avg_compliance_percent, windows_with_results,
               fully_compliant_nodes, strong_count, moderate_count, needs_attention_count,
               control_pass_rates
        FROM sebi_historical_compliance ORDER BY id DESC LIMIT 1
      `).catch((err) => {
        logger.error({ err, source: 'sebi_historical_compliance' }, 'Org report generation failed while fetching source data');
        throw err;
      }),
      db.query(`
        SELECT snapshot_at, avg_compliance_percent, windows_with_results,
               fully_compliant_nodes, strong_count, moderate_count, needs_attention_count,
               control_pass_rates
        FROM irdai_historical_compliance ORDER BY id DESC LIMIT 1
      `).catch((err) => {
        logger.error({ err, source: 'irdai_historical_compliance' }, 'Org report generation failed while fetching source data');
        throw err;
      }),
      db.query(`
        SELECT snapshot_at, avg_compliance_percent, windows_with_results,
               fully_compliant_nodes, strong_count, moderate_count, needs_attention_count,
               control_pass_rates
        FROM certin_historical_compliance ORDER BY id DESC LIMIT 1
      `).catch((err) => {
        logger.error({ err, source: 'certin_historical_compliance' }, 'Org report generation failed while fetching source data');
        throw err;
      }),
      db.query(`
        SELECT COUNT(*)::int AS total_nodes,
               COUNT(*) FILTER (WHERE last_seen > (EXTRACT(EPOCH FROM NOW()) - ${NODE_STATUS_ONLINE_THRESHOLD_SECONDS}))::int AS online_nodes,
               COUNT(*) FILTER (WHERE critical = true)::int AS critical_nodes,
               COUNT(*) FILTER (WHERE LOWER(COALESCE(os_platform,'')) LIKE '%windows%' OR LOWER(COALESCE(os_name,'')) LIKE '%windows%')::int AS windows_nodes
        FROM nodes
      `).catch((err) => {
        logger.error({ err, source: 'nodes' }, 'Org report generation failed while fetching source data');
        throw err;
      }),
      db.query(`
        SELECT COUNT(*)::int AS total,
               COUNT(*) FILTER (WHERE is_open = true)::int AS open,
               COUNT(*) FILTER (WHERE is_open = false)::int AS closed
        FROM alerts
      `).catch((err) => {
        logger.error({ err, source: 'alerts' }, 'Org report generation failed while fetching source data');
        throw err;
      }),
      // audit_trail lives on the primary datasource, not the fleet one the rest of
      // this batch uses. The fleet DB has an empty duplicate of the table, so
      // querying `db` succeeds and returns 0 rather than raising — the catch below
      // cannot detect the mistake.
      //
      // Neither branch below may default to 0: "0 audit events recorded" in a compliance
      // report is an assertion that nothing was logged, which is a finding in its own
      // right. An unreachable datasource or a failed count is an unknown, so it is carried
      // out as null and the template prints "not available".
      (async () => {
        const primary = dbSourceConnection()?.[0];
        if (!primary) {
          logger.warn({}, 'Primary datasource unavailable for audit trail event count; org report will state the figure is unavailable');
          return [{ total_events: null }];
        }
        return primary.query(`SELECT COUNT(*)::int AS total_events FROM audit_trail`);
      })().catch((err) => {
        logger.warn({ err }, 'Failed to fetch audit trail event count for org report; org report will state the figure is unavailable');
        return [{ total_events: null }];
      }),
      db.query(`SELECT snapshot_at, avg_compliance_percent FROM historical_compliance ORDER BY id DESC LIMIT ${COMPLIANCE_HISTORY_SNAPSHOT_LIMIT}`),
      db.query(`SELECT snapshot_at, avg_compliance_percent FROM sebi_historical_compliance ORDER BY id DESC LIMIT ${COMPLIANCE_HISTORY_SNAPSHOT_LIMIT}`),
      db.query(`SELECT snapshot_at, avg_compliance_percent FROM irdai_historical_compliance ORDER BY id DESC LIMIT ${COMPLIANCE_HISTORY_SNAPSHOT_LIMIT}`),
      db.query(`SELECT snapshot_at, avg_compliance_percent FROM certin_historical_compliance ORDER BY id DESC LIMIT ${COMPLIANCE_HISTORY_SNAPSHOT_LIMIT}`),
      // Weekly alert counts (last 7 days, grouped by calendar day)
      db.query(`
        SELECT DATE(to_timestamp(CAST(unixtime AS BIGINT))) AS alert_day,
               COUNT(*)::int AS daily_count
        FROM alerts
        WHERE CAST(unixtime AS BIGINT) >= $1
        GROUP BY alert_day
        ORDER BY alert_day ASC
      `, [Math.floor(Date.now() / 1000) - 7 * 86400]).catch((err) => {
        logger.warn({ err }, 'Failed to fetch weekly alert counts for org report, defaulting to empty');
        return [] as any[];
      }),
      // Total snapshot counts per framework (for the recency table).
      // A failed count is null, never 0: "0 snapshots saved" reads as "this framework has
      // never been assessed", and the recency table already renders null as a dash.
      db.query(`SELECT COUNT(*)::int AS cnt FROM sebi_historical_compliance`).catch((err) => {
        logger.warn({ err, framework: 'sebi' }, 'Failed to fetch snapshot count for org report; count will be reported as unknown');
        return [{ cnt: null }];
      }),
      db.query(`SELECT COUNT(*)::int AS cnt FROM irdai_historical_compliance`).catch((err) => {
        logger.warn({ err, framework: 'irdai' }, 'Failed to fetch snapshot count for org report; count will be reported as unknown');
        return [{ cnt: null }];
      }),
      db.query(`SELECT COUNT(*)::int AS cnt FROM certin_historical_compliance`).catch((err) => {
        logger.warn({ err, framework: 'certin' }, 'Failed to fetch snapshot count for org report; count will be reported as unknown');
        return [{ cnt: null }];
      }),
      db.query(`SELECT COUNT(*)::int AS cnt FROM historical_compliance`).catch((err) => {
        logger.warn({ err, framework: 'vajra' }, 'Failed to fetch snapshot count for org report; count will be reported as unknown');
        return [{ cnt: null }];
      }),
    ]);

    const fleet     = fleetRows?.[0]   ?? {};
    const alerts    = alertRows?.[0]   ?? {};
    const audit     = auditRows?.[0]   ?? {};
    const snapOrg    = orgSnap?.[0]    ?? null;
    const snapSebi   = sebiSnap?.[0]   ?? null;
    const snapIrdai  = irdaiSnap?.[0]  ?? null;
    const snapCertin = certinSnap?.[0] ?? null;

    const downloaded_by: string = (req as any).jwtPayload?.name ?? 'Unknown';

    const now = new Date();

    const sc = (v: any): number | null =>
      v?.avg_compliance_percent != null ? Math.round(v.avg_compliance_percent) : null;

    // Whether a framework's headline score can be reconciled with the per-control table in
    // the same snapshot. This is the guard generateFrameworkPdf already applies (see
    // headline_unreconciled there); the org report built its framework rows from the
    // snapshot scalars alone and never read control_pass_rates, so the contradiction the
    // per-framework PDF refuses to print was printed here in green instead - CERT-In at
    // 98 % over a control table recording not one passing host on any of its controls.
    //
    // A positive average pass rate cannot be produced by a table in which no endpoint
    // passed anything, and neither figure can be recomputed from what is stored, so the
    // score is withheld rather than one of the two being chosen. This is a not-assessed
    // state: it is not a finding of non-compliance, and nothing here turns a pass into a
    // failure or the reverse.
    // `guidelines`, when given, is the same already-filtered map each framework's `controls:`
    // field below is counted from (SEBI_GUIDELINES / IRDAI_GUIDELINES / CERTIN_ACTIVE_GUIDELINES
    // — each already excludes the structurally-unmeasurable Class A keys). Without this filter,
    // `rates` is the raw, unfiltered snapshot array and still contains the removed keys, so this
    // function's own count would silently disagree with the `controls:` figure printed a few
    // lines away in the same report — exactly the self-contradiction (10 vs 13 for CERT-In) the
    // 2026-09-03 post-deploy verification pass found in the "Data inconsistency" disclosure box.
    // The Vajra Baseline call site passes no guidelines map: its 18 keys are the shared Windows
    // baseline probe set, untouched by the SEBI/IRDAI/CERT-In Class A removal, so no filter applies.
    const controlPassHosts = (snap: any, guidelines?: Record<string, unknown>): { controls: number; passHosts: number } => {
      const allRates: any[] = Array.isArray(snap?.control_pass_rates) ? snap.control_pass_rates : [];
      const rates = guidelines ? allRates.filter((r: any) => guidelines[r?.key] !== undefined) : allRates;
      return {
        controls: rates.length,
        passHosts: rates.reduce((sum: number, r: any) => sum + (Number(r?.passHosts) || 0), 0),
      };
    };
    // Framework-aware for the same reason controlPassHosts takes a guidelines map: without it,
    // a removed Class A key's stored passHosts could tip this real pass/fail gate (whether the
    // score gets withheld), not just a displayed count.
    const scoreUnreconciled = (snap: any, guidelines?: Record<string, unknown>): boolean => {
      const score = sc(snap);
      const { controls, passHosts } = controlPassHosts(snap, guidelines);
      return score != null && score > 0 && controls > 0 && passHosts === 0;
    };
    const anyFrameworkUnreconciled = [
      [snapSebi, SEBI_GUIDELINES],
      [snapIrdai, IRDAI_GUIDELINES],
      [snapCertin, CERTIN_ACTIVE_GUIDELINES],
      [snapOrg, undefined],
    ].some(([snap, guidelines]) => scoreUnreconciled(snap, guidelines as Record<string, unknown> | undefined));
    if (anyFrameworkUnreconciled) {
      logger.warn(
        {},
        'At least one framework snapshot in the org report records a positive average pass rate with no passing host in any control; its score will be withheld from the report as unreconciled',
      );
    }

    // Previous score: history rows are ORDER BY id DESC, so index 1 is the snapshot before the latest
    const prevSc = (rows: any[]): number | null => {
      if (!rows || rows.length < 2) return null;
      const v = rows[1]?.avg_compliance_percent;
      return v != null ? Math.round(v) : null;
    };

    // Windows coverage
    const windows_nodes: number = fleet.windows_nodes ?? 0;

    const coveragePct = (assessed: number | null | undefined): string => {
      if (!assessed || !windows_nodes) return 'N/A';
      return `${Math.round((assessed / windows_nodes) * 100)}%`;
    };
    // Windows hosts in the fleet that this framework's latest sweep has no result for.
    // Not a failure and not a pass: they are simply outside what the percentages measure.
    const notAssessedWindowsHosts = (assessed: number | null | undefined): number | null => {
      if (assessed == null || !windows_nodes) return null;
      return Math.max(0, windows_nodes - Number(assessed));
    };

    const sebi_coverage   = coveragePct(snapSebi?.windows_with_results);
    const irdai_coverage  = coveragePct(snapIrdai?.windows_with_results);
    const certin_coverage = coveragePct(snapCertin?.windows_with_results);
    const vajra_coverage  = coveragePct(snapOrg?.windows_with_results);

    // Snapshot recency
    const fmtTs = (ts: any): string | null =>
      ts ? new Date(Number(ts) * 1000).toLocaleString(DEFAULT_LOCALE) : null;

    const sebi_latest_snapshot   = fmtTs(snapSebi?.snapshot_at);
    const irdai_latest_snapshot  = fmtTs(snapIrdai?.snapshot_at);
    const certin_latest_snapshot = fmtTs(snapCertin?.snapshot_at);
    const vajra_latest_snapshot  = fmtTs(snapOrg?.snapshot_at);

    // Age and control-logic provenance of each framework's newest snapshot. Every score
    // in this report is that snapshot's figure, not a measurement taken now, so how old
    // it is - and whether it was written by the previous control logic - is printed
    // alongside it rather than left to be inferred from the generation date.
    const sebi_provenance   = snapshotProvenance(snapSebi?.snapshot_at,   now);
    const irdai_provenance  = snapshotProvenance(snapIrdai?.snapshot_at,  now);
    const certin_provenance = snapshotProvenance(snapCertin?.snapshot_at, now);
    const vajra_provenance  = snapshotProvenance(snapOrg?.snapshot_at,    now);
    const control_logic_revised_on = sebi_provenance.control_logic_revised_on;
    const any_snapshot_predates_control_logic = [
      sebi_provenance, irdai_provenance, certin_provenance, vajra_provenance,
    ].some((prov) => prov.snapshot_predates_control_logic === true);
    if (any_snapshot_predates_control_logic) {
      logger.warn(
        {},
        'At least one framework snapshot in the org report predates the current control-evaluation logic; report will disclose that those figures are not a current measurement',
      );
    }

    // `?? 0` here would have undone the null the catches above now return, so the count is
    // only converted where one was actually read.
    const snapshotCount = (rows: any[] | undefined): number | null => {
      const cnt = rows?.[0]?.cnt;
      return cnt != null && Number.isFinite(Number(cnt)) ? Number(cnt) : null;
    };
    const sebi_snapshots_count   = snapshotCount(sebiCountRows);
    const irdai_snapshots_count  = snapshotCount(irdaiCountRows);
    const certin_snapshots_count = snapshotCount(certinCountRows);
    const vajra_snapshots_count  = snapshotCount(orgCountRows);

    // Weekly alert daily totals
    const weeklyDays = Array.from({ length: 7 }).map((_, i) => {
      const d = new Date(now);
      d.setDate(d.getDate() - (6 - i));
      const dateStr = d.toISOString().split('T')[0]; // YYYY-MM-DD
      const label   = d.toLocaleDateString(DEFAULT_LOCALE, { weekday: 'short', day: 'numeric', month: 'short' });
      const row     = (weeklyAlertRows as any[]).find((r: any) => String(r.alert_day ?? '').startsWith(dateStr));
      return { label, total: Number(row?.daily_count ?? 0) };
    });

    // Helper: per-framework fully-compliant donut
    const fwCompliantDonut = (snap: any, name: string) => {
      const compliant = snap?.fully_compliant_nodes ?? 0;
      const total     = snap?.windows_with_results  ?? 0;
      const nc = Math.max(0, total - compliant);
      return generateSimpleDonut(
        ['Fully Compliant', 'Not Fully Compliant'],
        compliant + nc > 0 ? [compliant, nc] : [0, 1],
        [STATUS_COLOR_PASS, STATUS_COLOR_FAIL],
        name,
      );
    };

    // Convert history rows to chart points (oldest → newest)
    const toHistPts = (rows: any[]) =>
      [...(rows ?? [])].reverse().map((r: any) => ({
        label: new Date((r.snapshot_at ?? 0) * 1000).toLocaleDateString(DEFAULT_LOCALE, { month: 'short', day: 'numeric' }),
        score: Math.round(r.avg_compliance_percent ?? 0),
      }));

    const onlineCount  = fleet.online_nodes ?? 0;
    const offlineCount = Math.max(0, (fleet.total_nodes ?? 0) - onlineCount);
    const criticalCount = fleet.critical_nodes ?? 0;
    const nonCriticalCount = Math.max(0, (fleet.total_nodes ?? 0) - criticalCount);

    const [
      vajra_logo_svg,
      comparison_chart, fleet_donut, critical_donut, alert_donut, multi_history_chart,
      sebi_fw_donut, irdai_fw_donut, certin_fw_donut, vajra_fw_donut,
      weekly_bar,
    ] = await Promise.all([
      getVajraLogoSvg(),
      generateOrgComparisonChart([
        { name: 'SEBI CSCRF',     score: sc(snapSebi),   color: FRAMEWORK_COLORS.sebi },
        { name: 'IRDAI',          score: sc(snapIrdai),  color: FRAMEWORK_COLORS.irdai },
        { name: 'CERT-In',        score: sc(snapCertin), color: FRAMEWORK_COLORS.certin },
        { name: 'Vajra Baseline', score: sc(snapOrg),    color: FRAMEWORK_COLORS.vajra },
      ]),
      generateSimpleDonut(
        ['Online', 'Offline'], [onlineCount, offlineCount],
        [STATUS_COLOR_PASS, '#9ca3af'], 'Fleet Online Status',
      ),
      generateSimpleDonut(
        ['Critical Assets', 'Standard Assets'], [criticalCount, nonCriticalCount],
        [STATUS_COLOR_FAIL, FRAMEWORK_COLORS.sebi], 'Fleet Asset Classification',
      ),
      generateSimpleDonut(
        ['Open Alerts', 'Closed Alerts'], [alerts.open ?? 0, alerts.closed ?? 0],
        [STATUS_COLOR_FAIL, STATUS_COLOR_PASS], 'Alert Status Distribution',
      ),
      generateMultiHistoryLine([
        { name: 'SEBI CSCRF',     color: FRAMEWORK_COLORS.sebi, data: toHistPts(sebiHistory) },
        { name: 'IRDAI',          color: FRAMEWORK_COLORS.irdai, data: toHistPts(irdaiHistory) },
        { name: 'CERT-In',        color: FRAMEWORK_COLORS.certin, data: toHistPts(certinHistory) },
        { name: 'Vajra Baseline', color: FRAMEWORK_COLORS.vajra, data: toHistPts(orgHistory) },
      ]),
      fwCompliantDonut(snapSebi,   'SEBI CSCRF'),
      fwCompliantDonut(snapIrdai,  'IRDAI'),
      fwCompliantDonut(snapCertin, 'CERT-In'),
      fwCompliantDonut(snapOrg,    'Vajra Baseline'),
      generateWeeklyAlertsBar(weeklyDays),
    ]);

    const templateData = {
      vajra_logo_svg,
      comparison_chart,
      fleet_donut,
      critical_donut,
      alert_donut,
      multi_history_chart,
      sebi_fw_donut,
      irdai_fw_donut,
      certin_fw_donut,
      vajra_fw_donut,
      weekly_bar,
      generated_on:       now.toLocaleDateString(DEFAULT_LOCALE),
      generated_datetime: now.toLocaleString(DEFAULT_LOCALE),
      fleet_total:    fleet.total_nodes    ?? 0,
      fleet_online:   onlineCount,
      fleet_offline:  offlineCount,
      fleet_critical: criticalCount,
      windows_nodes,
      sebi_coverage,
      irdai_coverage,
      certin_coverage,
      vajra_coverage,
      alerts_total:   alerts.total  ?? 0,
      alerts_open:    alerts.open   ?? 0,
      alerts_closed:  alerts.closed ?? 0,
      // null (not 0) when the count could not be read; the template prints 'Not available'.
      audit_events:   audit.total_events ?? null,
      downloaded_by,
      control_logic_revised_on,
      any_snapshot_predates_control_logic,
      any_framework_unreconciled: anyFrameworkUnreconciled,
      frameworks: [
        {
          // 27, not 37: SEBI_GUIDELINES excludes both the 4 hidden/dead-evaluator keys and
          // the 10 keys confirmed structurally unmeasurable (Class A) by the 2026-09-03
          // live-sweep verification pass. See SEBI_STRUCTURALLY_UNMEASURABLE above.
          name: 'SEBI CSCRF', controls: Object.keys(SEBI_GUIDELINES).length,
          assessed:        snapSebi?.windows_with_results,
          not_assessed:    notAssessedWindowsHosts(snapSebi?.windows_with_results),
          assessed_caveat: null,
          compliant:       snapSebi?.fully_compliant_nodes ?? null,
          score:           sc(snapSebi),
          score_unreconciled: scoreUnreconciled(snapSebi, SEBI_GUIDELINES),
          control_pass_hosts: controlPassHosts(snapSebi, SEBI_GUIDELINES).passHosts,
          control_rows:       controlPassHosts(snapSebi, SEBI_GUIDELINES).controls,
          prev_score:      prevSc(sebiHistory),
          strong:          snapSebi?.strong_count          ?? 0,
          moderate:        snapSebi?.moderate_count        ?? 0,
          needs_attention: snapSebi?.needs_attention_count ?? 0,
          latest_snapshot: sebi_latest_snapshot,
          snapshot_age_text: sebi_provenance.snapshot_age_text,
          snapshot_predates_control_logic: sebi_provenance.snapshot_predates_control_logic,
          snapshots_count: sebi_snapshots_count,
        },
        {
          // 20, not 31: IRDAI_GUIDELINES excludes both the 2 hidden/dead-evaluator keys and
          // the 9 keys confirmed structurally unmeasurable (Class A) by the 2026-09-03
          // live-sweep verification pass. See IRDAI_STRUCTURALLY_UNMEASURABLE above.
          // (Was 18 of 30 before key 7 was reclassified to Class B on 2026-09-04 and key 31,
          // data-at-rest encryption, was added on 2026-09-07.)
          name: 'IRDAI', controls: Object.keys(IRDAI_GUIDELINES).length,
          assessed:        snapIrdai?.windows_with_results,
          not_assessed:    notAssessedWindowsHosts(snapIrdai?.windows_with_results),
          assessed_caveat: null,
          compliant:       snapIrdai?.fully_compliant_nodes ?? null,
          score:           sc(snapIrdai),
          score_unreconciled: scoreUnreconciled(snapIrdai, IRDAI_GUIDELINES),
          control_pass_hosts: controlPassHosts(snapIrdai, IRDAI_GUIDELINES).passHosts,
          control_rows:       controlPassHosts(snapIrdai, IRDAI_GUIDELINES).controls,
          prev_score:      prevSc(irdaiHistory),
          strong:          snapIrdai?.strong_count          ?? 0,
          moderate:        snapIrdai?.moderate_count        ?? 0,
          needs_attention: snapIrdai?.needs_attention_count ?? 0,
          latest_snapshot: irdai_latest_snapshot,
          snapshot_age_text: irdai_provenance.snapshot_age_text,
          snapshot_predates_control_logic: irdai_provenance.snapshot_predates_control_logic,
          snapshots_count: irdai_snapshots_count,
        },
        {
          // 10, not 13: CERT-In 4.2 is carried in the snapshot and is listed in
          // CERTIN_GUIDELINES as an operator-attested control instead of being dropped, but
          // CERTIN_ACTIVE_GUIDELINES additionally excludes the 3 keys (1.12, 2.6, 5.8)
          // confirmed structurally unmeasurable (Class A) by the 2026-09-03 live-sweep
          // verification pass. See CERTIN_STRUCTURALLY_UNMEASURABLE above.
          name: 'CERT-In', controls: Object.keys(CERTIN_ACTIVE_GUIDELINES).length,
          assessed:        snapCertin?.windows_with_results,
          not_assessed:    notAssessedWindowsHosts(snapCertin?.windows_with_results),
          // The CERT-In writer persists windows_with_results as the count of hosts the
          // sweep targeted, not the count that answered; see the same note in
          // generateFrameworkPdf.
          assessed_caveat: 'Endpoints Assessed counts the endpoints the CERT-In sweep targeted; that snapshot does not separately record which of them answered.',
          compliant:       snapCertin?.fully_compliant_nodes ?? null,
          score:           sc(snapCertin),
          score_unreconciled: scoreUnreconciled(snapCertin, CERTIN_ACTIVE_GUIDELINES),
          control_pass_hosts: controlPassHosts(snapCertin, CERTIN_ACTIVE_GUIDELINES).passHosts,
          control_rows:       controlPassHosts(snapCertin, CERTIN_ACTIVE_GUIDELINES).controls,
          prev_score:      prevSc(certinHistory),
          strong:          snapCertin?.strong_count          ?? 0,
          moderate:        snapCertin?.moderate_count        ?? 0,
          needs_attention: snapCertin?.needs_attention_count ?? 0,
          latest_snapshot: certin_latest_snapshot,
          snapshot_age_text: certin_provenance.snapshot_age_text,
          snapshot_predates_control_logic: certin_provenance.snapshot_predates_control_logic,
          snapshots_count: certin_snapshots_count,
        },
        {
          name: 'Vajra Baseline', controls: 18,
          assessed:        snapOrg?.windows_with_results,
          not_assessed:    notAssessedWindowsHosts(snapOrg?.windows_with_results),
          assessed_caveat: null,
          // Always null: historical_compliance has no fully_compliant_nodes column at all
          // (see the note on the query above), so the Vajra Baseline register records no
          // fully-compliant endpoint count for this report to print. The dash in that
          // column is an unrecorded figure, not a count of zero, and the footnote below
          // says so rather than leaving the dash to be read as none.
          compliant:       snapOrg?.fully_compliant_nodes ?? null,
          compliant_caveat: 'The Vajra Baseline snapshot does not record a fully-compliant endpoint count - that register stores per-control pass rates only - so this figure is unavailable rather than zero.',
          score:           sc(snapOrg),
          score_unreconciled: scoreUnreconciled(snapOrg),
          control_pass_hosts: controlPassHosts(snapOrg).passHosts,
          control_rows:       controlPassHosts(snapOrg).controls,
          prev_score:      prevSc(orgHistory),
          strong:          snapOrg?.strong_count          ?? 0,
          moderate:        snapOrg?.moderate_count        ?? 0,
          needs_attention: snapOrg?.needs_attention_count ?? 0,
          latest_snapshot: vajra_latest_snapshot,
          snapshot_age_text: vajra_provenance.snapshot_age_text,
          snapshot_predates_control_logic: vajra_provenance.snapshot_predates_control_logic,
          snapshots_count: vajra_snapshots_count,
        },
      ],
    };

    let html: string;
    try {
      html = await ejs.renderFile(ORG_TEMPLATE, templateData);
    } catch (err) {
      logger.error({ err, stage: 'template_render' }, 'Org report generation failed while rendering HTML template');
      throw err;
    }

    // Take a page on the shared Chromium rather than spawning a private one per
    // download; see the lifetime notes in generateFrameworkReport.ts. On a
    // single-process server, a per-request launch blocks every other in-flight
    // request.
    let browser: Awaited<ReturnType<typeof acquireReportBrowser>>;
    try {
      browser = await acquireReportBrowser();
    } catch (err) {
      logger.error({ err, stage: 'browser_launch' }, 'Org report generation failed while launching headless browser');
      throw err;
    }
    let page: Awaited<ReturnType<typeof browser.newPage>> | undefined;
    try {
      page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'load' });
      const pdf = await page.pdf({
        format: 'A4',
        printBackground: true,
        displayHeaderFooter: true,
        headerTemplate: '<span></span>',
        footerTemplate: `
          <div style="width:100%;font-family:'Bookman Old Style','URW Bookman',Bookman,'Palatino Linotype',Palatino,Georgia,serif;font-size:7.5pt;
                      color:#999;display:flex;justify-content:space-between;align-items:center;
                      padding:3pt 16mm 0;border-top:0.5pt solid #e0e0e0;box-sizing:border-box;">
            <span>Vajra &middot; Confidential</span>
            <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
          </div>
        `,
        margin: { top: '18mm', bottom: '18mm', left: '16mm', right: '16mm' },
      });
      logger.debug({}, 'Organization compliance report generated');
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename="vajra-compliance-report.pdf"');
      return res.send(Buffer.from(pdf));
    } catch (err) {
      logger.error({ err, stage: 'pdf_render' }, 'Org report generation failed while rendering PDF');
      throw err;
    } finally {
      // Close the page, not the shared browser. Close failures are logged rather
      // than thrown so they cannot mask the real error from the try block.
      if (page) {
        await page.close().catch((err) => logger.warn({ err }, 'Failed to close org report page'));
      }
      releaseReportBrowser();
    }
  } catch (error) {
    logger.error({ err: error }, 'Failed to generate organization compliance report');
    return res.status(500).json({ status: 'Error', message: error instanceof Error ? error.message : 'Failed to generate report' });
  }
}
