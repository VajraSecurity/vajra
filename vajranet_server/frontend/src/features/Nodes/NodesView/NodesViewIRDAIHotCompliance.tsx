/**
 * NodesViewIRDAIHotCompliance
 *
 * IRDAI Hot compliance checklist for a single node.
 * Displays all 15 IRDAI Hot compliance points in a numbered table.
 */

import { useState, useCallback, useEffect } from 'react';
import { debugLog } from '@/lib/debugLog';
import type { NodeData } from './types';
import { ALERTS_URLS, API_BASE_URL, NODES_URLS } from '../../../api/urls';
import api from '../../../api/axiosInstance';
import { nodesViewApi } from './nodesViewApi';
import { fetchPowerShellOutputs, parsePsObjectList, SIGNATURE_MAX_AGE_DAYS } from './utils/certinComplianceChecks';
// 2026-09-07: the removable-storage probe is imported from the SEBI evidence module rather
// than kept as a private copy here. This file used to carry its own fetchUsbStatusForCompliance
// and its own UsbStatusResponse, and the two implementations drifted: the SEBI copy grew a
// tolerant envelope parse (parseWsPayload, single-object wrapping, a loose String(command_key)
// compare, a non-string `output`) and then a bounded retry, while this copy stayed on the
// original strict parse. The drift is not cosmetic — org snapshot sebi_historical_compliance
// id=57 measured key 12 on 13 of 13 Windows hosts from the key-54 probe, and
// irdai_historical_compliance id=25, sweeping the SAME 13 hosts 216 seconds later, measured
// key 10 on 0 of 13 from the same probe. A clean 13-vs-0 is what a parse that fails
// identically on every host produces, not what a missing retry produces. Importing the one
// hardened helper removes the divergence surface permanently; cross-file imports are already
// the pattern here (fetchPowerShellOutputs above comes from certinComplianceChecks.ts).
import { fetchUsbStatusForCompliance, BASELINE_FRESHNESS_DAYS, ALERT_EVIDENCE_WINDOW_DAYS } from './utils/sebiComplianceChecks';
import {
  PieChart, Pie, Cell, Tooltip as RTooltip, Legend,
  LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer,
} from 'recharts';
import { PIE_COLORS, renderActiveShape, CustomTooltip } from '../../Compliance/shared/ComplianceChart';
import { fmtDate, fmtDateTime, fmtTime } from '../../Compliance/shared/complianceDateUtils';

import { csrfHeadersJson, fetchWithCsrf } from '../../../api/csrfClient';

import { LoadingScreen, DuoSpinner } from '@/components/ui/loading';
import { InfoTooltip } from './components/InfoTooltip';

interface IRDAIHotGuideline {
  label: string;
  tooltip: string;
}

interface ComplianceRecord {
  id: number;
  host_identifier: string;
  unixtime: number;
  compliance_data: Array<{ command_key: string; output: string }>;
}

interface NodesViewIRDAIHotComplianceProps {
  node: NodeData;
  wsConnected?: boolean;
  wsSendMessage?: (message: unknown) => Promise<unknown>;
  agentOnline?: boolean;
}

type ControlPassRate = {
  key: string;
  label: string;
  passRatePct: number | null;
  passHosts: number;
  failHosts: number;
  eligibleHosts: number;
};

type OrgSnapshot = {
  id: number;
  snapshot_at: number;
  total_nodes: number | null;
  windows_hosts: number | null;
  windows_with_results: number | null;
  fully_compliant_nodes: number | null;
  avg_compliance_percent: number | null;
  strong_count: number | null;
  moderate_count: number | null;
  needs_attention_count: number | null;
  control_pass_rates: ControlPassRate[];
  source: string;
  // Backend already selects and returns this column (irdai_compliance_snapshots.ts) — it was
  // simply untyped/unread here. Needed for orgSnapshotListReconciles below.
  fully_compliant_nodes_list?: string[] | null;
};

// OUT-OF-FRAMEWORK controls, removed 2026-09-07. Same rationale as the SEBI register: these two
// carried only "Vajra-authored mapping — not an IRDAI clause", i.e. no Annexure III clause requires
// them, so they were inflating this register's denominator.
//   '4'  Configuration changes tracked — no IRDAI clause (SEBI keeps its equivalent, control 5,
//        which cites PR.IP.S3/S4/S6).
//   '10' USB / removable media restricted — no IRDAI clause (SEBI keeps control 12, which cites
//        PR.DS.S1, PR.DS.S2, PR.IP.S14).
const HIDDEN_GUIDELINES = new Set([
  '4',
  '10',
  '25',
  '30'
]);


const IRDAI_HOT_GUIDELINES: Record<string, IRDAIHotGuideline> = {
  '1': { label: 'A complete inventory of installed software, libraries, and versions is maintained for this system.', tooltip: 'Annexure III: ID.AM 106, ID.AM 107, PR.IP 194' },
  // 2026-09-04: label narrowed to the hardware fields the Point 2 evaluator actually reads
  // (vendor, model, CPU, RAM, logical core count, OS name/build) — it never reads storage or
  // firmware, matching the identical fix already applied to SEBI key 3 for the same evaluator.
  '2': { label: 'A hardware asset inventory (vendor, model, CPU, RAM, core count) is maintained for this system.', tooltip: 'Annexure III: ID.AM 106' },
  // 2026-09-04: label narrowed from a retention claim. The Point 3 evaluator explicitly never
  // passes on retention — it stops at 'generation confirmed, retention period not measured'
  // even when every audit subcategory is On, because Vajra collects no Windows event-log
  // retention setting from any endpoint. Mirrors the identical fix already applied to SEBI key 4.
  '3': { label: 'Audit-log generation is enabled for authentication, access, privilege-change, and system-modification events.', tooltip: 'Annexure III: PR.AC 145, DE.CM 2, DE.CM 35' },
  '4': { label: 'Configuration changes to systems and software are tracked and logged.', tooltip: 'Vajra-authored mapping — not an IRDAI clause' },
  '5': { label: 'An EDR/anti-malware protection is installed and enabled on this system.', tooltip: 'Annexure III: PR.PT 214' },
  '6': { label: 'Strong password rules (minimum length, complexity, etc.) are configured on this system.', tooltip: 'Annexure III: PR.AC 149, PR.DS 173' },
  '7': { label: 'Only approved IP addresses and network ports are allowed through firewall policies.', tooltip: 'Annexure III: DE.CM 7, DE.CM 23' },
  '8': { label: 'This system is configured to block known malicious IP addresses and domains.', tooltip: 'Annexure III: DE.CM 23, DE.CM 76' },
  '9': { label: 'An EDR (Endpoint Detection & Response) solution is installed and actively running.', tooltip: 'Annexure III: PR.PT 214' },
  '10': { label: 'Access to USB drives and removable media is restricted.', tooltip: 'Vajra-authored mapping — not an IRDAI clause' },
  '11': { label: 'Unnecessary services, ports, protocols, and software are disabled on endpoints.', tooltip: 'Annexure III: PR.DS 170' },
  // 2026-09-04: label narrowed from firmware+software SLA claim. The Point 12 evaluator reads
  // only the latest Windows Update result and scores it against a 30-day recency threshold —
  // firmware/BIOS updates and general application software are never read by this control.
  '12': { label: 'Operating system patches are applied within a 30-day recency window.', tooltip: 'Annexure III: PR.MA 205, PR.MA 210' },
  // 2026-09-04: label narrowed from an 'unauthorized access attempts' claim. The Point 13
  // evaluator counts ANY Vajra-generated alert for the endpoint (malware detection, removable
  // media, process activity, patch actions) with no filter for access-attempt alerts — no
  // Windows Security event-log data reaches Vajra from any endpoint on this fleet, mirroring
  // the identical gap already documented and fixed for SEBI key 16.
  '13': { label: 'Automated alerts are generated by Vajra\'s detection pipeline for this system.', tooltip: 'Annexure III: DE.CM 5' },
  '14': { label: 'Critical systems are continuously monitored in real time for threats and incidents.', tooltip: 'Annexure III: ID.AM 105, DE.CM 84, DE.CM 2' },
  '15': { label: 'User logins and session activities are tracked to detect suspicious behavior.', tooltip: 'Annexure III: DE.CM 5, DE.CM 54' },
  '16': { label: 'The list of local user accounts and their privilege levels is regularly reviewed.', tooltip: 'Annexure III: PR.AC 151' },
  '17': { label: 'Default credentials for all system accounts are changed and strong passwords enforced.', tooltip: 'Annexure III: PR.AC 149' },
  // 2026-09-04: label narrowed from an 'is ... current' claim. The Point 18 evaluator only
  // checks that update-history records exist and are readable (a data-visibility check) — it
  // performs no recency measurement; that distinct measurement is control 12.
  '18': { label: 'The update and patch history of installed software is visible in Vajra.', tooltip: 'Annexure III: PR.MA 210' },
  '19': { label: 'All local firewall rules and status are collected and reviewed for unauthorized changes.', tooltip: 'Annexure III: DE.CM 7' },
  '20': { label: 'Endpoint antivirus/EDR client is installed and reporting healthy status.', tooltip: 'Annexure III: PR.PT 214' },
  '21': { label: 'Removable media (USB, external drives) usage logs are collected and reviewed.', tooltip: 'Annexure III: PR.DS 177, DE.CM 2' },
  '22': { label: 'All running processes and services are inventoried and checked for unauthorized software.', tooltip: 'Annexure III: DE.CM 9, PR.PT 217' },
  '23': { label: 'The system time is synchronized with a trusted NTP source.', tooltip: 'Annexure III: DE.CM 99' },
  '24': { label: 'Failed login attempts and account lockouts are logged and alerted.', tooltip: 'Annexure III: PR.AC 157, DE.CM 54' },
  '25': { label: 'All scheduled tasks and startup programs are reviewed for unauthorized entries.', tooltip: 'Annexure III: PR.IP 193, PR.IP 197' },
  '26': { label: 'The BIOS/firmware version and configuration are checked for compliance.', tooltip: 'Annexure III: PR.PT 216' },
  '27': { label: 'All installed applications are checked against an authorized software list.', tooltip: 'Annexure III: ID.AM 107, PR.IP 193' },
  '28': { label: 'The system is isolated from the network when a major threat is detected.', tooltip: 'Annexure III: ID.AM 111, RS.MI 238' },
  '29': { label: 'Audit logs are protected from unauthorized modification or deletion.', tooltip: 'Vajra-authored mapping — not an IRDAI clause' },
  '30': { label: 'A process exists to restore system state from backup in case of incident.', tooltip: 'Annexure III: RS.RP 241' },
  // 2026-09-07: added. This register previously had no data-at-rest control of any kind while
  // the SEBI register measured the same hosts' BitLocker state on two controls (26 and 34), so
  // an IRDAI reader could not tell that Vajra holds the evidence. Mapped to PR.DS, the
  // data-security family already cited by keys 6, 11 and 21 — see the evaluator's WHY-comment.
  // The label names protection, not percentage encrypted, because that is what is measured.
  '31': { label: 'Endpoint storage volumes are encrypted at rest with protection active.', tooltip: 'Annexure III: PR.DS 170, PR.DS 177' },
};

// IRDAI_HOT_REASON_DETAIL — static fallback description shown in the guideline-column
// InfoTooltip when this run has not yet produced a live per-run `reason` for a control
// (no compliance sweep this session, or a sweep that did not resolve this particular key).
// The live `reason` computed in staticComplianceChecks is always preferred when present —
// it names this run's actual finding — this is only the "nothing fresher available yet"
// fallback, added so the tooltip is never empty. Mirrors constants/sebiHotGuidelines.ts's
// SEBI_HOT_REASON_DETAIL: one entry per key in IRDAI_HOT_COMMAND_KEYS, each read against
// the live evaluator branch(es) for that key in staticComplianceChecks below, each ending
// with a concrete "To become compliant" line grounded in what that evaluator actually
// measures today. Keys hidden or structurally unmeasurable (HIDDEN_GUIDELINES,
// STRUCTURALLY_UNMEASURABLE_IRDAI_KEYS below) are never rendered, so they have no entry.
const IRDAI_HOT_REASON_DETAIL: Record<string, { reason: string; detail: string }> = {
  '1': {
    reason: 'Software Asset Inventory checks whether Vajra has read back at least one installed Windows program (or deb/rpm package on Linux) for this host. Vajra automatically collects this list and it enables SBOM generation and vulnerability cross-referencing, but Vajra holds no organisation-approved software baseline, so it cannot itself judge whether the installed software is authorised — that comparison is control 27, which has no baseline to compare against either. There is no failing state for this control: an inventory that came back empty is recorded as not assessed, not as evidence that no software is installed. To become compliant: keep the Vajra Agent installed and reporting on this host — the installed-programs list is read on every sweep, so any host with a live agent normally satisfies this control automatically.',
    detail: 'Passes once ≥1 installed program/package is read back for this host; empty results are not assessed, never scored as failing.'
  },
  '2': {
    reason: 'Hardware Asset Inventory checks whether Vajra has read back at least 3 of the 5 fields it collects for this host: hardware vendor, hardware model, CPU type, physical memory, and OS name. It does not read storage, network-interface hardware, firmware/serial-number data, or compare successive snapshots for hardware changes — this is a current-value record, not a change-detection control. There is no failing state: fewer than 3 fields read back is recorded as not assessed, not as evidence that no inventory is maintained. To become compliant: keep the Vajra Agent installed and reporting on this host — these fields come from the same OS/hardware inventory probe as control 1, so a live, reporting agent normally satisfies this control automatically.',
    detail: 'Passes once ≥3 of vendor/model/CPU/RAM/OS-name are read back; fewer is not assessed, never scored as failing.'
  },
  '3': {
    reason: 'Audit-Log Generation checks 7 Windows advanced-audit-policy subcategories behind the four named log families (Special Logon, Credential Validation, Security Group Management, User Account Management, Plug and Play Events, Logon, Security System Extension) — whether the events that WOULD populate those logs are being written at all. It does not, and structurally cannot, measure the 180-day retention Annexure III PR.AC 145 actually asks for: Vajra collects no Windows event-log maximum-size or retention setting from any endpoint. So even a host with all 7 subcategories On stops at "generation confirmed, retention not measured" — not a pass. To clear the current FAIL: enable Success and Failure auditing for every subcategory reported Off, via Local Security Policy (secpol.msc → Advanced Audit Policy Configuration) or the equivalent GPO, or `auditpol /set /subcategory:"<name>" /success:enable /failure:enable`. Be aware this only reaches the best available state, "not assessed" — a full "passed" badge is not architecturally available for this control until Vajra also collects the endpoint\'s log retention/max-size setting.',
    detail: 'Off subcategories fail outright; all-On stops at "generation confirmed, retention not measured" — never a full pass.'
  },
  '4': {
    reason: 'Configuration-Change Tracking is measured on 3 Windows advanced-audit-policy subcategories that record a change as it happens: Process Creation (the act of running the tool that made the change), command-line capture in process-creation events (which command made it), and Security System Extension (service/driver/security-package installation). Unlike control 3, a genuine pass exists here, because these three settings ARE the tracking this control asks for, not logs whose retention is separately unmeasured. To become compliant: enable Success (and Failure, for Process Creation) auditing for any of the three reported Off, via Local Security Policy (secpol.msc → Advanced Audit Policy Configuration → Detailed Tracking → Process Creation; System → Security System Extension), and separately enable "Include command line in process creation events" under Administrative Templates → System → Audit Process Creation (registry value ProcessCreationIncludeCmdLine_Enabled = 1) — auditing Process Creation alone does not capture the command line without this second setting.',
    detail: 'Passes only when Process Creation, command-line capture, and Security System Extension auditing are all On.'
  },
  '5': {
    reason: 'Anti-Malware Protection Enabled is measured on whether the Vajra Agent — the EDR/anti-malware layer itself — has checked in within Vajra\'s 24-hour agent freshness window (a Vajra platform default, not an IRDAI-mandated interval), or, failing that, whether Windows Security Center reports a third-party antivirus/EDR product in state On. Vajra additionally offers IP/port blocking and USB/Bluetooth lockdown capabilities, but whether those specific containment mechanisms are configured and active on this node is not measured by this control. There is no failing state: when neither signal is available the control is not assessed, since Vajra cannot distinguish a stopped agent from a powered-off host. To become compliant: keep the Vajra Agent running and checking in within the 24-hour window, or ensure a third-party AV/EDR product Windows Security Center reports is turned On.',
    detail: 'Passes on Agent check-in within 24h OR a Security Center product On; neither → not assessed, never a hard fail.'
  },
  '6': {
    reason: 'Strong Password Rules are measured against Vajra\'s own baseline (minimum length ≥ 8 characters, complexity enabled, password history ≥ 1) — the 8-character floor is a Vajra platform default drawn from common CIS/ISO practice, not a length IRDAI Annexure III PR.AC 149 itself specifies. The values come from two independent probes (the secedit-derived security policy and the `net accounts` baseline) so a measured violation is corroborated, not a parsing artefact. To become compliant: set the minimum password length to at least 8, enable password-complexity requirements, and set password history to at least 1, via Local Security Policy (secpol.msc → Account Policies → Password Policy) or the equivalent GPO — clearing every violation named in this run\'s finding above is what turns this control to a pass.',
    detail: 'Fails on any of: min length < 8, complexity disabled, or history 0; passes only when length/complexity/history are all measured and clean.'
  },
  '7': {
    reason: 'IP and Port Access Controls checks every enabled INBOUND ALLOW rule in this node\'s Windows Firewall for whether its remote address is scoped to specific IPs/subnets, or left as "*"/"Any" (unscoped — admits traffic from anywhere). Vajra holds no organisation-approved address list, so it cannot verify the specific addresses allowed are the right ones — it measures whether the rules are scoped at all. This control is ported directly from the identically-worded SEBI firewall control (SEBI point 8), so both read the same wildcard-scope logic and must not drift apart. To become compliant: review every enabled inbound Allow rule (Windows Defender Firewall with Advanced Security) and set its Remote address to specific IPs/subnets instead of Any. Note that a stock, unmodified Windows install ships several wildcard inbound Allow rules by default (mDNS, network discovery, delivery optimization) — those need to be re-scoped or disabled too, not just custom rules you added yourself. Vajra does not enforce or modify firewall rules; it only reports what it finds.',
    detail: 'Fails on any enabled inbound Allow rule with an unscoped ("Any") remote address; passes when all are IP/subnet-scoped.'
  },
  '9': {
    reason: 'EDR Installed and Actively Running reads the identical evidence as control 5 (Vajra Agent check-in within the 24-hour freshness window, or a Windows Security Center product in state On) but states the verdict in its own words and is scored independently rather than by copying control 5\'s result. There is no failing state — an agent that has not been seen this run is not assessed, not scored as absent, since Vajra cannot tell a stopped agent from a powered-off host. To become compliant: keep the Vajra Agent running and checking in within the 24-hour window (a Vajra platform default), or ensure a third-party AV/EDR product Windows Security Center reports is turned On.',
    detail: 'Passes on Agent check-in within 24h OR a Security Center product On; neither → not assessed, never a hard fail.'
  },
  '10': {
    reason: 'Removable Media Access Restriction is measured with a live websocket query of the endpoint\'s USB storage policy at assessment time. It passes when that policy reports removable storage as Disabled/blocked, and fails when it reports Enabled — a response that returns neither state, or no response at all, is not assessed rather than scored either way. To become compliant: disable USB mass storage on this endpoint, e.g. via Group Policy (Computer Configuration → Administrative Templates → System → Removable Storage Access → "All Removable Storage classes: Deny all access") or by setting the registry value HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Start to 4.',
    detail: 'Passes only when the live USB policy query reports storage Disabled/blocked; Enabled fails; no usable response is not assessed.'
  },
  '12': {
    reason: 'Patch Recency reads the latest Windows Update result for this host and checks two things: that it succeeded, and that it was installed within 30 days — a Vajra platform default recency window, not a figure IRDAI Annexure III PR.MA 205/210 itself specifies. A failed update, or one older than 30 days, fails the control; no usable update result at all is not assessed. To become compliant: install pending Windows Updates on this host so the most recent update succeeds and lands within Vajra\'s 30-day recency window.',
    detail: 'Fails when the latest update failed or is >30 days old; no usable update result is not assessed, never a silent pass.'
  },
  '13': {
    reason: 'Automated Alert Generation checks whether Vajra\'s detection pipeline raised at least one alert FOR THIS ENDPOINT in the last 90 days — direct, endpoint-scoped evidence that automated detection produced a record here. It is deliberately asymmetric: silence is never scored as a failure, because Vajra cannot distinguish an endpoint with nothing to alert on from one where alerting is not reaching it, so zero alerts in the window is recorded as not assessed. There is no direct configuration change that forces this control to pass: it becomes compliant only when the detection pipeline actually raises an alert for this endpoint, so the most useful action is keeping the Vajra Agent live so any alert Vajra does generate for this host reaches the platform and is recorded against it.',
    detail: 'Passes only on ≥1 alert for this endpoint in the last 90 days; zero alerts is not assessed, never scored as a failure.'
  },
  '14': {
    reason: 'Continuous Monitoring of Critical Systems only resolves for a node explicitly marked critical in Vajra — a node not marked critical is not assessed by this control at all, since the control is specifically about how critical systems are monitored. For a critical node, the verdict is the Vajra Agent\'s own check-in: live within Vajra\'s 24-hour freshness window is a pass, and a stale or absent check-in is a fail. To become compliant: mark this node Critical in Vajra (node settings) if it handles sensitive data or an essential business function, and keep its Agent checking in within the 24-hour window.',
    detail: 'Non-critical nodes are not assessed; critical nodes pass only with an agent check-in inside the 24-hour freshness window.'
  },
  '15': {
    reason: 'User Login and Session Tracking is measured on the Logon advanced-audit-policy subcategory, which records interactive, network and remote logon and logoff events to the Security log. Special Logon and Credential Validation are reported alongside it as coverage detail, not as part of the pass/fail verdict. To become compliant: enable Success and Failure auditing for the Logon subcategory, via Local Security Policy (secpol.msc → Advanced Audit Policy Configuration → Logon/Logoff → Logon) or the equivalent GPO.',
    detail: 'Fails when Logon auditing is Off; passes when it is On; an unread probe is not assessed.'
  },
  '17': {
    reason: 'Default Credentials Changed / Strong Passwords Enforced is a two-limb control, and Vajra only measures one of them. The enforcement limb — minimum password length, complexity, and password history, read from the endpoint\'s security policy — is fully measured, and a violation there fails the control outright. The default-credential limb (whether every system account\'s password was actually changed from its default) is NOT measured: no per-account credential or password-age data exists anywhere in the schema, so a fully-enforced policy still stops at not assessed rather than a pass. To clear the current FAIL: fix every measured enforcement violation (minimum length ≥ 8 — a Vajra baseline, not an IRDAI-specified figure — complexity enabled, password history ≥ 1) via Local Security Policy (secpol.msc → Account Policies → Password Policy). Be aware this only reaches "not assessed", the best available state — a full "passed" badge is not architecturally available for this control until Vajra also collects per-account credential/password-age evidence for the default-credential limb.',
    detail: 'Enforcement violation fails outright; enforcement satisfied stops at "default credentials not measured" — never a full pass.'
  },
  '18': {
    reason: 'Update/Patch History Visibility checks only that Vajra can fetch at least one update-history record for this host — a data-visibility check, not a recency measurement (that is control 12). There is no failing state: a fetch that returns zero records, or fails outright, is not assessed rather than scored as non-compliant, since an empty or failed read is not evidence that no update history exists. To become compliant: keep the Vajra Agent installed and reporting on this host so the update-history endpoint has records to return — any host with a working agent and at least one recorded update normally satisfies this control automatically.',
    detail: 'Passes once ≥1 update-history record is fetched; empty or failed fetches are not assessed, never scored as failing.'
  },
  '20': {
    reason: 'Endpoint AV/EDR Healthy Status is decided first on signature currency — a stale-definitions signal overrides everything else, because agent liveness or a Security Center "On" state both speak to "installed and running" (control 9), not to "reporting healthy status". A product is unhealthy if Windows Security Center itself reports its signatures out of date, OR if live Defender telemetry shows the definition date is older than Vajra\'s 7-day currency bound (a Vajra platform default) even while Security Center still reports it current. Only once no staleness is found does agent liveness or a Security Center "On" product decide the pass. To become compliant: update antivirus/EDR signatures on this host (for Windows Defender: Windows Security → Virus & threat protection → Check for updates, or ensure automatic definition updates are enabled) so the reported and actual definition dates are both within the 7-day currency window.',
    detail: 'Stale signatures (Security Center OR live Defender telemetry >7 days) fail outright; otherwise passes on Agent/Security Center liveness.'
  },
  '21': {
    reason: 'Removable-Media Usage Logging is measured on the Plug and Play Events advanced-audit-policy subcategory, which is what makes Windows write a Security-log event when removable media is attached. It is a distinct question from control 10 (whether USB storage is restricted) and does not reuse that verdict. Reviewing those logged events remains the operator\'s task — Vajra collecting the telemetry does not by itself discharge the review half of this control. To become compliant: enable auditing for the Plug and Play Events subcategory, via Local Security Policy (secpol.msc → Advanced Audit Policy Configuration → Detailed Tracking → Plug and Play Events) or the equivalent GPO.',
    detail: 'Fails when Plug and Play Events auditing is Off; passes when it is On; an unread probe is not assessed.'
  },
  '24': {
    reason: 'Failed Login Attempts and Account Lockouts Logged and Alerted is a two-limb control, and Vajra only measures the logging limb — the "alerted" limb is not measured, since Vajra collects no endpoint alert-rule configuration for these events. The logging limb is read from 3 advanced-audit-policy subcategories: Account Lockout (the lockout event itself), Credential Validation (failed authentication), and Logon (failed interactive/network logons); any of the three reported Off fails the control outright. All three On satisfies the logging limb but the control still stops at not assessed, since alerting is architecturally unmeasured. To clear the current FAIL: enable Success and Failure auditing for every subcategory reported Off — Account Lockout, Credential Validation, and Logon — via Local Security Policy (secpol.msc → Advanced Audit Policy Configuration → Logon/Logoff → Account Lockout / Logon; Account Logon → Credential Validation). Be aware this only reaches "not assessed", the best available state — a full "passed" badge is not architecturally available for this control until Vajra also collects the endpoint\'s alert-rule configuration for the "alerted" limb.',
    detail: 'Any Off subcategory fails outright; all-On stops at "logging confirmed, alerting not measured" — never a full pass.'
  },
  '26': {
    reason: 'BIOS/Firmware Configuration Compliance is measured on UEFI Secure Boot state alone — read from the secureboot table first, falling back to the Confirm-SecureBootUEFI baseline probe when that is unavailable. Secure Boot enabled is a pass and disabled is a fail; a BIOS version string is collected and reported as detail only, since Vajra holds no vendor firmware baseline to compare a version number against — general firmware/BIOS "configuration compliance" beyond Secure Boot is not measured. To become compliant: enable UEFI Secure Boot in this system\'s firmware/BIOS settings.',
    detail: 'Fails when UEFI Secure Boot is disabled; passes when enabled; an unreadable state is not assessed. BIOS version is reported, not scored.'
  },
  '31': {
    reason: 'Encryption of Data at Rest is measured from the BitLocker volume records Vajra collects for this host. It passes only when EVERY volume reports protection status Protected together with conversion status Fully Encrypted. Reporting 100% encrypted is deliberately NOT accepted on its own: a volume whose BitLocker protection is suspended still reports 100% encrypted while its volume master key sits unprotected on disk — the state Windows enters across firmware updates — so protection has to be active, not merely conversion complete. A volume never encrypted, one encrypted with protection off, and one still converting all fail; a volume whose protection/conversion status cannot be decoded, and a host with no BitLocker records at all, are not assessed rather than failed. No minimum encryption algorithm is applied, because IRDAI Annexure III publishes none — the encryption method is reported as an observed value only. To become compliant: turn BitLocker on for every volume reported as never encrypted, and where a volume is 100% encrypted with protection off, resume protection (manage-bde -protectors -enable <drive>) so the master key is no longer readable from disk. This control reads the same BitLocker rows as the identically-reasoned SEBI control 26, so the two registers must not drift apart.',
    detail: 'Passes only when every volume is protection-on AND fully encrypted; 100% encrypted with protection suspended fails; undecodable or absent records are not assessed.'
  },
};

// STRUCTURALLY_UNMEASURABLE_IRDAI_KEYS — Class A controls, confirmed by the 2026-09-03
// live-sweep verification pass (see the compliance-controls-removal task doctrine).
//
// Class A vs Class B distinction:
//   Class A = STRUCTURALLY UNMEASURABLE. Every code path for this key in
//     staticComplianceChecks (below) resolves unconditionally to assessed:false — there is
//     no branch, on any host, on any run, that can ever produce a measured pass or fail,
//     because no evidence source exists for it. This is the removal-candidate set.
//   Class B = TRANSIENTLY UNASSESSED ON SOME HOSTS. The evaluator has a real, reachable
//     pass/fail branch and does produce measured verdicts on most swept hosts; a control
//     rendering "not assessed" for some or even all hosts on ONE sweep is NOT evidence of
//     Class A — that determination must come from the evaluator code, never from a single
//     run's numbers.
//
// This set was derived by reading every branch of every key in staticComplianceChecks and
// cross-checking against the live fleet DB (irdai_historical_compliance) on 2026-09-03.
// Keys 25/30 are deliberately excluded here even though they never render a measured
// verdict either: they are already invisible to the UI via HIDDEN_GUIDELINES above (a
// separate, pre-existing "hidden/dead evaluator" bucket), so they are not valid inputs to
// this Class A/B distinction. Key 14 ("critical systems continuously monitored") and key 26
// ("BIOS/firmware/Secure Boot configuration") were checked and confirmed to have real,
// reachable, currently-firing pass/fail branches — they are Class B, not included here.
//
// 2026-09-04: key 7 ("only approved IP addresses and network ports are allowed") reclassified
// out of this set to Class B. Its evaluator previously stopped after fetching
// windows_firewall_rules with every branch unconditionally assessed:false, even though SEBI
// control 8 — byte-identical wording, the same underlying data — already measures real
// pass/fail verdicts from the same rows via wildcard-scope analysis. Point 7 now uses that
// same logic (ported from sebiComplianceChecks.ts checks['8']); see the WHY-comment at its
// definition above.
//
// Consumers (UI table + PDF/report generation) should filter rendered/exported rows against
// this set so both surfaces drop the same controls in lockstep.
const STRUCTURALLY_UNMEASURABLE_IRDAI_KEYS: ReadonlySet<string> = new Set([
  '8',
  '11',
  '16',
  '19',
  '22',
  '23',
  '27',
  '28',
  '29',
]);

const IRDAI_HOT_COMMAND_KEYS = Object.keys(IRDAI_HOT_GUIDELINES).filter(
  (key) => !HIDDEN_GUIDELINES.has(key) && !STRUCTURALLY_UNMEASURABLE_IRDAI_KEYS.has(key)
);

// IRDAI_LEGACY_IMPOSSIBLE_PASS_KEYS — controls whose CURRENT staticComplianceChecks
// evaluator has no branch, on any host or run, that sets compliant:true (unlike
// STRUCTURALLY_UNMEASURABLE_IRDAI_KEYS above, these are still real, currently-rendered,
// Class B controls — they just cannot currently be satisfied). Point 3 ("audit logs
// retained") stops at generation-confirmed/not-assessed because the retention PERIOD is
// unmeasured; point 17 ("default credentials changed") stops at
// enforcement-satisfied/not-assessed because the default-credential limb is unmeasured;
// point 24 ("failed logins logged and alerted") stops at logging-confirmed/not-assessed
// because the alerting limb is unmeasured. See the `checks['3']`, `checks['17']` and
// `checks['24']` assignments below — grep confirms exactly one compliant:true-capable
// branch each, and none of the three has it.
//
// A row written by an OLDER version of this evaluator (before the retention/
// default-credential/alerting limb was added and tightened to a hard not-assessed) can
// still carry a stored 'true' for one of these keys. The per-node restore-from-history
// effect below must not replay such a row as a live "Passed" badge — that would
// misrepresent scoring rules that no longer exist as a current measured pass. This is a
// stopgap keyed on the literal control number rather than a proper scoring-logic version
// stamp persisted alongside each snapshot; add a key here whenever a future evaluator
// change removes the last compliant:true branch for a control, so old rows can't leak
// through the restore path.
const IRDAI_LEGACY_IMPOSSIBLE_PASS_KEYS: ReadonlySet<string> = new Set(['3', '17', '24']);

// Pass / fail / not-assessed, in the order the per-node score donut lists them.
// PIE_COLORS only carries two entries, so the neutral third slice is defined here
// rather than wrapping around to the green pass colour.
const SCORE_PIE_COLORS = [PIE_COLORS[0], PIE_COLORS[1], '#94a3b8'];

/**
 * How old the stored Windows baseline probe row (fleet.compliance_results) may be and
 * still describe the endpoint. A Vajra platform default, not an IRDAI-mandated interval:
 * the probes read static machine policy, which changes rarely, so a quarter-old row is
 * still evidence. Beyond it the row is treated as absent — not as a failure. Reads
 * BASELINE_FRESHNESS_DAYS from sebiComplianceChecks.ts rather than a second copy of the
 * same number, so CERT-In, SEBI and IRDAI can't drift apart.
 */
const IRDAI_BASELINE_FRESHNESS_DAYS = BASELINE_FRESHNESS_DAYS;

/**
 * Minimum password length Vajra scores against. A Vajra platform baseline (the common
 * CIS/ISO floor), not an IRDAI-mandated number: Annexure III PR.AC 149 requires a strong
 * password policy without naming a length.
 */
const IRDAI_MIN_PASSWORD_LENGTH = 8;

/**
 * Window over which a detection raised for this endpoint counts as alerting evidence.
 * Reads ALERT_EVIDENCE_WINDOW_DAYS from sebiComplianceChecks.ts rather than a second
 * copy of the same number, so CERT-In, SEBI and IRDAI can't drift apart.
 */
const IRDAI_ALERT_EVIDENCE_WINDOW_DAYS = ALERT_EVIDENCE_WINDOW_DAYS;
/** One page of device alerts is enough to evidence alerting; the backend caps at 500. */
const IRDAI_ALERT_EVIDENCE_PAGE_ROWS = 200;

/** Window the firewall rule-change review is performed over. */
const IRDAI_FIREWALL_REVIEW_WINDOW_DAYS = 30;

/**
 * What each collected Windows baseline probe key reports on. Names are kept identical to
 * COMPLIANCE_CONTROL_LABELS in features/Compliance/utils/complianceHelpers.ts so the same
 * setting is called the same thing wherever it is shown.
 */
const AUDIT_SUBCATEGORY: Record<string, string> = {
  '5': 'Special Logon',
  '6': 'Credential Validation',
  '9': 'Security Group Management',
  '10': 'User Account Management',
  '11': 'Process Creation',
  '12': 'Plug and Play Events',
  '13': 'Account Lockout',
  '14': 'Logon',
  '16': 'Security System Extension',
  '17': 'command-line capture in process-creation events',
};

const auditNames = (keys: string[]) =>
  keys.map((key) => AUDIT_SUBCATEGORY[key] ?? `audit subcategory ${key}`).join(', ');

/**
 * Fleet node list (`GET /api/nodes/list`), shared across the hosts of one sweep.
 *
 * It is the only endpoint that returns `critical`: /nodes/identifiers and
 * /nodes/details/{host} both select it away, so without this list the critical-system
 * control has no designation to read and can only ever be not-assessed. The payload is
 * fleet-wide, so it is cached for a window short enough to span a single sweep and no
 * longer. A failed or unparseable response resolves to null — never to an empty fleet —
 * so the dependent control stays not-assessed instead of being scored against a
 * fabricated absence. Mirrors fetchFleetNodes() in utils/sebiComplianceChecks.ts.
 */
const FLEET_NODES_TTL_MS = 30_000;
/** Matches backend PAGINATION_MAX_ROWS_NODES; the endpoint clamps to it anyway. */
const FLEET_NODES_MAX_ROWS = 1000;

let fleetNodesCache: { at: number; nodes: Array<Record<string, unknown>> } | null = null;
let fleetNodesInFlight: Promise<Array<Record<string, unknown>> | null> | null = null;

async function fetchFleetNodes(): Promise<Array<Record<string, unknown>> | null> {
  if (fleetNodesCache && Date.now() - fleetNodesCache.at < FLEET_NODES_TTL_MS) {
    return fleetNodesCache.nodes;
  }
  if (fleetNodesInFlight) return fleetNodesInFlight;

  fleetNodesInFlight = (async () => {
    try {
      const res = await api.get(`${NODES_URLS.NODES_LIST}?rows=${FLEET_NODES_MAX_ROWS}`);
      const json = res.data;
      const arr: Array<Record<string, unknown>> | null = Array.isArray(json?.nodes)
        ? json.nodes
        : Array.isArray(json?.data)
          ? json.data
          : Array.isArray(json)
            ? json
            : null;
      if (!arr) return null;
      fleetNodesCache = { at: Date.now(), nodes: arr };
      return arr;
    } catch {
      return null;
    } finally {
      fleetNodesInFlight = null;
    }
  })();

  return fleetNodesInFlight;
}

interface StaticCheckResult {
  compliant: boolean;
  reason: string;
  detail?: string;
  fraction?: { value: number; total: number; label: string };
  /**
   * Present (and false) only for controls that were NOT measured on this endpoint.
   * `compliant` is then a fail-safe placeholder, never a measured verdict, so a
   * capability statement is not reported as a pass. Identical in shape and meaning
   * to StaticCheckResult in utils/sebiComplianceChecks.ts and
   * utils/certinComplianceChecks.ts, so all three registers describe the
   * not-assessed state the same way.
   */
  assessed?: false;
}

/** The control was not measured on this endpoint: neither a pass nor a fail. */
const isNotAssessed = (result?: StaticCheckResult): boolean =>
  !!result && result.assessed === false;

/** A measured pass. Never true for an unmeasured control. */
const isPass = (result?: StaticCheckResult): boolean =>
  !!result && result.assessed !== false && result.compliant === true;

/** A measured fail. Never true for an unmeasured control. */
const isFail = (result?: StaticCheckResult): boolean =>
  !!result && result.assessed !== false && result.compliant === false;

/**
 * Row verdicts rendered in the status column. Kept aligned with the VERDICT_*
 * maps in NodesViewSebiHotCompliance.tsx so the three registers name the same
 * state the same way.
 *
 * 'not_run'      — no compliance sweep has been performed on this host yet.
 * 'not_assessed' — a sweep ran, but this control could not be measured.
 */
type RowVerdict = 'satisfied' | 'partial' | 'non_compliant' | 'not_assessed' | 'not_run';

const VERDICT_BADGE_CLASS: Record<RowVerdict, string> = {
  satisfied: 'bg-green-100 text-green-700 border border-green-200',
  partial: 'bg-amber-100 text-amber-700 border border-amber-200',
  non_compliant: 'bg-red-100 text-red-700 border border-red-200',
  not_assessed: 'bg-slate-100 text-slate-600 border border-slate-200',
  not_run: 'bg-slate-100 text-slate-500 border border-slate-200',
};

const VERDICT_ICON_CLASS: Record<RowVerdict, string> = {
  satisfied: 'fa-check',
  partial: 'fa-circle-half-stroke',
  non_compliant: 'fa-xmark',
  not_assessed: 'fa-circle-minus',
  not_run: 'fa-hourglass-half',
};

const VERDICT_LABEL: Record<RowVerdict, string> = {
  satisfied: 'Passed',
  partial: 'Partially Compliant',
  non_compliant: 'Failed',
  not_assessed: 'Not assessed',
  not_run: 'Not run yet',
};

/** Sub-line shown under the two neutral badges so they cannot be confused. */
const VERDICT_HINT: Partial<Record<RowVerdict, string>> = {
  not_assessed: 'A compliance run completed — this control could not be measured',
  not_run: 'No compliance run has been performed on this host yet',
};

interface FleetPointStat {
  /** Hosts that were assessed for this control AND passed it. */
  passed: number;
  /** Hosts that were actually assessed for this control (the denominator). */
  total: number;
  /**
   * Hosts that produced results but on which this control could not be measured.
   * They sit outside passed/total and are surfaced on their own, so the operator can
   * see how many endpoints the fraction leaves out. Identical in name and meaning to
   * FleetPointStat.notAssessed in NodesViewSebiHotCompliance.tsx.
   */
  notAssessed?: number;
}

async function staticComplianceChecks(
  hostId: string,
  node: NodeData,
  wsConnected = false,
  wsSendMessage?: (message: unknown) => Promise<unknown>,
): Promise<Record<string, StaticCheckResult | undefined>> {
  const checks: Record<string, StaticCheckResult | undefined> = {};

          // ---- Shared measured evidence, read once per host ----------------------
          //
          // Every control below is decided on endpoint state Vajra actually holds. Each
          // source resolves to null when it is absent, errored or unparseable, and every
          // predicate that reads it then returns not-assessed: a source that could not be
          // read is never turned into a failure.

          /**
           * Latest Windows baseline probe row for this host
           * (GET /api/nodes/compliance/latest/:host_identifier → fleet.compliance_results).
           *
           * It carries the `auditpol` advanced-audit-policy subcategories, the
           * Confirm-SecureBootUEFI result and the `net accounts` minimum password length
           * measured on the endpoint itself. A missing row, a non-array payload or a row
           * older than IRDAI_BASELINE_FRESHNESS_DAYS resolves to null.
           */
          const baseline = await (async () => {
            try {
              const res = await api.get(`${NODES_URLS.COMPLIANCE_LATEST}${encodeURIComponent(hostId)}`);
              const row = (res.data?.data ?? null) as { unixtime?: number | string; compliance_data?: unknown } | null;
              if (!row || !Array.isArray(row.compliance_data)) return null;
              const byKey: Record<string, string> = {};
              (row.compliance_data as Array<Record<string, unknown>>).forEach((item) => {
                if (!item || typeof item !== 'object') return;
                const key = String(item.command_key ?? '').trim();
                if (key.length === 0) return;
                byKey[key] = String(item.output ?? '').trim();
              });
              const takenSec = Number(row.unixtime);
              const collectedAt = Number.isFinite(takenSec) && takenSec > 0 ? takenSec : null;
              const ageDays = collectedAt !== null ? (Date.now() / 1000 - collectedAt) / 86400 : null;
              if (ageDays !== null && ageDays > IRDAI_BASELINE_FRESHNESS_DAYS) return null;
              return { byKey, collectedAt };
            } catch {
              return null;
            }
          })();

          /**
           * State of one baseline probe. Only the literal 'True' and 'False' the probe
           * writes are measured values; a key that is absent, empty (the shape a failed
           * probe takes) or unrecognised is indeterminate and can never produce a failure.
           */
          type ProbeState = 'on' | 'off' | 'indeterminate';
          const probe = (key: string): ProbeState => {
            const raw = baseline?.byKey[key];
            if (raw === undefined) return 'indeterminate';
            const value = raw.toLowerCase();
            if (value === 'true') return 'on';
            if (value === 'false') return 'off';
            return 'indeterminate';
          };
          const describeProbe = (key: string) => {
            const state = probe(key);
            return `${AUDIT_SUBCATEGORY[key] ?? `subcategory ${key}`} auditing ${state === 'on' ? 'is On' : state === 'off' ? 'is Off' : 'was not measured'}`;
          };
          const baselineTakenText = baseline?.collectedAt
            ? ` (Windows baseline collected ${fmtDateTime(baseline.collectedAt)})`
            : '';

          /**
           * Latest secedit-derived security policy row for this host
           * (POST /api/windows/profile_info → fleet.security_profile_info), read once and
           * shared by the password, default-credential and lockout controls. `fetched`
           * distinguishes "the endpoint has no policy row" from "the request failed", so
           * the reasons below can say which happened.
           */
          const securityProfile = await (async () => {
            try {
              const res = await nodesViewApi.getSecurityProfileInfo(hostId);
              const rows = res.data?.status === 'Success' && Array.isArray(res.data.data) ? res.data.data : [];
              const row = rows.length > 0 && rows[0] && typeof rows[0] === 'object'
                ? rows[0] as Record<string, unknown>
                : null;
              return { fetched: true, row };
            } catch {
              return { fetched: false, row: null as Record<string, unknown> | null };
            }
          })();

          /** A measured integer policy column, or null when it is absent or unparseable. */
          const profileInt = (column: string): number | null => {
            const raw = securityProfile.row?.[column];
            if (raw === null || raw === undefined || raw === '') return null;
            const value = Number(raw);
            return Number.isFinite(value) ? value : null;
          };

          /**
           * Detections raised for THIS endpoint (POST /api/alerts/list/device). One page is
           * enough: the control only needs evidence that the detection pipeline produced
           * alerts for this host, and the page is read newest-first.
           */
          const alertEvidence = await (async () => {
            try {
              const res = await api.post(`${ALERTS_URLS.ALERTS_LIST}/device`, {
                host_identifier: hostId,
                rows: IRDAI_ALERT_EVIDENCE_PAGE_ROWS,
                pageno: 1,
              });
              const payload = res.data as { success?: boolean; alerts?: unknown } | null;
              if (!payload?.success || !Array.isArray(payload.alerts)) return null;
              const rows = payload.alerts as Array<Record<string, unknown>>;
              const cutoff = Date.now() / 1000 - IRDAI_ALERT_EVIDENCE_WINDOW_DAYS * 86400;
              const times = rows
                .map((row) => Number(row?.unixtime))
                .filter((value) => Number.isFinite(value) && value > 0);
              const inWindow = times.filter((value) => value >= cutoff);
              return {
                inWindow: inWindow.length,
                newestSec: times.length > 0 ? Math.max(...times) : null,
                truncated: rows.length >= IRDAI_ALERT_EVIDENCE_PAGE_ROWS && inWindow.length === rows.length,
              };
            } catch {
              return null;
            }
          })();

          /**
           * This node's row in the fleet list — the only source that carries the `critical`
           * designation the critical-systems control is about.
           */
          const fleetNodeRow = await (async () => {
            const nodes = await fetchFleetNodes();
            if (!nodes) return null;
            return nodes.find((n) => String(n?.host_identifier ?? '').trim() === hostId) ?? null;
          })();

          // Point 1: Software inventory (per-host)
          // The measured count is kept so point 27 can state the size of the inventory it
          // has no authorised list to compare against, instead of describing it vaguely.
          let installedProgramCount: number | null = null;
          try {
            const res = await nodesViewApi.getProgramsList(hostId, node.os_name ?? node.os_platform);
            const data = (res.data ?? {}) as { programs?: unknown[]; deb?: unknown[]; rpm?: unknown[] };
            const isWindows = /windows/i.test(String(node.os_name ?? node.os_platform ?? ''));
            const winCount = Array.isArray(data.programs) ? data.programs.length : 0;
            const debCount = Array.isArray(data.deb) ? data.deb.length : 0;
            const rpmCount = Array.isArray(data.rpm) ? data.rpm.length : 0;
            const packageCount = isWindows ? winCount : debCount + rpmCount;
            const pkgLabel = isWindows ? 'program' : 'package';
            installedProgramCount = packageCount;

            checks['1'] = packageCount > 0
              ? {
                  compliant: true,
                  reason: `Software inventory is present: ${packageCount} installed ${pkgLabel}${packageCount !== 1 ? 's' : ''} recorded for this node, enabling SBOM and vulnerability cross-referencing.`,
                  detail: `${packageCount} ${pkgLabel}${packageCount !== 1 ? 's' : ''} recorded`,
                }
              : {
                  compliant: false,
                  assessed: false,
                  reason: `No ${isWindows ? 'Windows program' : 'deb/rpm package'} records were read back for this node, so the software asset inventory point could not be assessed. Absence of collected inventory is not evidence that no inventory is maintained.`,
                  detail: 'No software inventory recorded — not assessed',
                };
          } catch {
            // leave undefined
          }

          // Fetch full node details if required for hardware/sec products
          const nodeAny = node as unknown as Record<string, unknown>;
          const hasHardware = !!(nodeAny.hardware_model || nodeAny.hardware_vendor || nodeAny.hardware_physical_memory);
          const hasSecProds = Array.isArray(nodeAny.security_products);
          // `security_products` is attached by the node LIST endpoint only — the per-node
          // details endpoint fetched below never returns it. Capture it here, BEFORE
          // detailNode is reassigned, or the Windows Security Center evidence for points
          // 5, 9 and 20 is wiped by the very fetch that is meant to enrich it.
          // Mirrors utils/sebiComplianceChecks.ts.
          let securityProductsRaw: unknown = hasSecProds ? nodeAny.security_products : undefined;
          let detailNode: Record<string, unknown> = nodeAny;
          if (!hasHardware || !hasSecProds) {
            try {
              const res = await api.get(`${NODES_URLS.NODE}${encodeURIComponent(hostId)}`);
              const json = res.data;
              const raw = json?.data ?? json;
              if (raw && typeof raw === 'object') {
                detailNode = raw as Record<string, unknown>;
                // Only overwrite the captured list if the details payload really carries one.
                const detailSecProds = (raw as Record<string, unknown>).security_products;
                if (Array.isArray(detailSecProds)) securityProductsRaw = detailSecProds;
              }
            } catch {
              // fallback to provided node
            }
          }

          // Point 2: Hardware inventory
          {
            const hwVendor = String(detailNode.hardware_vendor ?? '').trim();
            const hwModel = String(detailNode.hardware_model ?? '').trim();
            const hwCpu = String(detailNode.hardware_cpu_type ?? '').trim();
            const hwMemRaw = String(detailNode.hardware_physical_memory ?? '').trim();
            const hwCores = String(detailNode.hardware_cpu_logical_core ?? '').trim();
            const osName = String(detailNode.os_name ?? detailNode.os_platform ?? '').trim();
            const osBuild = String(detailNode.os_build ?? '').trim();
            const nonEmpty = (s: string) => s.length > 0 && s !== 'null' && s !== 'undefined';
            const populated = [hwVendor, hwModel, hwCpu, hwMemRaw, osName].filter(nonEmpty);
            if (populated.length >= 3) {
              const ramGb = (() => {
                const bytes = parseInt(hwMemRaw, 10);
                if (!Number.isFinite(bytes) || bytes <= 0) return null;
                return `${(bytes / 1073741824).toFixed(1)} GB RAM`;
              })();
              const parts = [
                hwVendor && hwModel ? `${hwVendor} ${hwModel}` : (hwVendor || hwModel || null),
                hwCpu || null,
                ramGb,
                hwCores ? `${hwCores} cores` : null,
                osName ? `${osName}${osBuild ? ` (${osBuild})` : ''}` : null,
              ].filter(Boolean) as string[];
              checks['2'] = {
                compliant: true,
                reason: `Hardware inventory is recorded in Vajra for this node: ${parts.join(', ')}. This satisfies the IRDAI requirement for maintaining an up-to-date hardware asset record.`,
                detail: parts.slice(0, 2).join(' · ') || 'Hardware data present',
              };
            }
          }

          // Shared EDR / anti-malware evidence for points 5, 9 and 20.
          //
          // Vajra IS the EDR on these endpoints — an agent with kernel/eBPF telemetry,
          // ClamAV and Defender control, threat analysis, alerting and containment — and
          // it does NOT register itself with Windows Security Center. Judging these
          // controls on the Security Center product list alone therefore reported a
          // Vajra-protected host carrying no third-party AV as having no EDR, while its
          // EDR was the thing producing the report. These controls ask exactly the
          // question the agent's own check-in answers, so the agent's presence and
          // liveness is measured evidence here; Security Center products in state "On"
          // are recorded as additional coverage on top of it.
          //
          // There is deliberately no failing branch: Vajra cannot distinguish "the agent
          // is stopped" from "the host is powered off", and a Security Center list with
          // nothing On says nothing about Vajra, which never appears in it. When neither
          // source is determinable the points are not assessed.
          //
          // Each of the three points below forms its own verdict and its own wording from
          // this evidence — none of them copies another point's outcome.
          //
          // Point 20 additionally needs signature-CURRENCY, which the condensed
          // security_products field the node-list endpoint returns (name + state only)
          // cannot answer. Fetch the full per-product row from the same endpoint
          // utils/certinComplianceChecks.ts uses for control 5.11, so the two registers
          // read the identical signatures_up_to_date value rather than answering the
          // same question from two different sources that could disagree.
          let fullSecurityProducts: Array<Record<string, unknown>> | null = null;
          try {
            const res = await api.post(`${API_BASE_URL}/api/windows/security_products`, { host_identifier: hostId });
            const payload = res.data as { status?: string; data?: unknown[] } | null;
            fullSecurityProducts = payload?.status === 'Success' && Array.isArray(payload.data) && payload.data.length > 0
              ? (payload.data as Array<Record<string, unknown>>)
              : null;
          } catch {
            fullSecurityProducts = null;
          }
          // Live Defender signature telemetry (PowerShell key 64), the same second
          // measured-negative signal utils/certinComplianceChecks.ts control 5.11 already
          // reads — see that control's WHY-comment. Fetched here rather than inside the
          // edrEvidence IIFE below because it is an async websocket round trip.
          //
          // 2026-09-07: made CONDITIONAL on Defender actually being one of the running
          // antivirus products. It was previously fetched unconditionally for every host,
          // while line ~828 only ever CONSUMES it when defenderIsRunning — so on every
          // non-Defender host the sweep paid a full websocket round trip for a value it
          // then discarded. That matters because this register's websocket probes are
          // strictly serial per host and run on useNodeWebSocket's 15 s default with no
          // retry (the wsSendMessage prop type here cannot carry a timeoutMs, unlike
          // SEBI's, which uses 20 s plus a 2-attempt retry). Live evidence that the extra
          // round trip was load-bearing: irdai_historical_compliance key '10' (USB, the
          // slow PowerShell key-54 probe issued AFTER this one) measured 11 of 11 hosts on
          // 2026-09-04 (snapshot id 24) and then 0 of 13 on 2026-09-07 (snapshot id 25) —
          // a regression, not a long-standing budget gap — with this unconditional fetch
          // added in between (commit de6a603). SEBI's equivalent USB probe measured 13/13
          // three minutes before that same failing sweep, so the websocket transport
          // itself was healthy; what differed was this register's per-host budget.
          // Skipping the round trip where its result is unusable gives the key-54 probe
          // back its share of that budget without weakening any verdict: the only consumer
          // is gated on defenderIsRunning anyway, so a non-Defender host's outcome is
          // byte-identical to before.
          const defenderAmongRunningAv = (fullSecurityProducts ?? []).some(
            (row) => String((row as Record<string, unknown>).type ?? '').trim().toLowerCase() === 'antivirus'
              && String((row as Record<string, unknown>).state ?? '').trim().toLowerCase() === 'on'
              && /defender/i.test(String((row as Record<string, unknown>).name ?? '')),
          );
          const irdaiPsOutputs = defenderAmongRunningAv
            ? await fetchPowerShellOutputs(hostId, ['64'], wsConnected, wsSendMessage)
            : null;
          const edrEvidence = (() => {
            // Vajra platform default for "the agent is alive", not an IRDAI-mandated
            // interval. Kept identical to AGENT_CHECKIN_FRESHNESS_HOURS in
            // utils/sebiComplianceChecks.ts so the two registers answer the same
            // question with the same threshold.
            const AGENT_CHECKIN_FRESHNESS_HOURS = 24;
            const rawLastSeen = detailNode.last_seen ?? node.last_seen;
            const lastSec =
              (typeof rawLastSeen === 'number' || typeof rawLastSeen === 'string') && Number(rawLastSeen) > 0
                ? Number(rawLastSeen)
                : null;
            const ageHours = lastSec !== null ? (Date.now() / 1000 - lastSec) / 3600 : null;
            // Liveness is measured, never assumed: a node that has not checked in inside
            // the freshness window does not pass on agent evidence.
            const agentLive = ageHours !== null && ageHours <= AGENT_CHECKIN_FRESHNESS_HOURS;
            const describeAge = (hours: number) => (hours < 1
              ? `${Math.max(0, Math.round(hours * 60))} minute${Math.round(hours * 60) === 1 ? '' : 's'} ago`
              : `${Math.round(hours)} hour${Math.round(hours) === 1 ? '' : 's'} ago`);
            const agentSeenText = lastSec !== null
              ? `${fmtDateTime(lastSec)} (${describeAge(Math.max(0, ageHours ?? 0))})`
              : null;

            const secProdsRaw = securityProductsRaw;
            const productListRead = Array.isArray(secProdsRaw);
            // The firewall entry is a firewall control's evidence, not AV/EDR evidence.
            const avProds = (Array.isArray(secProdsRaw) ? secProdsRaw as Array<{ name?: string; state?: string }> : [])
              .filter((p) => !/firewall/i.test(String(p.name ?? '')));
            const describe = (list: Array<{ name?: string; state?: string }>) =>
              list.map((p) => `${p.name ?? 'unnamed product'} (${String(p.state ?? '').trim() || 'no state reported'})`).join(', ');
            const active = avProds.filter((p) => String(p.state ?? '').trim().toLowerCase() === 'on');

            // Appended when the agent's own liveness already carried the verdict.
            const extraCoverageText = active.length > 0
              ? ` Windows Security Center additionally reports ${active.length} antivirus/EDR product${active.length !== 1 ? 's' : ''} in state "On" on this node: ${describe(active)}.`
              : productListRead
                ? ' Windows Security Center registers no third-party antivirus product in state "On" here; Vajra does not register itself with Security Center, so that list does not describe this endpoint\'s EDR.'
                : '';

            // Appended when the agent's liveness could not be observed.
            const agentUnseenText = agentSeenText !== null
              ? ` The Vajra Agent last checked in at ${agentSeenText}, outside Vajra's default ${AGENT_CHECKIN_FRESHNESS_HOURS}-hour agent check-in freshness window, so its own liveness could not be confirmed on this run.`
              : ' Vajra holds no agent check-in time for this node, so the agent\'s own liveness could not be observed on this run.';

            // Signature currency for point 20's "reporting healthy status" — a measured
            // negative here overrides both agentLive and Security Center "On", because
            // neither of those speaks to whether a running product's definitions are
            // current. Mirrors utils/certinComplianceChecks.ts control 5.11 exactly, so
            // the two registers cannot disagree on the same fleet on the same day.
            const antivirusProducts = (fullSecurityProducts ?? []).filter(
              (row) => String((row as Record<string, unknown>).type ?? '').trim().toLowerCase() === 'antivirus'
                && String((row as Record<string, unknown>).state ?? '').trim().toLowerCase() === 'on',
            );
            const numField = (v: unknown): number | null => {
              const n = typeof v === 'number' ? v : typeof v === 'string' ? Number(v) : NaN;
              return Number.isFinite(n) ? n : null;
            };
            const staleSignatureProducts = antivirusProducts.filter((row) => numField((row as Record<string, unknown>).signatures_up_to_date) === 0);
            const signatureNamesOf = (rows: Array<Record<string, unknown>>) => rows.map((row) => String(row.name ?? 'unnamed product')).join(', ');

            // 2026-09-04: added the second measured-negative signal CERT-In control 5.11
            // already has — live Defender signature age via PowerShell key 64 — which this
            // control was missing, so it could disagree with 5.11 on a node whose Security
            // Center still reports signatures_up_to_date=1 but whose live signature date is
            // actually stale. It can only add a fail, never turn a measured negative into a
            // pass, and is read solely when Defender is one of the running antivirus
            // products (it speaks for Defender only).
            const defenderIsRunning = antivirusProducts.some((row) => /defender/i.test(String((row as Record<string, unknown>).name ?? '')));
            const signatureTelemetry = defenderIsRunning ? (parsePsObjectList(irdaiPsOutputs?.get('64'))?.[0] ?? null) : null;
            const signatureUpdatedRaw = String(signatureTelemetry?.AntivirusSignatureLastUpdated ?? '').trim();
            const signatureUpdatedMs = signatureUpdatedRaw ? Date.parse(signatureUpdatedRaw) : NaN;
            const signatureAgeDays = Number.isFinite(signatureUpdatedMs) && signatureUpdatedMs <= Date.now()
              ? Math.floor((Date.now() - signatureUpdatedMs) / 86400000)
              : null;
            const staleSignatureDate = signatureAgeDays !== null && signatureAgeDays > SIGNATURE_MAX_AGE_DAYS;

            return {
              agentLive,
              agentSeenText,
              activeCount: active.length,
              activeNames: describe(active),
              extraCoverageText,
              agentUnseenText,
              productListRead,
              // Two independent measured-negative signals, kept separate (not pre-merged)
              // so point 20's reason text can name whichever one actually fired — mirrors
              // certinComplianceChecks.ts control 5.11's staleProducts/staleSignatureDate
              // branches exactly.
              signaturesStale: staleSignatureProducts.length > 0 || staleSignatureDate,
              staleSignatureProductsPresent: staleSignatureProducts.length > 0,
              staleSignatureNames: signatureNamesOf(staleSignatureProducts),
              staleSignatureDate,
              signatureAgeDays,
              signatureUpdatedRaw,
            };
          })();

          // Point 14: "Critical systems are continuously monitored in real time for threats
          // and incidents." Answered per host, from this node's own critical designation and
          // its own agent check-in — never from a fleet-wide count of critical nodes, which
          // says nothing about this endpoint. The designation is only carried by
          // /api/nodes/list; where it could not be read the control is not assessed rather
          // than assumed non-critical.
          {
            const criticalRaw = detailNode.critical ?? nodeAny.critical ?? fleetNodeRow?.critical;
            const isCritical = criticalRaw === true || criticalRaw === 'true' || criticalRaw === 1;
            const isNotCritical = criticalRaw === false || criticalRaw === 'false' || criticalRaw === 0;

            if (isCritical && edrEvidence.agentLive) {
              checks['14'] = {
                compliant: true,
                reason: `This node is designated a critical system in Vajra, and the Vajra Agent monitoring it last reported at ${edrEvidence.agentSeenText}, inside the agent check-in freshness window. Real-time telemetry is therefore reaching the platform from this critical endpoint, which is the measurement this control asks for.`,
                detail: 'Critical system · agent reporting',
              };
            } else if (isCritical) {
              checks['14'] = {
                compliant: false,
                reason: `This node is designated a critical system, but no agent check-in was observed for it inside the freshness window, so it is not currently under continuous real-time monitoring.${edrEvidence.agentUnseenText}`,
                detail: 'Critical system · no recent agent check-in',
              };
            } else if (isNotCritical) {
              checks['14'] = {
                compliant: false,
                assessed: false,
                reason: 'This node is not designated a critical system in Vajra, so the control — which is about how critical systems are monitored — does not resolve for it. Marking the endpoints that handle sensitive data or essential services as critical is what makes this control measurable on them.',
                detail: 'Not designated a critical system — not assessed',
              };
            } else {
              checks['14'] = {
                compliant: false,
                assessed: false,
                reason: 'Vajra did not read back this node\'s critical-system designation on this run, so whether it is a critical system under continuous monitoring could not be measured. An unreadable designation is not evidence that the node is unmonitored.',
                detail: 'Critical designation not read back — not assessed',
              };
            }
          }

          // Point 5: anti-malware protections (EDR, AV, IP blocking, containment) enabled.
          //
          // 2026-09-04: the compliant-branch reason used to list IP/port blocking and USB/
          // Bluetooth lockdown as capabilities the agent's check-in evidences are 'enabled'.
          // Only the EDR/anti-malware layer's install+liveness is actually measured here; the
          // IP-blocklisting, port-blocking and containment posture actually CONFIGURED on this
          // node is not read by this control, mirroring the identical gap already documented
          // and fixed for the parallel SEBI key 6 evaluator. Narrowed so the reason states what
          // was measured and what was not, rather than implying both are confirmed active.
          if (edrEvidence.agentLive) {
            checks['5'] = {
              compliant: true,
              reason: `The Vajra Agent — the anti-malware/EDR product running on this endpoint — is installed on this node and last checked in at ${edrEvidence.agentSeenText}, which is observed evidence that anti-malware protection is installed and enabled here, not an assumption from its presence in the console. Vajra additionally provides IP/port blocking and USB/Bluetooth lockdown capabilities, but whether those specific containment mechanisms are configured and active on this node is not measured by this control.${edrEvidence.extraCoverageText}`,
              detail: edrEvidence.activeCount > 0
                ? `Vajra Agent active · ${edrEvidence.activeCount} additional AV/EDR product${edrEvidence.activeCount !== 1 ? 's' : ''} On`
                : 'Vajra Agent installed and actively checking in',
            };
          } else if (edrEvidence.activeCount > 0) {
            checks['5'] = {
              compliant: true,
              reason: `Windows Security Center reports ${edrEvidence.activeCount} antivirus/EDR product${edrEvidence.activeCount !== 1 ? 's' : ''} in state "On" on this node: ${edrEvidence.activeNames}. A product reported On is actively running, so anti-malware protection is enabled on this endpoint.${edrEvidence.agentUnseenText}`,
              detail: `${edrEvidence.activeCount} AV/EDR product${edrEvidence.activeCount !== 1 ? 's' : ''} On`,
            };
          } else {
            checks['5'] = {
              compliant: false,
              assessed: false,
              reason: `Neither source of anti-malware evidence was available for this node, so whether anti-malware protections are enabled was not measured.${edrEvidence.agentUnseenText}${edrEvidence.productListRead ? ' Windows Security Center registers no antivirus product in state "On" either, but Vajra does not register itself with Security Center, so that list is not evidence about the EDR actually deployed here.' : ' No Windows Security Center product list was read back for this node either.'}`,
              detail: 'Not assessed — no agent check-in and no active AV/EDR product record',
            };
          }

          // The Windows Update history is read ONCE per host and evaluated twice: control 12
          // (patch recency, immediately below) and control 18 (update-history visibility,
          // further down) both need it, and issuing two identical requests per host multiplied
          // the sweep's HTTP load for nothing. Rejection is re-thrown into whichever control
          // awaits it, so each keeps its own not-assessed branch; the no-op catch here only
          // stops an unhandled-rejection warning between the fetch and the first await.
          const updateHistoryPromise = nodesViewApi.getUpdateHistory(hostId);
          updateHistoryPromise.catch(() => { /* consumed by the per-control try/catch below */ });

          // Point 12: Patch Management — are OS patches applied within the recency window?
          //
          // 2026-09-07: the three reason strings below used to read as if the 30-day
          // recency window were an IRDAI-mandated SLA ("satisfy the IRDAI patch
          // management SLA", "IRDAI requires critical patches within 30 days",
          // "violating the IRDAI patch management requirement"). It is not — Annexure
          // III names no figure; 30 days is a Vajra platform default, same as it is
          // documented to be everywhere else this threshold appears (SEBI control 15,
          // and this control's own IRDAI_HOT_REASON_DETAIL['12'] static fallback).
          // Corrected so the live per-run text (which takes priority over that static
          // fallback whenever a fresh sweep exists) makes the same honest claim.
          //
          // 2026-09-07: evidence source replaced as well. This control used to read
          // nodesViewApi.getLatestUpdate, which returns exactly ONE row — the newest
          // windows_update_history record by Windows event date — and scored whatever that
          // single row happened to be. SEBI control 15 was moved off that same endpoint for
          // documented reasons that apply here unchanged (sebiComplianceChecks.ts checks['15']):
          // on this fleet the newest row is a Microsoft Defender signature refresh on most
          // hosts, so a host whose last true OS cumulative installed 90 days ago scored a PASS
          // off a signature update from yesterday; and where the newest row was instead a
          // failed Microsoft Store package, a host whose OS patching was current scored a FAIL.
          // Both are fabricated verdicts, and both make this register disagree with SEBI 15 on
          // the same host on the same day — the two registers ask the same question and must
          // answer it from the same evidence.
          //
          // Ported verbatim from sebiComplianceChecks.ts checks['15'], the same way control 7
          // was ported from SEBI control 8:
          //   * Defender signature / antimalware-platform / definition rows are excluded in
          //     either direction — signature freshness is not patch currency.
          //   * Only operating-system quality/security updates are measured.
          //   * An update that has NEVER recorded a success, whose most recent attempt failed
          //     or aborted, and whose most recent attempt is more recent than the newest
          //     successful quality update, is outstanding. That last clause is the supersession
          //     guard and is load-bearing: an old KB superseded by a later cumulative is not an
          //     open failure, and flagging it would be a fabricated failure.
          //   * 'InProgress' is neither a success nor a failure and is not scored.
          // FIXME(shared-module): this evaluator now exists in two hand-copied places. It should
          // be extracted into a module both registers import, as fetchUsbStatusForCompliance was.
          {
            const isWindows = /windows/i.test(String(detailNode.os_name ?? detailNode.os_platform ?? node.os_name ?? node.os_platform ?? ''));
            if (!isWindows) {
              checks['12'] = {
                compliant: false,
                assessed: false,
                reason: 'This is not a Windows endpoint, so the Windows Update record this check reads does not exist for it and patch currency on this node was not measured.',
                detail: 'Not assessed — not a Windows endpoint',
              };
            } else {
              try {
                const historyRes = await updateHistoryPromise;
                const historyPayload = historyRes.data as { status?: string; data?: unknown[] } | null;
                const historyRows = historyPayload?.status === 'Success' && Array.isArray(historyPayload.data)
                  ? historyPayload.data as Array<Record<string, unknown>>
                  : [];

                const titleOf = (row: Record<string, unknown>) => String(row.title ?? '').trim();
                const codeOf = (row: Record<string, unknown>) => String(row.result_code ?? '').trim().toLowerCase();
                const dateOf = (row: Record<string, unknown>) => {
                  const n = Number(String(row.date ?? '').trim());
                  return Number.isFinite(n) && n > 0 ? n : null;
                };
                const kbOf = (row: Record<string, unknown>) => (titleOf(row).match(/KB\d{5,}/i)?.[0] || titleOf(row) || 'untitled update');
                const SIGNATURE_RE = /security intelligence update|antimalware platform|definition update/i;
                const QUALITY_RE = /cumulative update|servicing stack|security update|\.net framework|feature update|^windows \d+, version/i;

                const substantive = historyRows.filter((row) => !SIGNATURE_RE.test(titleOf(row)));
                const quality = substantive.filter((row) => QUALITY_RE.test(titleOf(row)));
                const lastOkSec = quality
                  .filter((row) => codeOf(row) === 'succeeded')
                  .reduce<number | null>((acc, row) => {
                    const d = dateOf(row);
                    return d !== null && (acc === null || d > acc) ? d : acc;
                  }, null);

                const attemptsByUpdate = new Map<string, Array<Record<string, unknown>>>();
                quality.forEach((row) => {
                  const id = String(row.update_id ?? '').trim() || titleOf(row);
                  const list = attemptsByUpdate.get(id);
                  if (list) list.push(row);
                  else attemptsByUpdate.set(id, [row]);
                });
                const outstanding: Array<{ label: string; when: number | null }> = [];
                attemptsByUpdate.forEach((attempts) => {
                  if (attempts.some((row) => codeOf(row) === 'succeeded')) return;
                  const newest = attempts.reduce((best, row) => {
                    const d = dateOf(row);
                    const bd = dateOf(best);
                    return d !== null && (bd === null || d > bd) ? row : best;
                  }, attempts[0]);
                  const code = codeOf(newest);
                  if (code !== 'failed' && code !== 'aborted') return;
                  const when = dateOf(newest);
                  // Supersession guard — see the block comment above.
                  if (lastOkSec !== null && (when === null || when <= lastOkSec)) return;
                  outstanding.push({ label: kbOf(newest), when });
                });

                const nowSec = Math.floor(Date.now() / 1000);
                if (historyRows.length === 0) {
                  checks['12'] = {
                    compliant: false,
                    assessed: false,
                    reason: 'Vajra read back no Windows Update history for this node, so whether operating-system patches are applied within the recency window was not measured. An empty update history is not evidence that the node is unpatched.',
                    detail: 'Not assessed — no Windows Update history',
                  };
                } else if (outstanding.length > 0) {
                  const newestFailure = outstanding.reduce<number | null>((acc, o) => (
                    o.when !== null && (acc === null || o.when > acc) ? o.when : acc
                  ), null);
                  const names = outstanding.slice(0, 8).map((o) => o.label).join(', ');
                  checks['12'] = {
                    compliant: false,
                    reason: `${outstanding.length} operating-system quality/security update${outstanding.length !== 1 ? 's have' : ' has'} never installed successfully on this node and ${outstanding.length !== 1 ? 'their' : 'its'} most recent attempt failed: ${names}${outstanding.length > 8 ? `, and ${outstanding.length - 8} more` : ''}${newestFailure !== null ? `. The most recent failure was recorded on ${fmtDateTime(newestFailure)}` : ''}. Updates already superseded by a later successful cumulative are excluded, so ${outstanding.length !== 1 ? 'these are' : 'this is'} still outstanding. Unresolved failed patches leave known vulnerabilities unmitigated.`,
                    detail: `${outstanding.length} failed OS update${outstanding.length !== 1 ? 's' : ''} outstanding`,
                  };
                } else if (lastOkSec !== null) {
                  const daysOld = (nowSec - lastOkSec) / 86400;
                  checks['12'] = daysOld <= 30
                    ? {
                      compliant: true,
                      reason: `The newest operating-system quality/security update on this node installed successfully on ${fmtDateTime(lastOkSec)} (${Math.round(daysOld)} day${Math.round(daysOld) !== 1 ? 's' : ''} ago), within Vajra's default 30-day patch recency threshold, and no OS update is recorded as failing without a later success. The threshold is a Vajra platform default, not an IRDAI-mandated deadline — Annexure III names no figure. Microsoft Defender signature refreshes are excluded from this measurement.`,
                      detail: `Last OS patch ${Math.round(daysOld)} day${Math.round(daysOld) !== 1 ? 's' : ''} ago`,
                    }
                    : {
                      compliant: false,
                      reason: `The newest operating-system quality/security update on this node installed successfully on ${fmtDateTime(lastOkSec)}, ${Math.round(daysOld)} days ago — beyond Vajra's default 30-day patch recency threshold, which is a Vajra platform default rather than an IRDAI-mandated deadline. Microsoft Defender signature refreshes are excluded from this measurement, so recent signature activity does not offset it.`,
                      detail: `${Math.round(daysOld)} days since last OS patch`,
                    };
                } else {
                  checks['12'] = {
                    compliant: false,
                    assessed: false,
                    reason: `The Windows Update history Vajra holds for this node (${historyRows.length} record${historyRows.length !== 1 ? 's' : ''}) contains no operating-system quality-update record — only Defender signature refreshes and application packages — so patch currency was not measured. Signature freshness is not evidence of patch currency in either direction.`,
                    detail: 'Not assessed — no OS quality-update record',
                  };
                }
              } catch {
                checks['12'] = {
                  compliant: false,
                  assessed: false,
                  reason: 'Vajra could not fetch the Windows Update history for this node — the request failed before any update data was returned — so patch currency on this node was not measured.',
                  detail: 'Not assessed — update history fetch failed',
                };
              }
            }
          }

      // Point 7: are the firewall rules actually in force on this endpoint, scoped to
      // specific addresses, or do they admit any remote address?
      //
      // 2026-09-04: reclassified from Class A to Class B. This control's wording is
      // byte-identical to SEBI control 8, which reads the SAME windows_firewall_rules
      // data (via the same getFirewallRules endpoint) and already solves the "no
      // approved baseline" problem this control used to give up on — by measuring the
      // SCOPE of enabled inbound Allow rules (wildcard "*"/"Any" vs address-scoped)
      // rather than requiring an operator-supplied whitelist. Ported directly from
      // sebiComplianceChecks.ts checks['8'] — see that file for the canonical version.
      //
      // Honest limits, stated in the reason: Vajra holds NO organisation-approved
      // IP/port list to compare against, so this measures the SCOPE of the rules
      // rather than approval of the individual addresses; and stock Windows ships
      // wildcard inbound Allow rules (mDNS, network discovery, delivery
      // optimisation), so a default installation fails this control. A rule whose
      // direction/action/remote address cannot be decoded is not scored.
          // Rule count captured so point 19 can state its own evidence rather than copy this verdict.
          let firewallRuleCount: number | null = null;
          try {
            const fwRes = await nodesViewApi.getFirewallRules(hostId);
            const fwPayload = fwRes.data as { status?: string; data?: unknown[]; message?: string } | null;
            const fwRows = fwPayload?.status === 'Success' && Array.isArray(fwPayload.data)
              ? fwPayload.data as Array<Record<string, unknown>>
              : [];
            firewallRuleCount = fwPayload?.status === 'Success' && Array.isArray(fwPayload.data) ? fwPayload.data.length : null;

            const snapshotSec = fwRows.reduce<number | null>((acc, row) => {
              const n = Number(row?.unixtime);
              return Number.isFinite(n) && n > 0 && (acc === null || n > acc) ? n : acc;
            }, null);

            const str = (v: unknown) => String(v ?? '').trim().toLowerCase();
            const inboundAllow = fwRows.filter((row) => str(row.direction) === 'in'
              && str(row.action) === 'allow'
              && Number(row.enabled) === 1);
            const undecodableRules = fwRows.filter((row) => !['in', 'out'].includes(str(row.direction))
              || !['allow', 'block'].includes(str(row.action)));
            // An absent remote address is unmeasured, not a wildcard: only the
            // explicit any-address values are counted as unscoped.
            const isWildcard = (row: Record<string, unknown>) => ['*', 'any'].includes(str(row.remote_addresses));
            const unscopedAddress = (row: Record<string, unknown>) => row.remote_addresses === null
              || row.remote_addresses === undefined
              || str(row.remote_addresses) === '';
            const wildcardRules = inboundAllow.filter(isWildcard);
            const undecodableScope = inboundAllow.filter(unscopedAddress);
            const describeRule = (row: Record<string, unknown>) => {
              const name = String(row.name ?? row.app_name ?? 'unnamed rule').trim() || 'unnamed rule';
              const ports = String(row.local_ports ?? '').trim();
              return `${name}${ports ? ` (local ports ${ports})` : ''}`;
            };
            const snapshotNote = snapshotSec !== null ? ` Firewall snapshot taken ${fmtDateTime(snapshotSec)}.` : '';
            const noBaselineNote = 'Vajra holds no organisation-approved IP or port list for this node, so this measures whether the enabled inbound Allow rules are scoped to specific addresses at all — it does not certify the addresses that are scoped as approved.';

            if (fwRows.length === 0) {
              checks['7'] = { compliant: false, assessed: false, reason: 'Vajra read back no firewall rule records for this node, so the allow/deny posture actually configured on it was not measured. An empty rule inventory is not evidence that traffic is unrestricted.', detail: 'Not assessed — no firewall rule records' };
            } else if (undecodableRules.length === fwRows.length) {
              checks['7'] = { compliant: false, assessed: false, reason: `Vajra holds ${fwRows.length} firewall rule record${fwRows.length !== 1 ? 's' : ''} for this node, but none carries a direction and action it can decode, so the allow/deny posture was not measured.`, detail: 'Not assessed — undecodable firewall rules' };
            } else if (wildcardRules.length > 0) {
              const examples = wildcardRules.slice(0, 5).map(describeRule).join('; ');
              checks['7'] = {
                compliant: false,
                reason: `${wildcardRules.length} of ${inboundAllow.length} enabled inbound Allow rule${inboundAllow.length !== 1 ? 's' : ''} on this node accept traffic from any remote address ("*"/"Any") rather than from specific approved addresses. Examples: ${examples}${wildcardRules.length > 5 ? `, and ${wildcardRules.length - 5} more` : ''}. ${noBaselineNote} Note that stock Windows ships several such wildcard inbound Allow rules (mDNS, network discovery, delivery optimisation), so an unmodified endpoint fails this control on its defaults.${snapshotNote}`,
                detail: `${wildcardRules.length} / ${inboundAllow.length} inbound allow rules accept any address`,
              };
            } else if (inboundAllow.length === 0) {
              checks['7'] = {
                compliant: true,
                reason: `No enabled inbound Allow rule is present in the firewall snapshot Vajra holds for this node (${fwRows.length} rule record${fwRows.length !== 1 ? 's' : ''} in total), so no inbound traffic is admitted by an unscoped rule. ${noBaselineNote}${snapshotNote}`,
                detail: `0 enabled inbound allow rules of ${fwRows.length}`,
              };
            } else if (undecodableScope.length === inboundAllow.length) {
              checks['7'] = { compliant: false, assessed: false, reason: `All ${inboundAllow.length} enabled inbound Allow rule${inboundAllow.length !== 1 ? 's' : ''} on this node came back without a readable remote-address scope, so whether they are limited to approved addresses was not measured.`, detail: 'Not assessed — no readable remote-address scope' };
            } else {
              checks['7'] = {
                compliant: true,
                reason: `Every one of the ${inboundAllow.length - undecodableScope.length} enabled inbound Allow rule${inboundAllow.length - undecodableScope.length !== 1 ? 's' : ''} Vajra could read on this node is scoped to specific remote addresses or to the local subnet; none admits traffic from any address. ${noBaselineNote}${undecodableScope.length > 0 ? ` ${undecodableScope.length} further inbound Allow rule${undecodableScope.length !== 1 ? 's' : ''} carried no readable remote-address scope and ${undecodableScope.length !== 1 ? 'were' : 'was'} not scored.` : ''}${snapshotNote}`,
                detail: `${inboundAllow.length - undecodableScope.length} scoped inbound allow rule${inboundAllow.length - undecodableScope.length !== 1 ? 's' : ''}`,
              };
            }
          } catch {
            checks['7'] = { compliant: false, assessed: false, reason: 'The firewall rules request for this node failed, so the allowed IP/port policy could not be assessed. A failed API call is not evidence of non-compliance.', detail: 'Firewall rules fetch failed — not assessed' };
          }

      // Point 26: "The BIOS/firmware version and configuration are checked for compliance."
      //
      // UEFI Secure Boot is a firmware CONFIGURATION setting and Vajra measures it twice:
      // the secureboot table (POST /api/windows/secureboot) and, independently, the
      // Confirm-SecureBootUEFI baseline probe. The secureboot row is preferred because it
      // covers more hosts and is fresher; secure_boot = -1 means the firmware could not be
      // queried, so it falls through to the probe rather than being read as disabled.
      //
      // The BIOS VERSION half is reported as detail only: Vajra holds no vendor firmware
      // baseline to compare a version against, so the reason says which half was measured.
      {
        let biosVersion = '';
        let biosMessage = '';
        try {
          const biosRes = await nodesViewApi.getBiosInfo(hostId);
          const biosPayload = biosRes.data as { status?: string; data?: unknown; message?: string } | null;
          const biosRows = Array.isArray(biosPayload?.data)
            ? biosPayload?.data
            : biosPayload?.data && typeof biosPayload.data === 'object'
              ? [biosPayload.data]
              : [];
          // wmi_bios_info is a name/value settings table (columns: id, host_identifier,
          // unixtime, name, value) — there is no `version` field on any row. Look up the
          // version by row name instead, preferring the plain 'Version' setting and
          // falling back to the SMBIOS-specific names when it is absent.
          const biosRowsTyped = biosRows.filter(
            (row): row is Record<string, unknown> => !!row && typeof row === 'object'
          );
          const findBiosValue = (name: string) =>
            String(
              biosRowsTyped.find((row) => String(row.name ?? '').toLowerCase() === name.toLowerCase())?.value ?? ''
            ).trim();
          biosVersion =
            findBiosValue('Version') ||
            findBiosValue('SMBIOSBIOSVersion') ||
            findBiosValue('BIOSVersion');
          biosMessage = String(biosPayload?.message ?? '');
        } catch {
          biosMessage = '';
        }

        let secureBootRow: number | null = null;
        try {
          const sbRes = await nodesViewApi.getSecureBootInfo(hostId);
          const sbPayload = sbRes.data as { status?: string; data?: unknown } | null;
          const sbRows = Array.isArray(sbPayload?.data) ? sbPayload.data as Array<Record<string, unknown>> : [];
          if (sbPayload?.status === 'Success' && sbRows.length > 0) {
            const value = Number(sbRows[0]?.secure_boot);
            secureBootRow = Number.isFinite(value) ? value : null;
          }
        } catch {
          secureBootRow = null;
        }

        const sbProbe = probe('4');
        const secureBootState: 'enabled' | 'disabled' | 'unknown' =
          secureBootRow === 1 ? 'enabled'
            : secureBootRow === 0 ? 'disabled'
              : sbProbe === 'on' ? 'enabled'
                : sbProbe === 'off' ? 'disabled'
                  : 'unknown';
        const sbSourceText = secureBootRow === 1 || secureBootRow === 0
          ? 'the Secure Boot state collected from this endpoint'
          : `the Confirm-SecureBootUEFI baseline probe run on this endpoint${baselineTakenText}`;
        const versionText = biosVersion
          ? ` The BIOS version reported by this node is ${biosVersion}; Vajra holds no vendor firmware baseline, so the version itself is reported but not compared against one.`
          : ' No BIOS version string was read back for this node, so only the firmware configuration setting above was measured.';

        if (secureBootState === 'enabled') {
          checks['26'] = {
            compliant: true,
            reason: `UEFI Secure Boot is enabled on this node according to ${sbSourceText}, so the firmware is configured to refuse unsigned boot components — the firmware configuration setting this control is measured on.${versionText}`,
            detail: biosVersion ? `Secure Boot enabled · BIOS ${biosVersion}` : 'Secure Boot enabled',
          };
        } else if (secureBootState === 'disabled') {
          checks['26'] = {
            compliant: false,
            reason: `UEFI Secure Boot is disabled on this node according to ${sbSourceText}. With Secure Boot off the firmware will load unsigned boot components, so the firmware configuration does not meet the baseline.${versionText}`,
            detail: biosVersion ? `Secure Boot disabled · BIOS ${biosVersion}` : 'Secure Boot disabled',
          };
        } else {
          checks['26'] = {
            compliant: false,
            assessed: false,
            reason: `Neither the Secure Boot state nor the Confirm-SecureBootUEFI probe returned a usable value for this node${secureBootRow === -1 ? ' (the firmware reported that Secure Boot could not be queried)' : ''}, so the firmware configuration was not measured.${biosVersion ? ` BIOS version ${biosVersion} was collected, but a version on its own is not a configuration verdict and Vajra holds no vendor firmware baseline to compare it against.` : biosMessage ? ` BIOS metadata was also unavailable: ${biosMessage}.` : ' No BIOS metadata was read back either.'}`,
            detail: 'Secure Boot state not measured — not assessed',
          };
        }
      }

      // Point 31: "Endpoint storage volumes are encrypted at rest with protection active."
      //
      // 2026-09-07: added. Until now this register carried NO encryption control at all —
      // grepping the whole file for 'encrypt' or 'bitlocker' returned nothing, neither a
      // guideline label nor an evaluator — while the SEBI register measured the same hosts'
      // BitLocker state twice (SEBI 26 endpoint encryption, SEBI 34 encryption-status
      // reporting). Vajra already holds the evidence for every Windows host it sweeps, so an
      // IRDAI-regulated reader was being shown a register that silently omitted data-at-rest
      // protection with nothing to say the evidence existed. Mapped to Annexure III PR.DS,
      // the data-security family this register already cites on keys 6 (PR.DS 173), 11
      // (PR.DS 170) and 21 (PR.DS 177) — not a Vajra-authored mapping.
      //
      // The test is ported verbatim from sebiComplianceChecks.ts checks['26'], including its
      // load-bearing reasoning: `percentage_encrypted === 100` on its own is NOT evidence of
      // protection, because a volume whose BitLocker protection is suspended still reports
      // 100% encrypted while its volume master key sits unprotected on disk — the state
      // Windows enters across firmware updates, and the state a local admin attacker would
      // choose. A pass therefore requires protection_status Protected AND conversion_status
      // Fully Encrypted. Status encodings are the ones NodesViewStorage.tsx renders from these
      // same rows (protection_status 1 Protected / 0 Unprotected / 2 Unknown;
      // conversion_status 1 Fully Encrypted / 0 Fully Decrypted / 2 In Progress / -1 N/A) and
      // a value outside them is not decoded into a verdict. No minimum encryption algorithm is
      // imposed — IRDAI Annexure III publishes none — so encryption_method is carried through
      // as an observed value only.
      {
        try {
          const storageRes = await nodesViewApi.getStorage(hostId);
          const storageInfo = storageRes as {
            data?: {
              bitlocker?: unknown;
              volumes?: Array<Record<string, unknown>>;
              data?: { bitlocker?: unknown; volumes?: Array<Record<string, unknown>> };
            };
          };
          const bitLockerData = storageInfo?.data?.bitlocker
            ?? storageInfo?.data?.data?.bitlocker
            ?? storageInfo?.data?.volumes?.find((v: Record<string, unknown>) => v.bitlocker)?.bitlocker
            ?? null;
          const blRows = Array.isArray(bitLockerData) ? (bitLockerData as Array<Record<string, unknown>>) : [];
          debugLog('[IRDAI Hot] BitLocker rows for control 31:', { hostId, count: blRows.length });

          const letterOf = (v: unknown) => String(v ?? '').trim().toUpperCase().replace(/:$/, '');
          const codeOf = (v: unknown) => {
            if (v === null || v === undefined || String(v).trim() === '') return null;
            const n = Number(v);
            return Number.isFinite(n) ? n : null;
          };
          const labelOf = (row: Record<string, unknown>) => {
            const letter = letterOf(row.drive_letter) || String(row.device_id ?? '').trim() || 'volume';
            const method = String(row.encryption_method ?? '').trim();
            return `${letter}${method ? ` (${method})` : ''}`;
          };

          // The boot/system volume is called out separately where the storage payload
          // identifies one: it carries the OS, and a suspension there is what matters most.
          const rawVolumes = storageInfo?.data?.data?.volumes ?? storageInfo?.data?.volumes ?? [];
          const bootLetters = new Set(
            (Array.isArray(rawVolumes) ? (rawVolumes as Array<Record<string, unknown>>) : [])
              .filter((v) => v?.bootPartition === true)
              .map((v) => letterOf(v?.mount ?? v?.name))
              .filter((letter) => letter.length > 0),
          );

          const protectedRows: Array<Record<string, unknown>> = [];
          const unprotectedRows: Array<Record<string, unknown>> = [];
          const undecodedRows: Array<Record<string, unknown>> = [];
          for (const row of blRows) {
            const ps = codeOf(row.protection_status);
            const cs = codeOf(row.conversion_status);
            if (ps === 1 && cs === 1) protectedRows.push(row);
            else if (ps === 0 || cs === 0 || cs === 2) unprotectedRows.push(row);
            else undecodedRows.push(row);
          }

          // The two failing states need different remediation: a volume that was never
          // encrypted has to be encrypted, while a volume that is 100% encrypted with
          // protection off (BitLocker suspended, or an OEM clear-key protector) only needs
          // protection resumed — but until it is, its master key is readable from disk.
          const neverEncryptedRows = unprotectedRows.filter((row) => codeOf(row.conversion_status) === 0);
          const encryptedUnprotectedRows = unprotectedRows.filter((row) => codeOf(row.conversion_status) === 1);
          const encryptionInProgressRows = unprotectedRows.filter((row) => codeOf(row.conversion_status) === 2);

          const systemRows = blRows.filter((row) => bootLetters.has(letterOf(row.drive_letter)));
          const systemNote = systemRows.length > 0
            ? ` System volume${systemRows.length !== 1 ? 's' : ''}: ${systemRows.map((row) => `${labelOf(row)} — ${protectedRows.includes(row) ? 'protection on, conversion complete' : unprotectedRows.includes(row) ? 'protection not active' : 'status not decodable'}`).join(', ')}.`
            : '';

          if (blRows.length === 0) {
            checks['31'] = {
              compliant: false,
              assessed: false,
              reason: 'Vajra holds no BitLocker volume records for this node, so whether its storage volumes are encrypted at rest with protection active was not measured. An empty record set is not evidence that the volumes are unencrypted.',
              detail: 'Not assessed — no BitLocker volume records',
            };
          } else if (unprotectedRows.length > 0) {
            checks['31'] = {
              compliant: false,
              reason: `BitLocker reports ${unprotectedRows.length} of ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} on this node without active protection.${neverEncryptedRows.length > 0 ? ` Never encrypted (BitLocker has to be turned on): ${neverEncryptedRows.map(labelOf).join(', ')}.` : ''}${encryptedUnprotectedRows.length > 0 ? ` Encrypted but unprotected — 100% encrypted with protection off, i.e. BitLocker suspended or holding only a clear-key protector, so the volume master key is readable from disk and protection has to be resumed: ${encryptedUnprotectedRows.map(labelOf).join(', ')}.` : ''}${encryptionInProgressRows.length > 0 ? ` Encryption still in progress: ${encryptionInProgressRows.map(labelOf).join(', ')}.` : ''} A volume can report 100% encrypted while its protection is suspended, so this control requires protection status "on" together with a completed conversion.${systemNote}`,
              detail: `${protectedRows.length} / ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} BitLocker-protected`,
            };
          } else if (undecodedRows.length > 0) {
            checks['31'] = {
              compliant: false,
              assessed: false,
              reason: `Vajra read ${blRows.length} BitLocker volume record${blRows.length !== 1 ? 's' : ''} for this node but could not decode the reported protection/conversion status of ${undecodedRows.length} of them (${undecodedRows.map(labelOf).join(', ')}), so encryption of data at rest was not measured.${systemNote}`,
              detail: 'Not assessed — undecodable BitLocker status',
            };
          } else {
            checks['31'] = {
              compliant: true,
              reason: `BitLocker reports all ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} on this node with protection on and conversion complete: ${protectedRows.map(labelOf).join(', ')}. Encryption methods are recorded as observed values; no minimum algorithm is applied, because IRDAI Annexure III publishes none.${systemNote}`,
              detail: `${protectedRows.length} / ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} BitLocker-protected`,
            };
          }
        } catch {
          checks['31'] = {
            compliant: false,
            assessed: false,
            reason: 'Vajra could not fetch storage encryption data for this node — the request failed before any volume record was returned — so encryption of data at rest was not measured. A failed request is not evidence that the volumes are unencrypted.',
            detail: 'Not assessed — storage encryption data fetch failed',
          };
        }
      }

      // Point 10: USB websocket check
      try {
      const usbStatus = await fetchUsbStatusForCompliance(hostId, node, wsConnected, wsSendMessage);
      // The point requires removable storage to be RESTRICTED, so a disabled/blocked policy is
      // the passing state and an enabled one is the failing state.
      //
      // 2026-09-07: decoding order corrected to match SEBI control 12, which answers the
      // identical question from the identical key-54 payload (sebiComplianceChecks.ts
      // checks['12']). The previous form was a flat three-way OR in each direction:
      //   compliant    = policy==='Disabled' || enabled===false || status==='disabled'
      //   nonCompliant = policy==='Enabled'  || enabled===true  || status==='enabled'
      // The Windows shape is { enabled, status: 'enabled'|'disabled'|'unknown', registry_start }
      // and it reports status 'unknown' — with `enabled` still carrying a boolean — when the
      // USBSTOR registry policy could NOT be read at all (NodesViewUsbControl.tsx derives its
      // own verdict from `status` alone for exactly this reason). Under the flat OR,
      // { enabled: false, status: 'unknown' } scored as a measured PASS and
      // { enabled: true, status: 'unknown' } as a measured FAIL — both fabricated verdicts on
      // an endpoint whose policy was never read. "Unknown" is not evidence in either direction.
      //
      // So: usb_storage_policy (the non-Windows removableDevice shape) decides when present;
      // otherwise the `status` field decides whenever the payload carries one; the boolean is
      // consulted only when there is no status field at all. Values are trimmed and lowercased
      // because neither register controls the casing the agent emits ('Disabled' in the status
      // field used to fall through to not-assessed here while SEBI decoded it).
      const usbPolicy = String(usbStatus?.usb_storage_policy ?? '').trim().toLowerCase();
      const usbStatusField = typeof usbStatus?.status === 'string'
        ? usbStatus.status.trim().toLowerCase()
        : null;
      const isUsbCompliant = usbPolicy === 'disabled'
        || (usbPolicy === '' && (usbStatusField !== null
          ? usbStatusField === 'disabled'
          : usbStatus?.enabled === false));
      const isUsbNonCompliant = usbPolicy === 'enabled'
        || (usbPolicy === '' && (usbStatusField !== null
          ? usbStatusField === 'enabled'
          : usbStatus?.enabled === true));
      debugLog('USB status for compliance:', { usbStatus, isUsbCompliant, isUsbNonCompliant });

      checks['10'] = {
        compliant: isUsbCompliant,
        // Only a response that actually reports the policy is a measured verdict. A response that
        // reports neither state, and the no-telemetry case, are indeterminate — not failures.
        ...(isUsbCompliant || isUsbNonCompliant ? {} : { assessed: false as const }),
        reason: usbStatus
          ? isUsbCompliant
            ? 'Vajra queried live USB telemetry and confirmed that removable storage is disabled or blocked on this node, satisfying the IRDAI removable media restriction requirement.'
            : isUsbNonCompliant
              ? 'Vajra queried live USB telemetry and found removable storage still enabled on this node, so the IRDAI removable media restriction requirement is not yet satisfied.'
              : usbStatusField === 'unknown'
                ? 'The agent returned a USB status of "unknown" for this node, meaning the removable-storage registry policy could not be read on the endpoint, so whether removable media is restricted was not measured. "Unknown" is not evidence that removable storage is blocked.'
                : 'Vajra queried live USB telemetry for this node but the response did not report a usable removable storage policy, so this point could not be assessed.'
          : 'Vajra could not retrieve live USB telemetry for this node from the websocket USB status query, so this point could not be assessed. Absent telemetry is not evidence that removable storage is unrestricted.',
        detail: usbStatus
          ? (usbStatus.usb_storage_policy
            ?? usbStatus.status
            ?? (usbStatus.enabled === false ? 'disabled' : usbStatus.enabled === true ? 'enabled' : 'unknown'))
          : 'USB status unavailable — not assessed',
      };
    } catch {
      checks['10'] = {
        compliant: false,
        assessed: false,
        reason: 'Vajra could not retrieve live USB telemetry for this node. The USB status query failed before a usable response was returned, so this point could not be assessed — a failed query is not evidence of non-compliance.',
        detail: 'USB status query failed — not assessed',
      };
    }

    // Point 17: "Default credentials for all system accounts are changed and strong
    // passwords enforced." Two limbs, only one of which Vajra measures.
    //
    // The enforcement limb is fully measured from the secedit policy row read above. The
    // default-credential limb is NOT: security_profile_info carries the built-in account
    // names and whether the guest account is enabled, but an account name is not evidence
    // about a password, and no per-account credential or password-age data exists anywhere
    // in the schema. So a violated enforcement limb fails the control on its own and says
    // so, while a satisfied enforcement limb can only be not-assessed — passing on half a
    // control is exactly the fabricated pass this register removed.
    {
      const minLength = profileInt('minimum_password_length');
      const complexity = profileInt('password_complexity');
      const history = profileInt('password_history_size');
      const guestEnabled = profileInt('enable_guest_account');
      const adminName = String(securityProfile.row?.new_administrator_name ?? '').trim();
      const guestName = String(securityProfile.row?.new_guest_name ?? '').trim();

      const violations: string[] = [];
      if (minLength !== null && minLength < IRDAI_MIN_PASSWORD_LENGTH) {
        violations.push(minLength === 0
          ? 'no minimum password length is enforced (measured as 0)'
          : `the minimum password length is ${minLength}, below the ${IRDAI_MIN_PASSWORD_LENGTH}-character baseline`);
      }
      if (complexity !== null && complexity !== 1) violations.push('complexity requirements are disabled');
      if (history !== null && history < 1) violations.push('password history is 0, so a previous password can be reused immediately');

      const accountNotes: string[] = [];
      if (guestEnabled === 1) accountNotes.push('the built-in Guest account is enabled on this node');
      if (adminName.toLowerCase() === 'administrator') accountNotes.push('the built-in administrator account is still named "Administrator"');
      if (guestName.toLowerCase() === 'guest') accountNotes.push('the built-in guest account is still named "Guest"');
      const accountText = accountNotes.length > 0
        ? ` Additionally observed on this endpoint: ${accountNotes.join('; ')} — reported as supporting detail only, since an account name is not evidence about a password.`
        : '';

      if (minLength === null && complexity === null && history === null) {
        checks['17'] = {
          compliant: false,
          assessed: false,
          reason: securityProfile.fetched
            ? 'No password policy values were read back for this node, so neither the strong-password enforcement limb nor the default-credential limb of this control could be measured. Absent policy telemetry is not evidence of non-compliance.'
            : 'The security policy request for this node did not complete, so neither the strong-password enforcement limb nor the default-credential limb of this control could be measured. A failed request is not evidence of non-compliance.',
          detail: securityProfile.fetched ? 'No password policy row — not assessed' : 'Security profile fetch failed — not assessed',
        };
      } else if (violations.length > 0) {
        checks['17'] = {
          compliant: false,
          reason: `Strong passwords are not enforced on this node: ${violations.join(', ')}. Whether the default credentials of the system accounts were actually changed is a separate limb that Vajra does not measure — no per-account credential or password-age data is collected — but the enforcement failure above is sufficient on its own for this control.${accountText}`,
          detail: minLength !== null ? `Minimum password length ${minLength}` : 'Password policy violated',
        };
      } else {
        checks['17'] = {
          compliant: false,
          assessed: false,
          reason: `The password enforcement limb of this control is satisfied on this node (${[
            minLength !== null ? `minimum length ${minLength}` : null,
            complexity === 1 ? 'complexity enabled' : null,
            history !== null ? `password history ${history}` : null,
          ].filter(Boolean).join(', ')}), but the default-credential limb is not measured: Vajra collects no per-account credential or password-age data, so whether the default credentials of every system account were changed is unknown. The control is therefore not scored as a pass on the measured half alone.${accountText}`,
          detail: 'Enforcement satisfied, default credentials not measured — not assessed',
        };
      }
    }

    // Point 18: Update history
      {
        try {
          // Same fetch control 12 reads — issued once per host, awaited twice.
          const updateHistoryRes = await updateHistoryPromise;
          const updateHistoryData = updateHistoryRes.data as { status?: string; data?: unknown[] } | null;

          if (updateHistoryData?.status === 'Success' && Array.isArray(updateHistoryData.data) && updateHistoryData.data.length > 0) {
            checks['18'] = {
              compliant: true,
              reason: `Vajra successfully fetched ${updateHistoryData.data.length} update history record(s) for this node, so the update-history visibility check is validated.`,
              detail: 'Update history fetched successfully',
            };
          } else {
            checks['18'] = {
              compliant: false,
              assessed: false,
              reason: 'Vajra fetched the update history endpoint, but no update history records were returned for this node, so the update-history visibility point could not be assessed.',
              detail: 'No update history records returned — not assessed',
            };
          }
        } catch {
          checks['18'] = {
            compliant: false,
            assessed: false,
            reason: 'Vajra could not fetch update history for this node, so the update-history visibility point could not be assessed. A failed API call is not evidence of non-compliance.',
            detail: 'Update history fetch failed — not assessed',
          };
        }
      }

          // Fallback defaults
          // Point 1 fallback: Software Asset Inventory & SBOM
          if (checks['1'] === undefined) {
            checks['1'] = { compliant: false, assessed: false, reason: 'The installed-software inventory request for this node did not complete, so whether a complete inventory of installed software, libraries and versions is maintained for it was not measured. A failed request is not evidence that no inventory exists.', detail: 'Software inventory request failed — not assessed' };
          }
          // Point 2: Being checked — when too few inventory fields were read back there is no verdict
          if (checks['2'] === undefined) {
            checks['2'] = { compliant: false, assessed: false, reason: 'Vajra did not read back enough hardware/OS inventory fields for this node to evaluate the hardware asset record, so this point could not be assessed. Missing inventory telemetry is not evidence that no inventory is maintained.', detail: 'Insufficient hardware inventory data — not assessed' };
          }
          // Point 3: "Audit logs are retained for authentication, access, privilege changes,
          // and system modifications." The four named families map onto the advanced-audit
          // subcategories that generate them: authentication → Credential Validation,
          // access → Logon and Special Logon, privilege changes → Security Group Management
          // and User Account Management, system modifications → Security System Extension
          // and Plug and Play Events. A subcategory that is Off never writes its events, and
          // a log family that is never generated cannot be retained — that is a measured
          // negative, not an inference from missing data. The retention PERIOD itself is not
          // collected by any Vajra probe, so an all-On host is not-assessed rather than a
          // pass: generation alone is not retention.
          //
          // The key set is deliberately the same as REQUIRED_AUDIT_KEYS in
          // utils/sebiComplianceChecks.ts: the SEBI register carries this control with
          // word-for-word the same text, and two registers asking the same question must
          // not answer it from different evidence.
          {
            const RETENTION_KEYS = ['5', '6', '9', '10', '12', '14', '16'];
            const off = RETENTION_KEYS.filter((key) => probe(key) === 'off');
            const on = RETENTION_KEYS.filter((key) => probe(key) === 'on');

            if (off.length === 0 && on.length === 0) {
              checks['3'] = {
                compliant: false,
                assessed: false,
                reason: baseline === null
                  ? `No Windows advanced-audit baseline within the last ${IRDAI_BASELINE_FRESHNESS_DAYS} days was read back for this node, so whether the authentication, access, privilege-change and system-modification log families are generated and retained was not measured.`
                  : 'The Windows advanced-audit baseline for this node returned no usable value for any of the subcategories behind the four named log families, so this control was not measured.',
                detail: 'No advanced-audit baseline — not assessed',
              };
            } else if (off.length > 0) {
              checks['3'] = {
                compliant: false,
                reason: `${off.length} of the ${RETENTION_KEYS.length} advanced-audit subcategories that generate the log families this control names are switched Off on this node: ${auditNames(off)}. Events that are never written cannot be retained, so those log families do not exist on this endpoint to be kept${baselineTakenText}.`,
                detail: `${off.length}/${RETENTION_KEYS.length} audit subcategories Off`,
              };
            } else {
              checks['3'] = {
                compliant: false,
                assessed: false,
                reason: `All ${on.length} measured advanced-audit subcategories behind the four named log families are On for this node, so those events are being generated. The retention PERIOD this control asks about is still unmeasured — Vajra collects no Windows event-log maximum size or retention setting from the endpoint — so the 180-day rolling retention of Annexure III PR.AC 145 could not be verified and the control is not scored as a pass on generation alone.`,
                detail: 'Log generation confirmed, retention period not measured — not assessed',
              };
            }
          }

          // Point 4: "Configuration changes to systems and software are tracked and logged."
          // Measured on the three settings that record a change as it is made: Process
          // Creation (the act of running the tool that changes something), command-line
          // capture in those events (which change was made), and Security System Extension
          // (service, driver and security-package installation). Unlike point 3 a genuine
          // pass exists here, because these three settings are the tracking itself rather
          // than the generation of logs whose retention is unmeasured.
          //
          // Same three limbs as the identically worded SEBI control in
          // utils/sebiComplianceChecks.ts. The legacy security_profile_info.audit_* columns
          // are deliberately not used: they describe the superseded basic audit policy and
          // say nothing about what the advanced policy actually in force audits.
          //
          // 2026-09-07: the limb SET matched SEBI control 5 but the pass THRESHOLD did not.
          // The pass branch here was the else of `off.length === 0 && on.length === 0` /
          // `off.length > 0`, i.e. it fired whenever at least ONE limb read On and none read
          // Off — and its reason string then asserted all three ("the act of changing a
          // configuration is recorded, the command that made the change is recorded with it,
          // and service, driver and security-package installation is recorded too") about
          // settings it had never read. On a host where Process Creation returns True and the
          // other two probes come back empty (the shape a failed probe takes), this register
          // passed while SEBI 5 correctly returned not-assessed on the identical evidence.
          // Asserting an unmeasured setting as satisfied is the same class of error as a
          // fabricated pass, so the pass now requires all three limbs readable and enabled —
          // `on.length === CONFIG_KEYS.length`, matching sebiComplianceChecks.ts checks['5']
          // (`measured.length === CHANGE_LIMBS.length`) — and the partial-but-clean case is
          // routed to not-assessed with the limbs it actually read named explicitly.
          {
            const CONFIG_KEYS = ['11', '17', '16'];
            const off = CONFIG_KEYS.filter((key) => probe(key) === 'off');
            const on = CONFIG_KEYS.filter((key) => probe(key) === 'on');

            if (off.length === 0 && on.length === 0) {
              checks['4'] = {
                compliant: false,
                assessed: false,
                reason: baseline === null
                  ? `No Windows advanced-audit baseline within the last ${IRDAI_BASELINE_FRESHNESS_DAYS} days was read back for this node, so whether configuration changes are tracked and logged was not measured.`
                  : 'The Windows advanced-audit baseline for this node returned no usable value for the security-configuration change subcategories, so this control was not measured.',
                detail: 'No advanced-audit baseline — not assessed',
              };
            } else if (off.length > 0) {
              checks['4'] = {
                compliant: false,
                reason: `Configuration changes made on this node are not fully recorded by it: ${auditNames(off)} ${off.length === 1 ? 'is' : 'are'} Off${baselineTakenText}. ${off.includes('11') ? 'The act of running the tool that changes a configuration is never recorded; ' : ''}${off.includes('17') ? 'even a recorded change does not show the command that made it; ' : ''}${off.includes('16') ? 'service, driver and security-package installation is not recorded; ' : ''}these are measured settings read from the endpoint, not missing data.`,
                detail: `${off.length}/${CONFIG_KEYS.length} configuration-change subcategories Off`,
              };
            } else if (on.length === CONFIG_KEYS.length) {
              checks['4'] = {
                compliant: true,
                reason: `This node records the configuration changes made on it (${auditNames(on)} are all On${baselineTakenText}): the act of changing a configuration is recorded, the command that made the change is recorded with it, and service, driver and security-package installation is recorded too. Together those three settings are the tracking and logging this control asks for.`,
                detail: `${on.length} / ${CONFIG_KEYS.length} configuration-change subcategories On`,
              };
            } else {
              // Partial but clean: nothing measured is in violation, but the limbs that
              // returned no value cannot be asserted as satisfied. Not-assessed, not a pass.
              checks['4'] = {
                compliant: false,
                assessed: false,
                reason: `Only ${on.length} of the ${CONFIG_KEYS.length} configuration-change subcategories returned a readable value on this node (${auditNames(on)}${on.length === 1 ? ', which is' : ', all of them'} On${baselineTakenText}); ${auditNames(CONFIG_KEYS.filter((key) => !on.includes(key) && !off.includes(key)))} returned nothing, so whether configuration changes are tracked and logged was only partly measured. Nothing measured was in violation, but an unread setting is not an enabled one.`,
                detail: `Not assessed — ${on.length} / ${CONFIG_KEYS.length} configuration-change subcategories readable`,
              };
            }
          }
          // Point 6: "Strong password rules ... are configured on this system."
          //
          // Two independent measurements of the same policy: the secedit-derived policy row
          // (minimum length, complexity, history, lockout threshold) and the `net accounts`
          // minimum-password-length baseline probe. Where both report the length they are
          // reported as corroborating each other. A value of 0 is a measured negative and a
          // real failure; a probe that returned an empty string is not a 0 and leaves the
          // control unmeasured. A pass requires length, complexity AND history to all be
          // measured and all satisfied — a partially measured policy cannot pass.
          {
            const profileLength = profileInt('minimum_password_length');
            const complexity = profileInt('password_complexity');
            const history = profileInt('password_history_size');
            const lockout = profileInt('lockout_bad_count');
            const rawProbeLength = baseline?.byKey['18'];
            const probeLength = rawProbeLength !== undefined && rawProbeLength !== '' && Number.isFinite(Number(rawProbeLength))
              ? Number(rawProbeLength)
              : null;
            const minLength = profileLength ?? probeLength;
            const corroborated = profileLength !== null && probeLength !== null && profileLength === probeLength;

            const violations: string[] = [];
            if (minLength !== null && minLength < IRDAI_MIN_PASSWORD_LENGTH) {
              violations.push(minLength === 0
                ? 'the minimum password length is measured as 0, so no minimum is enforced at all'
                : `the minimum password length is ${minLength}, below the ${IRDAI_MIN_PASSWORD_LENGTH}-character baseline`);
            }
            if (complexity !== null && complexity !== 1) violations.push('complexity requirements are disabled');
            if (history !== null && history < 1) violations.push('password history is 0, so a previous password can be reused immediately');
            if (lockout !== null && lockout === 0) violations.push('the account lockout threshold is 0, so failed sign-in attempts never lock the account');

            if (minLength === null && complexity === null && history === null && lockout === null) {
              checks['6'] = {
                compliant: false,
                assessed: false,
                reason: securityProfile.fetched || baseline !== null
                  ? 'Neither the security policy row nor the minimum-password-length probe returned a usable value for this node, so the password rules in force could not be measured. An empty probe result is not a measured zero.'
                  : 'No password policy could be read for this node: the security policy request did not complete and no Windows baseline probe row is available. Absent policy telemetry is not evidence of a weak password policy.',
                detail: 'No password policy measurement — not assessed',
              };
            } else if (violations.length > 0) {
              checks['6'] = {
                compliant: false,
                reason: `The password rules measured on this node do not meet the baseline: ${violations.join('; ')}.${corroborated ? ` The minimum length of ${minLength} is reported identically by two independent probes (the secedit security policy and \`net accounts\`), so it is not a parsing artefact.` : ''}`,
                detail: minLength !== null ? `Minimum length ${minLength}${complexity !== null ? `, complexity ${complexity === 1 ? 'on' : 'off'}` : ''}` : 'Password rules below baseline',
              };
            } else if (minLength !== null && complexity !== null && history !== null) {
              checks['6'] = {
                compliant: true,
                reason: `Strong password rules are configured on this node: minimum length ${minLength}, complexity requirements enabled, password history ${history}${lockout !== null ? `, account lockout threshold ${lockout}` : ''}.${corroborated ? ' The minimum length is corroborated by a second, independent probe.' : ''}`,
                detail: `Minimum length ${minLength}, complexity on`,
              };
            } else {
              checks['6'] = {
                compliant: false,
                assessed: false,
                reason: `Only part of the password policy was measured on this node (${[
                  minLength !== null ? `minimum length ${minLength}` : null,
                  complexity !== null ? `complexity ${complexity === 1 ? 'enabled' : 'disabled'}` : null,
                  history !== null ? `password history ${history}` : null,
                  lockout !== null ? `lockout threshold ${lockout}` : null,
                ].filter(Boolean).join(', ')}), and nothing measured is in violation. The unmeasured settings are not assumed compliant, so the control is not scored as a pass.`,
                detail: 'Password policy only partly measured — not assessed',
              };
            }
          }
          // POINT 7: Being checked with firewall rules API
          // POINT 8: the firewall rule list used by point 7 is not evidence of malicious IP/domain blocking.
          checks['8'] = { compliant: false, assessed: false, reason: 'Vajra applies no threat-intelligence feed to this endpoint and collects no per-host block-list enforcement state, so whether known malicious IP addresses and domains are blocked here was not measured. What is missing is a feed of known-bad indicators bound to this node plus a readback of which of them the endpoint is actually enforcing; the domain reputation lookups Vajra offers are an operator-driven query, not endpoint enforcement state.', detail: 'No threat feed bound to this endpoint — not assessed' };
          // Point 9: "An EDR solution is installed and actively running." Evaluated here on
          // its own terms from the shared EDR evidence measured above — it no longer copies
          // point 5's verdict or reason.
          if (edrEvidence.agentLive) {
            checks['9'] = {
              compliant: true,
              reason: `An EDR solution is installed and actively running on this node: the Vajra Agent is the endpoint detection and response product deployed here, and it last checked in at ${edrEvidence.agentSeenText}, streaming endpoint telemetry to this platform. The agent's own check-in is the direct measurement this control asks for.${edrEvidence.extraCoverageText}`,
              detail: 'Vajra EDR agent installed and running',
            };
          } else if (edrEvidence.activeCount > 0) {
            checks['9'] = {
              compliant: true,
              reason: `Windows Security Center reports ${edrEvidence.activeCount} antivirus/EDR product${edrEvidence.activeCount !== 1 ? 's' : ''} in state "On" on this node: ${edrEvidence.activeNames}. A product reported On is installed and actively running, satisfying this control.${edrEvidence.agentUnseenText}`,
              detail: `${edrEvidence.activeCount} AV/EDR product${edrEvidence.activeCount !== 1 ? 's' : ''} On`,
            };
          } else {
            checks['9'] = {
              compliant: false,
              assessed: false,
              reason: `Whether an EDR solution is installed and actively running on this node was not measured.${edrEvidence.agentUnseenText}${edrEvidence.productListRead ? ' No Windows Security Center product is in state "On" either, and Vajra does not register itself with Security Center, so that list cannot rule out the EDR deployed here.' : ' No Windows Security Center product list was read back for this node either.'}`,
              detail: 'Not assessed — EDR liveness not observed on this run',
            };
          }

          // POINT 10: USB: Being checked above
          // POINT 11: Unnecessary devices and services:
          // Point 11: listening-port telemetry exists in the fleet database but no API
          // exposes it to this register, and no approved services/ports baseline is defined.
          // Scoring on a hard-coded "unnecessary port" list is deliberately NOT done: 445
          // and 3389 are legitimately open across this fleet, so such a list would
          // manufacture failures rather than measure anything.
          checks['11'] = { compliant: false, assessed: false, reason: 'Which of this endpoint\'s services and ports are unnecessary was not measured. Vajra collects live listening-port telemetry from Windows hosts, but no API exposes it to the compliance register, and no approved services/ports baseline has been defined to judge the open ports against. Both are needed before this control can resolve; no default "risky port" list is assumed in their place.', detail: 'No services/ports baseline and no port API — not assessed' };

          // POINT 12: Being checked above — a missing/failed update query leaves the point unmeasured
          if (checks['12'] === undefined) {
            checks['12'] = { compliant: false, assessed: false, reason: 'Vajra did not obtain a usable Windows Update result for this node — no update summary was returned, the update query failed, or this is not a Windows endpoint — so patch SLA compliance could not be assessed. Absent patch telemetry is not evidence of an overdue patch.', detail: 'No usable update result — not assessed' };
          }

          // Point 13: "Automated alerts are generated for suspicious, anomalous, or
          // unauthorized access attempts."
          //
          // Asymmetric on purpose. An alert row raised FOR THIS ENDPOINT is direct evidence
          // that the detection pipeline produced alerts here — an endpoint measurement, not
          // a claim about the platform. Silence is not the opposite: Vajra cannot tell an
          // endpoint with nothing to alert on from one where alerting is not reaching it, so
          // zero alerts is never scored as a failure.
          {
            if (alertEvidence === null) {
              checks['13'] = {
                compliant: false,
                assessed: false,
                reason: 'The alert history for this endpoint could not be read on this run, so whether automated alerts are being generated for it was not measured. A failed request is not evidence that alerting is absent.',
                detail: 'Alert history unavailable — not assessed',
              };
            } else if (alertEvidence.inWindow > 0) {
              checks['13'] = {
                compliant: true,
                reason: `Vajra's detection pipeline raised ${alertEvidence.truncated ? 'at least ' : ''}${alertEvidence.inWindow} alert${alertEvidence.inWindow !== 1 ? 's' : ''} for this endpoint in the last ${IRDAI_ALERT_EVIDENCE_WINDOW_DAYS} days${alertEvidence.newestSec ? `, most recently at ${fmtDateTime(alertEvidence.newestSec)}` : ''}. Those alert records were produced by automated detection on this node's own telemetry, which is the measurement this control asks for. Whether every suspicious attempt on the endpoint produced one is not measurable from alert records alone.`,
                detail: `${alertEvidence.truncated ? '≥' : ''}${alertEvidence.inWindow} alerts in ${IRDAI_ALERT_EVIDENCE_WINDOW_DAYS} days`,
              };
            } else {
              checks['13'] = {
                compliant: false,
                assessed: false,
                reason: `No alert has been raised for this endpoint in the last ${IRDAI_ALERT_EVIDENCE_WINDOW_DAYS} days${alertEvidence.newestSec ? ` (the most recent one dates from ${fmtDateTime(alertEvidence.newestSec)})` : ''}. Vajra cannot distinguish an endpoint with nothing to alert on from one where alerting is not reaching it, so alert silence is reported as unmeasured rather than scored as a failure.`,
                detail: 'No alerts raised in the evidence window — not assessed',
              };
            }
          }

          // POINT 14: measured per host above, from this node's critical designation and
          // its own agent check-in. No fleet-wide fallback: a count of how many other nodes
          // are marked critical is not evidence about this endpoint.

          // Point 15: "User logins and session activities are tracked to detect suspicious
          // behavior." Decided on the Logon subcategory, which records interactive, network
          // and remote logon and logoff events; Special Logon (elevated/administrative
          // sessions) and Credential Validation are reported alongside it as coverage
          // detail, not as part of the verdict.
          {
            const logon = probe('14');
            const coverage = ` Alongside it on this node: ${describeProbe('5')}, and ${describeProbe('6')}.`;

            if (logon === 'on') {
              checks['15'] = {
                compliant: true,
                reason: `Logon auditing is enabled on this node, so interactive, network and remote logons and logoffs are written to the Security log and user session activity is tracked${baselineTakenText}.${coverage}`,
                detail: 'Logon auditing On',
              };
            } else if (logon === 'off') {
              checks['15'] = {
                compliant: false,
                reason: `Logon auditing is Off on this node, so logons and logoffs are never written to the Security log and user login and session activity is not tracked on this endpoint${baselineTakenText}.${coverage}`,
                detail: 'Logon auditing Off',
              };
            } else {
              checks['15'] = {
                compliant: false,
                assessed: false,
                reason: baseline === null
                  ? `No Windows advanced-audit baseline within the last ${IRDAI_BASELINE_FRESHNESS_DAYS} days was read back for this node, so whether user logins and session activity are tracked was not measured.`
                  : 'The Logon auditing probe returned no usable value for this node, so whether user logins and session activity are tracked was not measured. An empty probe result is not a measured negative.',
                detail: 'Logon auditing not measured — not assessed',
              };
            }
          }

          // POINT 16: the security profile fetch used by point 17 is not an account/privilege review.
          checks['16'] = { compliant: false, assessed: false, reason: 'Vajra collects no local user account inventory from this endpoint — no list of accounts and no group membership or privilege level is gathered by any probe, and no API exposes one to this register. The only endpoint account state Vajra holds is whether the built-in Administrator and Guest accounts are enabled and whether they have been renamed, which is neither the account list nor the privilege levels this control asks to be reviewed. What is missing is collection of the operating system\'s user and user-group tables from the agent.', detail: 'No local account inventory collected — not assessed' };

          // POINT 18: Being checked above

          // Point 19: "All local firewall rules and status are collected and reviewed for
          // unauthorized changes."
          //
          // Vajra does keep prior rule snapshots per host and ships a diff engine over them
          // (POST /api/windows/firewall_rules_diff), so the collection-and-change-review this
          // control asks for is genuinely performed: two or more snapshots inside the window
          // are compared and the added, deleted and modified rules are surfaced. Fewer than
          // two snapshots in the window means no comparison happened — an absence, not a
          // failure. Vajra still holds no approved-rule baseline, so "unauthorized" remains
          // an operator judgement on the surfaced changes; the reason says so rather than
          // implying the platform made that call.
          {
            const nowSec = Math.floor(Date.now() / 1000);
            const windowStartSec = nowSec - IRDAI_FIREWALL_REVIEW_WINDOW_DAYS * 86400;
            const collectedText = firewallRuleCount === null
              ? ''
              : ` ${firewallRuleCount} rule${firewallRuleCount !== 1 ? 's' : ''} are currently collected from this host.`;
            try {
              const diffRes = await nodesViewApi.getFirewallRulesDiff(hostId, String(windowStartSec), String(nowSec));
              const diffPayload = diffRes.data as {
                status?: string;
                data?: {
                  meta?: { snapshots_compared?: number; actual_start?: string; actual_end?: string };
                  summary?: { added_count?: number; deleted_count?: number; modified_count?: number };
                };
              } | null;
              const meta = diffPayload?.status === 'Success' ? diffPayload.data?.meta : undefined;
              const summary = diffPayload?.status === 'Success' ? diffPayload.data?.summary : undefined;
              const compared = Number(meta?.snapshots_compared);

              if (!summary || !Number.isFinite(compared) || compared < 2) {
                checks['19'] = {
                  compliant: false,
                  assessed: false,
                  reason: `Fewer than two firewall rule snapshots exist for this host inside the last ${IRDAI_FIREWALL_REVIEW_WINDOW_DAYS} days${Number.isFinite(compared) ? ` (${compared} found)` : ''}, so no change review could be performed over that window and this control was not measured.${collectedText} Having too few snapshots to compare is an absence of evidence, not a failed review.`,
                  detail: 'Too few snapshots in the review window — not assessed',
                };
              } else {
                const added = Number(summary.added_count ?? 0);
                const deleted = Number(summary.deleted_count ?? 0);
                const modified = Number(summary.modified_count ?? 0);
                const newestText = meta?.actual_end && Number.isFinite(Number(meta.actual_end))
                  ? ` The newest snapshot compared was taken ${fmtDateTime(Number(meta.actual_end))}.`
                  : '';
                // Collection is genuinely measured here — compared snapshots exist and the
                // added/deleted/modified diff is real — but "reviewed for unauthorized
                // changes" needs an approved-rule baseline to judge those changes against,
                // which Vajra does not hold. Passing on snapshot count alone (this control
                // is >=2 for effectively every alive host, since rules are collected every
                // ~45 minutes) would be a fabricated pass on the review half of the control,
                // exactly like keys 3, 17 and 24. So this stays not-assessed and states
                // plainly what WAS measured.
                checks['19'] = {
                  compliant: false,
                  assessed: false,
                  reason: `Firewall rules and status ARE collected and diffed for this node: ${compared} snapshots over the last ${IRDAI_FIREWALL_REVIEW_WINDOW_DAYS} days show ${added} rule${added !== 1 ? 's' : ''} added, ${deleted} deleted and ${modified} modified.${collectedText}${newestText} Vajra holds no approved-rule baseline, so whether any of these changes is unauthorized was not measured — that judgement needs a stored baseline to compare against, which does not exist for this node.`,
                  detail: `${compared} snapshots compared · not assessed — no approved-rule baseline`,
                };
              }
            } catch {
              checks['19'] = {
                compliant: false,
                assessed: false,
                reason: `No firewall rule snapshot for this host could be compared over the last ${IRDAI_FIREWALL_REVIEW_WINDOW_DAYS} days — the change-review request returned no snapshots in that range or did not complete — so whether local firewall rules and status are collected and reviewed for unauthorized changes was not measured.${collectedText}`,
                detail: 'Firewall change review unavailable — not assessed',
              };
            }
          }

          // Point 20: "Endpoint antivirus/EDR client is installed and reporting healthy
          // status." A measured signature-currency negative decides first: a client whose
          // definitions are stale is not "healthy", regardless of whether the Vajra Agent
          // itself is live or Security Center shows the product state as On — agent
          // liveness and an On state both speak to "installed and running" (point 9), not
          // to "reporting healthy status", which this control specifically asks for.
          if (edrEvidence.staleSignatureProductsPresent) {
            checks['20'] = {
              compliant: false,
              reason: `The antivirus client on this node is not reporting healthy status: Windows Security Center reports the signatures of ${edrEvidence.staleSignatureNames} as out of date. An out-of-date product is not healthy even while it is installed and running.`,
              detail: `Definitions out of date: ${edrEvidence.staleSignatureNames}`,
            };
          } else if (edrEvidence.staleSignatureDate) {
            checks['20'] = {
              compliant: false,
              reason: `The antivirus client on this node is not reporting healthy status: the Defender signature set was last updated ${edrEvidence.signatureAgeDays} days ago (${edrEvidence.signatureUpdatedRaw}), beyond the ${SIGNATURE_MAX_AGE_DAYS}-day bound this check treats as current, even though Windows Security Center still reports the definitions as up to date. An out-of-date product is not healthy even while it is installed and running.`,
              detail: `Defender signatures ${edrEvidence.signatureAgeDays} days old`,
            };
          } else if (edrEvidence.agentLive) {
            checks['20'] = {
              compliant: true,
              reason: `The endpoint EDR client on this node is the Vajra Agent, and it is reporting healthy: its most recent status report reached the platform at ${edrEvidence.agentSeenText}, so the client is both installed and successfully reporting its own health. No antivirus product on this node was found with stale signatures.${edrEvidence.extraCoverageText}`,
              detail: 'Vajra EDR client reporting healthy',
            };
          } else if (edrEvidence.activeCount > 0) {
            checks['20'] = {
              compliant: true,
              reason: `Windows Security Center reports ${edrEvidence.activeCount} antivirus/EDR client${edrEvidence.activeCount !== 1 ? 's' : ''} on this node in state "On" with current signatures: ${edrEvidence.activeNames}. A client reported On with current definitions is installed and reporting healthy status.${edrEvidence.agentUnseenText}`,
              detail: `${edrEvidence.activeCount} AV/EDR client${edrEvidence.activeCount !== 1 ? 's' : ''} reporting On`,
            };
          } else {
            checks['20'] = {
              compliant: false,
              assessed: false,
              reason: `No health report was observed from any antivirus/EDR client on this node during this run, so whether the client is installed and reporting healthy status was not measured.${edrEvidence.agentUnseenText} A client that has not reported is not the same as a client that is absent or unhealthy.`,
              detail: 'Not assessed — no AV/EDR client health report observed',
            };
          }

          // Point 21: "Removable media (USB, external drives) usage logs are collected and
          // reviewed." Decided on the Plug and Play Events subcategory, which is what makes
          // Windows write an event when removable media is attached. The USB policy verdict
          // of point 10 is a different question and is not reused here.
          {
            const pnp = probe('12');
            if (pnp === 'on') {
              checks['21'] = {
                compliant: true,
                reason: `Plug and Play event auditing is enabled on this node, so attaching removable media writes an event to the Security log and removable-media usage is logged on this endpoint${baselineTakenText}. Reviewing those logs remains the operator's task — Vajra collecting telemetry does not discharge the review half of this control.`,
                detail: 'Plug and Play auditing On',
              };
            } else if (pnp === 'off') {
              checks['21'] = {
                compliant: false,
                reason: `Plug and Play event auditing is Off on this node, so attaching a USB device or external drive writes no event and removable-media usage is not logged on this endpoint${baselineTakenText}.`,
                detail: 'Plug and Play auditing Off',
              };
            } else {
              checks['21'] = {
                compliant: false,
                assessed: false,
                reason: baseline === null
                  ? `No Windows advanced-audit baseline within the last ${IRDAI_BASELINE_FRESHNESS_DAYS} days was read back for this node, so whether removable-media usage is logged was not measured.`
                  : 'The Plug and Play event auditing probe returned no usable value for this node, so whether removable-media usage is logged was not measured.',
                detail: 'Plug and Play auditing not measured — not assessed',
              };
            }
          }

          // POINT 22: no running-process or service inventory is collected from the endpoint.
          checks['22'] = { compliant: false, assessed: false, reason: 'Vajra holds no running-process or service inventory for this endpoint: no point-in-time snapshot of processes, services or their open sockets is collected by any probe, and no API exposes one to this register. Advanced-audit Process Creation logging is measured separately (it records process starts as events) and is not an inventory of what is running now. What is missing is collection of the operating system\'s process and service tables from the agent.', detail: 'No process/service inventory collected — not assessed' };

          // POINT 23: no NTP/time-sync telemetry exists. Note the trap: the only clock-related
          // probe Vajra runs is a TIMEZONE check (baseline key 3, `(Get-TimeZone).DisplayName`).
          // A timezone is a display setting, not a synchronisation state, and it must never be
          // mapped to this control.
          checks['23'] = { compliant: false, assessed: false, reason: 'Vajra collects no NTP configuration, no configured time source or peer and no last-synchronisation time from this endpoint, so whether the system clock is synchronised with a trusted source was not measured. The only clock-related probe Vajra runs reports the configured timezone, which says nothing about synchronisation and is deliberately not read as a sync verdict. What is missing is a time-service status probe on the agent (the configured peers and last sync time) and somewhere to store its result.', detail: 'No time-synchronisation telemetry collected — not assessed' };

          // Point 24: "Failed login attempts and account lockouts are logged and alerted."
          //
          // Measured on the three subcategories that write those events: Account Lockout
          // (the lockout itself), Credential Validation (failed NTLM/Kerberos
          // authentication) and Logon (failed interactive and network logons). Each of these
          // probes is True only when BOTH Success and Failure are audited, which is exactly
          // what "failed attempts are logged" requires. The "and alerted" limb is not
          // measured — Vajra collects no endpoint alert-rule configuration — so a fully
          // audited host is not-assessed rather than a pass.
          {
            const LOGIN_KEYS = ['13', '6', '14'];
            const off = LOGIN_KEYS.filter((key) => probe(key) === 'off');
            const on = LOGIN_KEYS.filter((key) => probe(key) === 'on');
            const lockoutThreshold = profileInt('lockout_bad_count');
            const lockoutText = lockoutThreshold === null
              ? ''
              : lockoutThreshold > 0
                ? ` The account lockout threshold on this node is ${lockoutThreshold} bad attempts, so lockouts do occur${off.includes('13') ? ' — they are simply never audited' : ''}.`
                : ' No account lockout threshold is set on this node at all, so no lockout can occur to be logged.';

            if (off.length === 0 && on.length === 0) {
              checks['24'] = {
                compliant: false,
                assessed: false,
                reason: baseline === null
                  ? `No Windows advanced-audit baseline within the last ${IRDAI_BASELINE_FRESHNESS_DAYS} days was read back for this node, so whether failed login attempts and account lockouts are logged was not measured.${lockoutText}`
                  : `The auditing probes behind failed logons and account lockouts returned no usable value for this node, so this control was not measured.${lockoutText}`,
                detail: 'Logon/lockout auditing not measured — not assessed',
              };
            } else if (off.length > 0) {
              checks['24'] = {
                compliant: false,
                reason: `Auditing for failed authentication and account lockouts is Off on this node: ${auditNames(off)}. ${off.includes('13') ? 'Lockout events are never written to the Security log; ' : ''}${off.includes('6') ? 'failed authentications are not recorded; ' : ''}so failed login attempts and lockouts are not logged on this endpoint${baselineTakenText}.${lockoutText}`,
                detail: `${off.length}/${LOGIN_KEYS.length} logon/lockout subcategories Off`,
              };
            } else {
              checks['24'] = {
                compliant: false,
                assessed: false,
                reason: `All measured subcategories behind failed logons and account lockouts are auditing on this node (${auditNames(on)}), so the logging limb of this control is satisfied. The "and alerted" limb is not measured — Vajra collects no endpoint alert-rule configuration for these events — so the control is not scored as a pass on the logging half alone.${lockoutText}`,
                detail: 'Logging confirmed, alerting not measured — not assessed',
              };
            }
          }
          // POINT 25: ??

          // POINT 26: Being checked above

          // POINT 27:
          checks['27'] = { compliant: false, assessed: false, reason: `Vajra holds a complete installed-application inventory for this host${installedProgramCount !== null ? ` (${installedProgramCount} program${installedProgramCount !== 1 ? 's' : ''})` : ''}, but no authorised software list exists to compare it against: no software whitelist has been defined for this node. The Windows patch-management catalogue is an install source, not an organisational authorisation baseline, and is deliberately not substituted for one — doing so would invent the very list this control requires the operator to supply. The comparison therefore was not performed.`, detail: installedProgramCount !== null ? `${installedProgramCount} programs inventoried, no authorised list to compare — not assessed` : 'No authorised software list defined — not assessed' }

          // POINT 28
          checks['28'] = { compliant: false, assessed: false, reason: 'Whether this node is isolated from the network when a major threat is detected was not measured. Vajra can isolate an endpoint on demand, but no isolation event is recorded against any detection and no per-host isolation-readiness state is collected, so nothing links a detection on this endpoint to a containment action on it. Platform capability is not evidence of endpoint state, and it is not reported as such here.', detail: 'No detection-to-isolation record for this endpoint — not assessed' };

          // POINT 29
          checks['29'] = { compliant: false, assessed: false, reason: 'Whether this node protects its own audit logs from unauthorized modification or deletion was not measured. That answer needs the Security event-log channel access control list (EventLog\\Security\\CustomSD) and the crash-on-audit-failure policy, neither of which Vajra collects from the endpoint. Vajra securing the copy of the telemetry it receives answers a different question about a different system and is not evidence about this node\'s logs.', detail: 'Event-log ACL and audit-failure policy not collected — not assessed' };

  // Filtered here, at the source, so every consumer — the live single-device sweep's
  // pass/fail/not-assessed KPI count, the persisted compliance_data snapshot, the fleet
  // reducer, and the rendered table — is automatically correct without each call site
  // having to remember to filter. Mirrors utils/sebiComplianceChecks.ts's return.
  return Object.fromEntries(
    Object.entries(checks).filter(
      ([key]) => !HIDDEN_GUIDELINES.has(key) && !STRUCTURALLY_UNMEASURABLE_IRDAI_KEYS.has(key)
    )
  );
}

export default function NodesViewIRDAIHotCompliance({
  node,
  wsConnected = false,
  wsSendMessage,
  agentOnline = true,
}: NodesViewIRDAIHotComplianceProps) {
  const hostLabel = node.hostname || node.name || `Node ${node.id}`;
  const hostId = node.host_identifier || String(node.id);

  const [staticChecks, setStaticChecks] = useState<Record<string, StaticCheckResult | undefined>>({});
  const [fleetPointStats, setFleetPointStats] = useState<Record<string, FleetPointStat>>({});
  const [hasRefreshed, setHasRefreshed] = useState(false);

  const [downloadLoading, setDownloadLoading] = useState(false);
  
  const [oneDeviceCompliance, setOneDeviceCompliance] = useState(false);
  const [orgHistory, setOrgHistory] = useState<OrgSnapshot[]>([]);
  const [orgHistoryLoading, setOrgHistoryLoading] = useState(false);
  const [orgHistoryError, setOrgHistoryError] = useState(false);

  const [historyLoading, setHistoryLoading] = useState(false);
  const [history, setHistory] = useState<ComplianceRecord[]>([]);
  const [historyError, setHistoryError] = useState(false);
  const [sortBy, setSortBy] = useState<'default' | '100_compliant' | 'not_100_compliant'>('default');

  const [pointsLoading, setPointsLoading] = useState(false);

  const [onlineNodes, setOnlineNodes] = useState<number | null>(null);
  const [totalWindowsNodes, setTotalWindowsNodes] = useState<number | null>(null);

  const [, setAggregateCompliance] = useState(0);
  const [, setAverageCompliance] = useState(0);

  const [totalNodes, setTotalNodes] = useState(0);
  const [fullyCompliantNodes, setFullyCompliantNodes] = useState(0);
  const [, setActiveIndex] = useState(0);

  // Fetch latest saved record from API
  
  // Fetch history for trend chart
  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await api.get(`${NODES_URLS.IRDAI_NODE_COMPLIANCE_HISTORY}${encodeURIComponent(hostId)}`);
      const json = res.data;
      if (json.success) {
        setHistory(json.data ?? []);
        setHistoryError(false);
      } else {
        setHistoryError(true);
      }
    } catch (err: unknown) {
      if (import.meta.env.DEV) {
        console.warn('IRDAI Hot history fetch:', err);
      }
      setHistoryError(true);
    } finally {
      setHistoryLoading(false);
    }
  }, [hostId]);

  const fetchOrgHistory = useCallback(async () => {
      setOrgHistoryLoading(true);
      try {
        const res = await api.get(NODES_URLS.IRDAI_COMPLIANCE_HISTORY);
        const json = res.data;
        if (json?.success && Array.isArray(json.data)) {
          setOrgHistory(json.data as OrgSnapshot[]);
          setOrgHistoryError(false);
        } else {
          setOrgHistoryError(true);
        }
      } catch {
        setOrgHistoryError(true);
      } finally {
        setOrgHistoryLoading(false);
      }
    }, []);

  const fetchOnlineNodes = useCallback(async () => {
    const res = await api.get(NODES_URLS.NODES_IDENTIFIERS);
      const json = res.data;
      const nodesArray: Array<Record<string, unknown>> = Array.isArray(json?.data)
        ? json.data
        : Array.isArray(json?.nodes)
          ? json.nodes
          : Array.isArray(json)
            ? json
            : [];

      const isWindowsNode = (n: Record<string, unknown>) => {
        const osName = String(n?.os_name ?? '').toLowerCase();
        const osPlatform = String(n?.os_platform ?? '').toLowerCase();
        return osName.includes('windows') || osPlatform.includes('windows');
      };

      const isOnlineNode = (n: Record<string, unknown>) => {
        const status = String(n?.status ?? n?.displayStatus ?? '').toLowerCase();
        return n?.agent_online === true || status === 'online';
      };

      const windowsCandidates = nodesArray.filter(isWindowsNode);
      const windowsOnline = windowsCandidates.filter(isOnlineNode);
      setOnlineNodes(windowsOnline.length);
      setTotalWindowsNodes(windowsCandidates.length);
  }, []);


  useEffect(() => {
    if (hostId === '0') {
      fetchOrgHistory();
      fetchOnlineNodes();
      setOneDeviceCompliance(false);
    }
    else {
      setPassCount(0);
      setFailCount(0);
      setNotAssessedCount(0);
      fetchHistory();
      setOneDeviceCompliance(true);
    }
  }, [fetchHistory, fetchOnlineNodes, fetchOrgHistory, hostId]);

  useEffect(() => {
  setPointsLoading(true);
  if (hostId !== '0') {
    setPointsLoading(false);
    return;
  }

  const latest = orgHistory?.[0];

  if (!latest) {
    setPointsLoading(false);
    return;
  }

  const nextStats: Record<string, FleetPointStat> = {};
  const nextChecks: Record<string, StaticCheckResult> = {};

  latest.control_pass_rates.forEach((control) => {
    // Dropped from this register's table entirely — a stored row for one of these
    // (including rows saved before this exclusion existed, or before a control was
    // reclassified into this set) must not populate the fleet stats/checks state a
    // restored snapshot renders from. Mirrors the identical guard in the parallel SEBI
    // org-level restore effect (NodesViewSebiHotCompliance.tsx).
    if (STRUCTURALLY_UNMEASURABLE_IRDAI_KEYS.has(String(control.key))) return;
    nextStats[control.key] = {
      passed: control.passHosts,
      total: control.eligibleHosts,
      // Hosts that produced results in this snapshot but on which this control could not
      // be measured. They sit outside passed/total, so without this the operator has no
      // way to see how many endpoints the fraction leaves out.
      notAssessed: Math.max(0, (latest.windows_with_results ?? 0) - (control.eligibleHosts ?? 0)),
    };

    const passHosts = control.passHosts ?? 0;
    const eligibleHosts = control.eligibleHosts ?? 0;

    // Satisfied only when every assessed host passed; some hosts passing is a partial
    // result, and no assessed host at all is not-assessed, never a fleet failure.
    nextChecks[control.key] = eligibleHosts > 0
      ? {
          compliant: passHosts === eligibleHosts,
          reason: passHosts === eligibleHosts
            ? `All ${eligibleHosts} assessed node${eligibleHosts !== 1 ? 's' : ''} passed this control in the latest snapshot.`
            : passHosts > 0
              ? `Partial: ${passHosts}/${eligibleHosts} assessed nodes passed this control in the latest snapshot.`
              : `None of the ${eligibleHosts} assessed node${eligibleHosts !== 1 ? 's' : ''} passed this control in the latest snapshot.`,
          detail: `${control.passRatePct}% pass rate`,
        }
      : {
          compliant: false,
          assessed: false,
          reason: 'No node produced a measured result for this control in the latest snapshot.',
          detail: 'Not assessed',
        };

  });

  const totalPasses =
    latest.control_pass_rates?.reduce(
      (sum, control) => sum + (control.passHosts ?? 0),
      0
    ) ?? 0;

  const totalFails =
    latest.control_pass_rates?.reduce(
      (sum, control) => sum + ((control.eligibleHosts - control.passHosts)),
      0
    ) ?? 0;

  const aggPerecent = totalPasses + totalFails > 0 ? (totalPasses / (totalPasses + totalFails) * 100) : 0;
  
  setHasRefreshed(true);
  setPointsLoading(false);
  setStaticChecks(nextChecks);
  setFleetPointStats(nextStats);
  setFullyCompliantNodes(latest.fully_compliant_nodes ?? 0);

  setAverageCompliance(
    latest.avg_compliance_percent ?? 0
  );

  setTotalNodes(
    latest.windows_with_results ?? 0
  );

  setAggregateCompliance(
    aggPerecent
  );
}, [orgHistory, hostId]);

useEffect(() => {
    setPointsLoading(true);
    if (hostId === '0') {
      setPointsLoading(false);
      return;
    }
  
    const latest = history?.[0];
  
    if (!latest) {
      setPointsLoading(false);
      return;
    }
    
    // Stored rows may predate a control being reclassified as structurally
    // unmeasurable (Class A) and dropped from the register — those keys still sit in
    // the persisted compliance_data array forever, so every count derived from it
    // must be taken over the CURRENT command-key set, not the raw stored array, or a
    // removed control keeps inflating the not-assessed tally after it has been hidden
    // from the table.
    const currentCompliancePoints = latest.compliance_data.filter(
      (check) => IRDAI_HOT_COMMAND_KEYS.includes(check.command_key),
    );

    // A stored 'true' for a key in IRDAI_LEGACY_IMPOSSIBLE_PASS_KEYS is not a real
    // verdict — the current evaluator for that control has no branch left that can
    // produce compliant:true, so the row predates a scoring-logic change and is a
    // replay of a prior run's rules, not evidence about this node today. Treated as
    // not-assessed everywhere below (score and table alike), exactly like a genuine
    // stored 'not_assessed' — never as a pass.
    const isLegacyImpossiblePass = (check: { command_key: string; output: string }) =>
      check.output === 'true' && IRDAI_LEGACY_IMPOSSIBLE_PASS_KEYS.has(check.command_key);

    // Points stored as 'not_assessed' were never measured, so they are excluded from the score
    // rather than counted as either a pass or a fail. Same treatment for a legacy
    // impossible-pass row, per the comment above.
    const assessedData = currentCompliancePoints.filter(
      (check) => check.output !== 'not_assessed' && !isLegacyImpossiblePass(check),
    );

    const totalChecks = assessedData.length;

    const passedChecks = assessedData.filter(
      (check) => check.output === 'true' // or whatever your pass condition is
    ).length;

    const nextChecks: Record<string, StaticCheckResult> = {};

    // Stored snapshots keep only the verdict for each control; the measurement that
    // produced it is not persisted. The reason shown for a replayed row therefore says
    // exactly that, instead of echoing the raw stored value ('true'/'false').
    currentCompliancePoints.forEach((item) => {
      const legacyImpossiblePass = isLegacyImpossiblePass(item);
      nextChecks[item.command_key] = item.output === 'not_assessed' || legacyImpossiblePass
        ? {
            compliant: false,
            assessed: false,
            detail: legacyImpossiblePass
              ? 'Scoring rules changed since this run — not assessed'
              : 'Not assessed in the last recorded compliance run',
            reason: legacyImpossiblePass
              ? 'This control was recorded as compliant in an older stored compliance run, but the current scoring logic for this control (see staticComplianceChecks above) has no branch that can produce a pass verdict — the stored "true" predates that change and is not evidence of a current pass. Re-run the compliance check to get a verdict under the current scoring rules.'
              : 'This control was recorded as not assessed in the last stored compliance run for this node, so it counts as neither a pass nor a fail. Stored snapshots keep only the verdict — re-run the compliance check to see the current measurement and its reason.',
          }
        : {
            compliant: item.output === 'true',
            detail: item.output === 'true' ? 'Compliant based on latest agent data' : 'Non-compliant based on latest agent data',
            reason: item.output === 'true'
              ? 'Recorded as compliant in the last stored compliance run for this node. Stored snapshots keep only the verdict, not the evidence that produced it — re-run the compliance check to see the current measurement and its reason.'
              : 'Recorded as non-compliant in the last stored compliance run for this node. Stored snapshots keep only the verdict, not the evidence that produced it — re-run the compliance check to see the current measurement and its reason.',
          };
    });

    setPassCount(passedChecks);
    setFailCount(totalChecks - passedChecks);
    setNotAssessedCount(currentCompliancePoints.length - totalChecks);

    setHasRefreshed(true);
    setStaticChecks(nextChecks);
    
    setPointsLoading(false);
  
  }, [history, hostId]);

  const [passCount, setPassCount] = useState(0);
  const [failCount, setFailCount] = useState(0);
  // Controls Vajra could not measure. Counted and shown on their own, never as failures.
  const [notAssessedCount, setNotAssessedCount] = useState(0);

  const [noWindowsOnline, setNoWindowsOnline] = useState(false);

  const handleOneDeviceCompliance = useCallback(async () => {
    try {
      setHasRefreshed(true);
      setPointsLoading(true);
      const checks = await staticComplianceChecks(
        hostId,
        node,
        wsConnected,
        wsSendMessage
      );

      let pass = 0;
      let fail = 0;
      let notAssessed = 0;

      Object.values(checks).forEach((result) => {
        if (!result) return;

        if (isNotAssessed(result)) {
          notAssessed += 1;
          return;
        }

        if (isPass(result)) {
          pass += 1;
        } else {
          fail += 1;
        }
      });

      setPassCount(pass);
      setFailCount(fail);
      setNotAssessedCount(notAssessed);

      debugLog('[IRDAI Hot] One-device compliance', {
        hostId,
        pass,
        fail,
        notAssessed,
        total: pass + fail,
      });
      setPointsLoading(false);
      setStaticChecks(checks);

      const complianceData = Object.entries(checks).map(([command_key, result]) => {
        return {
          command_key,
          output: isPass(result) ? 'true' : isFail(result) ? 'false' : 'not_assessed',
        };
      });

      try {
        await fetchWithCsrf(`${NODES_URLS.IRDAI_NODE_COMPLIANCE_SNAPSHOT}${encodeURIComponent(hostId)}`, {
          method: 'POST',
          credentials: 'include',
          headers: csrfHeadersJson(),
          body: JSON.stringify({
            hostIdentifier: hostId,
            unixtime: Math.floor(Date.now() / 1000),
            complianceData,
          }),
        });

        // Refresh latest/history after saving
        void fetchHistory();
      } catch (err) {
        console.error('[IRDAI Hot] Failed to save compliance snapshot:', err);
      }
    } catch (err) {
      console.error('[IRDAI Hot] Failed to calculate compliance:', err);
    }
  }, [fetchHistory, hostId, node, wsConnected, wsSendMessage]);

  const handleDownloadVajraCompliance = useCallback(async () => {
    if (downloadLoading) return;

    setDownloadLoading(true);
    try {
      const downloadUrl = `${API_BASE_URL}/api/compliance/reports/irdai-pdf`;
      const response = await fetch(downloadUrl, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new Error(errorText || `Download failed with status ${response.status}`);
      }

      const contentType = response.headers.get('content-type') ?? '';
      if (!contentType.toLowerCase().includes('pdf')) {
        const preview = await response.text().catch(() => '');
        throw new Error(preview || `Unexpected response type: ${contentType || 'unknown'}`);
      }

      const blob = await response.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = 'vajra-irdai-compliance.pdf';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(objectUrl);
    } catch (error) {
      console.error('Failed to download Vajra Compliance PDF', error);
    } finally {
      setDownloadLoading(false);
    }
  }, [downloadLoading]);

  const handleRefresh = async () => {
    try {
      setHasRefreshed(true);
      setPointsLoading(true);
      setNoWindowsOnline(false);
      let currentChecks: Record<string, StaticCheckResult | undefined> = {};
      if (hostId !== '0') {
        currentChecks = await staticComplianceChecks(hostId, node);
        setStaticChecks(currentChecks);
      }

      const res = await api.get(NODES_URLS.NODES_IDENTIFIERS);

      const json = res.data;
      const nodesArray: Array<Record<string, unknown>> = Array.isArray(json?.data)
        ? json.data
        : Array.isArray(json?.nodes)
          ? json.nodes
          : Array.isArray(json)
            ? json
            : [];

      const isWindowsNode = (n: Record<string, unknown>) => {
        const osName = String(n?.os_name ?? '').toLowerCase();
        const osPlatform = String(n?.os_platform ?? '').toLowerCase();
        return osName.includes('windows') || osPlatform.includes('windows');
      };

      const isOnlineNode = (n: Record<string, unknown>) => {
        const status = String(n?.status ?? n?.displayStatus ?? '').toLowerCase();
        return n?.agent_online === true || status === 'online';
      };

      const windowsCandidates = nodesArray.filter(isWindowsNode);
      const windowsOnline = windowsCandidates.filter(isOnlineNode);

      debugLog('[IRDAI Hot] Windows candidates:', windowsCandidates.map((n) => ({
        id: n?.id,
        host_identifier: n?.host_identifier,
        hostname: n?.hostname,
        os_name: n?.os_name,
        os_platform: n?.os_platform,
        agent_online: n?.agent_online,
        status: n?.status,
        displayStatus: n?.displayStatus,
      })));

      debugLog('[IRDAI Hot] Online Windows nodes:', windowsOnline.map((n) => ({
        id: n?.id,
        host_identifier: n?.host_identifier,
        hostname: n?.hostname,
        os_name: n?.os_name,
        os_platform: n?.os_platform,
        agent_online: n?.agent_online,
        status: n?.status,
        displayStatus: n?.displayStatus,
      })));

      if (wsConnected) {
        debugLog('[IRDAI Hot] Websocket is connected. Will attempt live USB status queries for each node during compliance checks.');
      }
      if (wsSendMessage) {
        debugLog('[IRDAI Hot] Websocket send function is available. Will use it to query live USB status for each node during compliance checks.');
      }

      const hostIds = windowsOnline
        .map((n) => String(n?.host_identifier ?? n?.id ?? '').trim())
        .filter((id) => id.length > 0);

      if (hostIds.length === 0) {
        setPointsLoading(false);
        setNoWindowsOnline(true);
        throw new Error('No Windows nodes found to run IRDAI compliance.');
      }

      let successCount = 0;
      let failureCount = 0;
      let cumulativeNodePercent = 0;
      let processedNodes = 0;
      let fullyCompliantCount = 0;

      const resultLines: string[] = [];
      const fullyCompliantNodesList: string[] = [];
      const nonCompliantNodesWithChecks: Array<{ host_identifier: string; failed_checks: string[] }> = [];
      const nextFleetPointStats: Record<string, FleetPointStat> = 
        IRDAI_HOT_COMMAND_KEYS.reduce<Record<string, FleetPointStat>>(
          (acc, key) => {
            acc[key] = { passed: 0, total: 0, notAssessed: 0 };
            return acc;
          },
          {}
        );

      // 2026-09-07: a host that never produced checks — thrown sweep, or a candidate that
      // vanished from the Windows online list between the identifier fetch and the loop —
      // used to touch nextFleetPointStats not at all. It therefore contributed to neither
      // eligibleHosts nor notAssessed for any control, and the operator saw a per-control
      // denominator that had silently shrunk with nothing on screen to say so. A host the
      // sweep set out to cover and could not measure belongs in the coverage accounting as
      // not-assessed on every control, which is what the SEBI driver does
      // (NodesViewSebiHotCompliance.tsx, the failureReason branch of the outcome loop).
      const markHostNotAssessed = () => {
        IRDAI_HOT_COMMAND_KEYS.forEach((key) => {
          nextFleetPointStats[key].notAssessed = (nextFleetPointStats[key].notAssessed ?? 0) + 1;
        });
      };

      for (const id of hostIds) {
        try {
          const targetNode = windowsOnline.find((n) => String(n?.host_identifier ?? n?.id ?? '').trim() === id) as NodeData | undefined;
          if (!targetNode) {
            failureCount += 1;
            markHostNotAssessed();
            resultLines.push(`${id}: skipped (missing candidate)`);
            debugLog(`[IRDAI Hot] ${id} skipped because it was not found in the Windows online list`);
            continue;
          }

          const checks = await staticComplianceChecks(id, targetNode, wsConnected, wsSendMessage);
          // Not-assessed points are outside both the numerator and the denominator.
          const pass = Object.values(checks)
            .filter((c) => isPass(c))
            .length;

          const total = Object.values(checks)
            .filter((c) => isPass(c) || isFail(c))
            .length;

            if (total === 0) {
              // No control produced a measured result on this host, so it is neither fully
              // compliant nor non-compliant: it stays out of both lists and out of the average.
              debugLog(`[IRDAI Hot] ${id} produced no measured control — not assessed`);
            } else if (pass === total) {
              fullyCompliantCount += 1;
              fullyCompliantNodesList.push(id);
            } else {
              const failedChecks = Object.entries(checks)
                .filter(([, v]) => isFail(v))
                .map(([k]) => k);
              nonCompliantNodesWithChecks.push({ host_identifier: id, failed_checks: failedChecks });
            }

          // Only hosts with at least one measured control contribute to the average.
          if (total > 0) {
            cumulativeNodePercent += (pass / total) * 100;
            processedNodes++;
          }

          IRDAI_HOT_COMMAND_KEYS.forEach((key) => {
            const result = checks[key];
            // A host the control could not be measured on is counted on its own rather
            // than dropped: it belongs to neither the numerator nor the denominator, but
            // the operator still needs to see that it exists.
            if (!isPass(result) && !isFail(result)) {
              nextFleetPointStats[key].notAssessed = (nextFleetPointStats[key].notAssessed ?? 0) + 1;
              return;
            }
            nextFleetPointStats[key].total += 1;
            if (isPass(result)) {
              nextFleetPointStats[key].passed += 1;
            }
          });

          const trueChecks = Object.entries(IRDAI_HOT_GUIDELINES).reduce<Record<string, { label: string; compliant: boolean }>>((acc, [marker, meta]) => {
            const result = checks[marker];
            if (result?.compliant === true) {
              acc[marker] = { label: meta.label, compliant: true };
            }
            return acc;
          }, {});

          debugLog('[IRDAI Hot] true checks for node', {
            hostId: id,
            hostname: String(targetNode.hostname ?? targetNode.name ?? ''),
            trueChecks,
          });

          successCount += 1;
          resultLines.push(`${id}: success`);
          debugLog(`[IRDAI Hot] ${id} success`);
        } catch (err) {
          failureCount += 1;
          // See markHostNotAssessed above: a thrown host was measured for nothing, so it is
          // counted as not-assessed on every control rather than dropped from the accounting.
          markHostNotAssessed();
          resultLines.push(`${id}: failed`);
          console.error(`[IRDAI Hot] Failed to run compliance checks on node ${id}:`, err);
        }
      }

      debugLog('[IRDAI Hot] fleet refresh summary', {
        successCount,
        failureCount,
        total: hostIds.length,
        resultLines,
        currentHostId: hostId,
      });

      const averageNodeCompliance =
        processedNodes > 0
          ? cumulativeNodePercent / processedNodes
          : 0;

      let totalPassed = 0;
      let totalChecks = 0;
      Object.entries(nextFleetPointStats).forEach(([key, stat]) => {
        if (HIDDEN_GUIDELINES.has(key)) return;
        totalPassed += stat.passed;
        totalChecks += stat.total;
      });

      const aggregateFleetCompliance =
        totalChecks > 0
          ? (totalPassed / totalChecks) * 100
          : 0;

      setAggregateCompliance(aggregateFleetCompliance);
      setAverageCompliance(averageNodeCompliance);

      setTotalNodes(processedNodes);
      setFullyCompliantNodes(fullyCompliantCount);

      const fleetAwareChecks = { ...currentChecks };
      Object.entries(nextFleetPointStats).forEach(([key, stat]) => {
        if (HIDDEN_GUIDELINES.has(key)) return;
        // Satisfied only when every assessed host passed. Some hosts passing is a partial
        // result, and no assessed host at all is not-assessed rather than a fleet failure.
        if (stat.total > 0) {
          fleetAwareChecks[key] = {
            compliant: stat.passed === stat.total,
            reason: stat.passed === stat.total
              ? `All ${stat.total} assessed Windows node${stat.total !== 1 ? 's' : ''} passed this check during this compliance run.`
              : stat.passed > 0
                ? `Partial: ${stat.passed} of ${stat.total} assessed Windows nodes passed this check during this compliance run, so the control is not satisfied fleet-wide.`
                : `None of the ${stat.total} assessed Windows node${stat.total !== 1 ? 's' : ''} passed this check during this compliance run.`,
            detail: `${stat.passed}/${stat.total} nodes passed`,
          };
        } else {
          fleetAwareChecks[key] = {
            compliant: false,
            assessed: false,
            reason: `No Windows node produced a measured result for this control during this compliance run, so it could not be assessed fleet-wide${(stat.notAssessed ?? 0) > 0 ? ` (${stat.notAssessed} node${stat.notAssessed !== 1 ? 's' : ''} not assessed)` : ''}.`,
            detail: (stat.notAssessed ?? 0) > 0
              ? `${stat.notAssessed} node${stat.notAssessed !== 1 ? 's' : ''} not assessed`
              : 'No host assessed — not assessed',
          };
        }
      });

      const controlPassRates =
        Object.entries(nextFleetPointStats)
          .filter(([key]) => !HIDDEN_GUIDELINES.has(key))
          .map(([key, stat]) => ({
            key,
            label: IRDAI_HOT_GUIDELINES[key].label,
            passRatePct:
              stat.total > 0
                ? Number(((stat.passed / stat.total) * 100).toFixed(2))
                : null,
            passHosts: stat.passed,
            failHosts: stat.total - stat.passed,
            eligibleHosts: stat.total,
          }));

      setPointsLoading(false);
      setStaticChecks(fleetAwareChecks);
      setFleetPointStats(nextFleetPointStats);

      try {
      const snapshotRes = await fetchWithCsrf(NODES_URLS.IRDAI_COMPLIANCE_SNAPSHOT, {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeadersJson(),
        body: JSON.stringify({
          snapshotAt: Math.floor(Date.now() / 1000),

          totalNodes: windowsCandidates.length,

          windowsHosts: hostIds.length,

          windowsWithResults: successCount,

          fullyCompliantNodes: fullyCompliantCount,

          avgCompliancePercent: averageNodeCompliance.toFixed(2),

          strongCount: 0,
          moderateCount: 0,
          needsAttentionCount: 0,

          controlPassRates,

          source: 'live',

            fullyCompliantNodesList,
            // Sent as { host_identifier, failed_checks } objects, matching SEBI and
            // CERT-In: the framework report's stored-snapshot branch can only score a
            // non-compliant host when failed_checks is present, and renders
            // "Score not recorded" otherwise. reports.ts reads both shapes.
            nonCompliantNodesList: nonCompliantNodesWithChecks,
        }),
      });
      if (!snapshotRes.ok) {
        console.warn(`[IRDAI Hot] Compliance snapshot save failed: HTTP ${snapshotRes.status}`);
      } else {
        debugLog('[IRDAI Hot] Compliance snapshot saved successfully');
        void fetchOrgHistory();
      }
    } catch (err) {
      console.warn('[IRDAI Hot] Compliance snapshot save failed:', err);
    }
    } catch (err) {
      console.error('[IRDAI Hot] Failed to refresh compliance:', err);
    }
  };

  const totalChecks = passCount + failCount;

  // The donut's percentage is passed / (passed + failed): controls that were not
  // measured are excluded from the score. They are still drawn as their own slice so
  // the chart shows everything the KPI tiles below it report, and the centre label and
  // the caption both name the denominator instead of leaving it implied.
  const pieData =
    totalChecks > 0
      ? [
          { name: 'Pass', value: passCount },
          { name: 'Fail', value: failCount },
          ...(notAssessedCount > 0
            ? [{ name: 'Not Assessed', value: notAssessedCount }]
            : []),
        ]
      : [];

  const fullyCompliantChartData =
    totalNodes > 0 ? [
      { name: 'Fully Compliant',
        value: Number(((fullyCompliantNodes / totalNodes) * 100.0).toFixed(2)),
      },
      {
        name: 'Not Fully Compliant',
        value: Number((100.0 - (fullyCompliantNodes / totalNodes) * 100.0).toFixed(2)),
      },
    ] : [];

  const orgLatestSnapshot = orgHistory?.[0];

  // Whether the latest STORED org snapshot's fully_compliant_nodes scalar agrees with the
  // length of its own fully_compliant_nodes_list. Ported from NodesViewCertInCompliance.tsx's
  // orgSnapshotListReconciles (which caught a real live self-contradiction there) — IRDAI has
  // the identical unguarded shape (confirmed live: 3 of the oldest stored rows carry this same
  // mismatch, though the current/latest row does not). IRDAI has no manual "Save Compliance"
  // button and no scoreIsLive concept, so — like SEBI — this is a display-only gate, not a
  // save-guard: it stops the donut from ever rendering an unsubstantiated percentage.
  const orgSnapshotListReconciles = orgLatestSnapshot == null
    || Number(orgLatestSnapshot.fully_compliant_nodes ?? 0) === (orgLatestSnapshot.fully_compliant_nodes_list ?? []).length;

  const chartOrgData = [...orgHistory]
    .reverse()
    .map((snapshot) => ({
      label: `${fmtDate(snapshot.snapshot_at)}|${fmtTime(snapshot.snapshot_at)}`,
      tooltip: fmtDateTime(snapshot.snapshot_at),
      // null, never 0: a snapshot in which no host produced a measurement has no pass
      // rate at all, and plotting it as 0% reads as "the entire fleet failed". recharts
      // renders a null as a gap in the line, which is what "not assessed" looks like.
      percent: snapshot.windows_with_results
        ? ((snapshot.fully_compliant_nodes ?? 0) / snapshot.windows_with_results) * 100
        : null,
      nodeCount: snapshot.windows_with_results ?? 0,
    }));

  const chartData = [...history].reverse().map((rec) => {
    const irdaiData =
      (IRDAI_HOT_COMMAND_KEYS.length > 0
        ? rec.compliance_data.filter((r) =>
            IRDAI_HOT_COMMAND_KEYS.includes(r.command_key)
          )
        : rec.compliance_data).filter((r) => r.output !== 'not_assessed');

  const passCount = irdaiData.filter((r) => {
    try {
      return JSON.parse(r.output) === true;
    } catch {
      return false;
    }
  }).length;

    const totalCount = irdaiData.length;

    return {
      label: `${fmtDate(rec.unixtime)}|${fmtTime(rec.unixtime)}`,
      tooltip: fmtDateTime(rec.unixtime),
      percent:
        totalCount > 0
          ? Math.round((passCount / totalCount) * 100)
          : 0,
    };
  });

  const latestSnapshot = orgHistory?.[0];

  const lastRunText = latestSnapshot
    ? fmtDateTime(latestSnapshot.snapshot_at)
    : 'Never';

  const latestNodeSnapshot = history?.[0];

  const lastNodeRunText = latestNodeSnapshot
    ? fmtDateTime(latestNodeSnapshot.unixtime)
    : 'Never';

  return (
    <div className="px-4 pb-4 space-y-4">
      {/* IRDAI Toolbar */}
        <div className="mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
          <div className="flex flex-wrap items-center gap-5 w-full">
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                <span className="text-xs font-semibold text-slate-500">Compliance Checks:</span>
                <span className="text-sm font-semibold text-slate-800 tabular-nums">{IRDAI_HOT_COMMAND_KEYS.length} points</span>
              </div>
              {!oneDeviceCompliance && (
                <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500" aria-hidden="true" />
                  <span className="text-xs font-semibold text-slate-500">Nodes Online:</span>
                  <span className="text-sm font-semibold text-slate-800 tabular-nums">{onlineNodes} / {totalWindowsNodes}</span>
                </div>
              )}
              {oneDeviceCompliance && (
                <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                  <span className="text-xs font-semibold text-slate-500">Last Compliance Run:</span>
                  <span className="text-sm font-semibold text-slate-800">{lastNodeRunText}</span>
                </div>
              )}
              {oneDeviceCompliance && (
                <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                  <span className="text-xs font-semibold text-slate-500">Device Name:</span>
                  <span className="text-sm font-semibold text-slate-800">{hostLabel}</span>
                </div>
              )}
              {!oneDeviceCompliance && (
                <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                  <span className="text-xs font-semibold text-slate-500">Last Compliance Run:</span>
                  <span className="text-sm font-semibold text-slate-800">{lastRunText}</span>
                </div>
              )}
            </div>
            
            <div className="ml-auto flex flex-wrap items-center gap-2">
              {!oneDeviceCompliance && (
                <>
                  <button
                    type="button"
                    onClick={handleRefresh}
                    disabled={pointsLoading}
                    className="inline-flex items-center gap-2 rounded-lg bg-[rgb(4,34,119)] px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-[rgb(10,50,150)] disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    {pointsLoading
                      ? <DuoSpinner size="xs" className="text-white" />
                      : <i className="fa fa-people-arrows text-xs text-blue-200" />}
                    {pointsLoading ? 'Fetching…' : 'Fetch Endpoint Data'}
                  </button>
                  <button
                    type="button"
                    onClick={handleDownloadVajraCompliance}
                    disabled={downloadLoading}
                    className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm transition-colors hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    {downloadLoading
                      ? <DuoSpinner size="xs" className="text-slate-500" />
                      : <i className="fa fa-download text-xs" />}
                    {downloadLoading ? 'Downloading…' : 'Download Report'}
                  </button>
                </>
            )}
            {oneDeviceCompliance && agentOnline && (
              <button
                type="button"
                onClick={handleOneDeviceCompliance}
                className="inline-flex items-center gap-2 rounded-lg bg-[rgb(4,34,119)] px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-[rgb(10,50,150)] disabled:opacity-60 disabled:cursor-not-allowed"
              >
                <i className="fa fa-rotate-right text-xs text-blue-200" />
                Refresh IRDAI Compliance
              </button>
            )}
            </div>
          </div>
        </div>

      {!agentOnline && oneDeviceCompliance && (
        <div className="flex gap-3 rounded-xl border border-blue-200 bg-blue-100 px-4 py-3 text-sm text-slate-700 mb-4" role="status">
          <i className="fa fa-clock-rotate-left mt-0.5 shrink-0 text-slate-600" aria-hidden />
          <div>
            <p className="font-semibold text-slate-900">Agent is offline.</p>
            <p className="mt-1 text-slate-700/90">Latest compliance can only be checked when the agent is online.</p>
          </div>
        </div>
      )}

      {noWindowsOnline && (
        <div className="flex gap-3 rounded-xl border border-blue-200 bg-blue-100 px-4 py-3 text-sm text-slate-700 mb-4" role="status">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-slate-600" aria-hidden />
          <div>
            <p className="font-semibold text-slate-900">No Windows nodes found</p>
            <p className="mt-1 text-slate-700/90">
              IRDAI compliance checks are only applicable online to Windows devices. No Windows nodes were found to run compliance checks on.
            </p>
          </div>
        </div>
      )}

      {
        !pointsLoading && orgHistoryError && !oneDeviceCompliance && (
          <div className="flex gap-3 rounded-xl border border-blue-200 bg-blue-100 px-4 py-3 text-sm text-slate-700 mb-4" role="status">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-slate-600" aria-hidden />
          <div>
            <p className="font-semibold text-slate-900">Failed to fetch IRDAI compliance history for organization</p>
            <p className="mt-1 text-slate-700/90">
              Historical compliance data could not be retrieved. Please try refreshing the page or running a new compliance check.
            </p>
          </div>
        </div>
        )
      }

      {
        !pointsLoading && historyError && oneDeviceCompliance && (
          <div className="flex gap-3 rounded-xl border border-blue-200 bg-blue-100 px-4 py-3 text-sm text-slate-700 mb-4" role="status">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-slate-600" aria-hidden />
          <div>
            <p className="font-semibold text-slate-900">Failed to fetch IRDAI compliance history for node</p>
            <p className="mt-1 text-slate-700/90">
              Historical compliance data could not be retrieved. Please try refreshing the page or running a new compliance check.
            </p>
          </div>
        </div>
        )
      }

      {pointsLoading ? (
        <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-600">
          <LoadingScreen
            title="Calculating IRDAI compliance..."
            subtitle="This may take a few moments depending on number of endpoints and network conditions."
            size="md"
            fullScreen={false}
          />
        </div>) :
      (
    <>
      <div className="flex flex-col lg:flex-row gap-4 mt-4 lg:items-stretch">
        <div className="flex-1 min-w-0">
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-slate-200">
            <div className="flex justify-between gap-2 items-center">
              <div className="text-base font-semibold text-white">IRDAI Guidelines</div>
              
              <div className="flex items-center gap-3">
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as 'default' | '100_compliant' | 'not_100_compliant')}
                  className="bg-white border border-blue-200 text-blue-900 text-xs font-medium rounded-lg px-2 py-1 outline-none focus:ring-2 focus:ring-blue-500/50 transition-shadow"
                >
                  <option value="default">Default Order</option>
                  <option value="100_compliant">Highest Compliance First</option>
                  <option value="not_100_compliant">Lowest Compliance First</option>
                </select>

                {!oneDeviceCompliance && !noWindowsOnline && (
                  <span className="inline-flex items-center rounded-full bg-blue-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                    <i className="fa fa-arrow-down-wide-short text-slate-400 mr-2" />
                    Fetched from last successful compliance run on {lastRunText}
                  </span>
                )}
                {oneDeviceCompliance && (
                  <span className="inline-flex items-center rounded-full bg-blue-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                    <i className="fa fa-arrow-down-wide-short text-slate-400 mr-2" />
                    Fetched from last successful compliance run on {lastNodeRunText}
                  </span>
                )}
              </div>
            </div>
          </div>
          <div className="table-scrollbar overflow-auto max-h-[432px]">
            <div className="flex-1">
              <table className="w-full text-sm border-separate border-spacing-0">
                <thead>
                  <tr>
                    <th className="py-2 px-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide w-20 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                      Point
                    </th>
                    <th className="py-2 px-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                      Requirement
                    </th>
                    <th className="py-2 px-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                      IRDAI Ref
                    </th>
                    <th className="py-2 px-3 text-center text-xs font-medium text-slate-500 uppercase tracking-wide w-36 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const allKeys = [...IRDAI_HOT_COMMAND_KEYS];
                    const getComplianceFraction = (key: string) => {
                      if (staticChecks[key] !== undefined) {
                        if (fleetPointStats[key] && fleetPointStats[key].total > 0 && !noWindowsOnline && !oneDeviceCompliance) {
                          return fleetPointStats[key].passed / fleetPointStats[key].total;
                        }
                        return staticChecks[key]!.compliant ? 1 : 0;
                      }
                      return 0;
                    };

                    if (sortBy === '100_compliant') {
                      allKeys.sort((a, b) => {
                        return getComplianceFraction(b) - getComplianceFraction(a);
                      });
                    } else if (sortBy === 'not_100_compliant') {
                      allKeys.sort((a, b) => {
                        return getComplianceFraction(a) - getComplianceFraction(b);
                      });
                    }

                    return allKeys.map((key) => {
                      const idx = IRDAI_HOT_COMMAND_KEYS.indexOf(key);
                      const check = staticChecks[key];
                      const fleetStat = fleetPointStats[key];
                      const isFleetRollup = !!fleetStat && fleetStat.total > 0 && !noWindowsOnline && !oneDeviceCompliance;
                      // Some assessed hosts passing is a partial result, shown apart from a clean fail.
                      const isPartial = isFleetRollup && fleetStat.passed > 0 && fleetStat.passed < fleetStat.total;
                      // Three states are kept distinct and are never collapsed into one another:
                      // no compliance run has happened yet ('not_run'), a run happened but this
                      // control could not be measured ('not_assessed'), and a measured verdict.
                      const verdict: RowVerdict = !hasRefreshed
                        ? 'not_run'
                        : check === undefined || isNotAssessed(check)
                          ? 'not_assessed'
                          : check.compliant
                            ? 'satisfied'
                            : isPartial
                              ? 'partial'
                              : 'non_compliant';
                      // The measured reason produced for this control on this host. It is the
                      // evidence behind the badge, so it is surfaced rather than discarded.
                      const reason = !hasRefreshed
                        ? undefined
                        : check?.reason
                          ?? 'The last compliance run produced no result for this control on this host, so it is recorded as not assessed rather than as a pass or a fail.';
                      // Tooltip description: prefer this run's own live reason (more
                      // specific — this host's actual finding) and fall back to the static,
                      // evaluator-accurate description below when no fresh run has produced
                      // one yet (e.g. before the first sweep of a session). Either source is
                      // enough content to show the info icon; only when NEITHER exists (a key
                      // missing from both, which should not happen for a rendered control) is
                      // it hidden.
                      const tooltipDescription = reason ?? IRDAI_HOT_REASON_DETAIL[key]?.reason;
                      const detailLine =
                        check?.detail ?? VERDICT_HINT[verdict];
                      const badgeText =
                        isFleetRollup && (verdict === 'satisfied' || verdict === 'partial' || verdict === 'non_compliant')
                          ? `${fleetStat.passed}/${fleetStat.total} nodes passed`
                          : VERDICT_LABEL[verdict];
                      return (
                        <tr
                          key={key}
                      className="border-b border-slate-100 hover:bg-slate-50/60 transition-colors"
                    >
                      <td className="py-2.5 px-3 text-slate-500 text-xs font-semibold">{idx + 1}</td>
                      <td className="py-2.5 px-3 text-slate-800">
                        <span className="inline-flex items-start">
                          <span>{IRDAI_HOT_GUIDELINES[key].label}</span>
                          {tooltipDescription && (
                            <InfoTooltip
                              text={IRDAI_HOT_GUIDELINES[key].tooltip}
                              description={tooltipDescription}
                              withDescription
                              align="right"
                            />
                          )}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-700 text-xs whitespace-pre-line">
                        {IRDAI_HOT_GUIDELINES[key].tooltip}
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <div className="inline-flex flex-col items-center gap-0.5 w-full">
                          <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${VERDICT_BADGE_CLASS[verdict]}`}>
                            <i className={`fa ${VERDICT_ICON_CLASS[verdict]} text-[9px]`} />
                            {badgeText}
                          </span>

                          {detailLine && (
                            <span className="text-[10px] leading-snug text-slate-500 font-medium whitespace-normal">
                              {detailLine}
                            </span>
                          )}

                          {fleetPointStats[key] && fleetPointStats[key].total > 0 && !noWindowsOnline && !oneDeviceCompliance && (
                            <div className="w-full mt-0.5 px-1">
                              <div className="h-1 w-full max-w-[96px] mx-auto bg-gray-100 rounded-full overflow-hidden">
                                <div
                                  className="h-full rounded-full bg-sky-400 transition-all duration-500"
                                  style={{ width: `${Math.max((fleetPointStats[key].passed / fleetPointStats[key].total) * 100, fleetPointStats[key].passed > 0 ? 4 : 0)}%` }}
                                />
                              </div>
                              {(fleetPointStats[key].notAssessed ?? 0) > 0 && (
                                <div className="mt-0.5 text-[10px] text-slate-400 font-medium">
                                  {fleetPointStats[key].notAssessed} not assessed
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </td>
                        </tr>
                      );
                    });
                  })()}
                </tbody>
              </table>
            </div>
          </div>
          </div>
        </div>
        {oneDeviceCompliance && (
          <div className="w-full lg:w-96 shrink-0 flex flex-col">

            <div className="bg-blue-50 rounded-xl border border-blue-200 overflow-hidden">
              <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-slate-700 flex items-center justify-between">
                <span className="font-semibold text-white text-base">Compliance Score</span>
              </div>

              {pieData.length > 0 ? (
                <div className="p-4">

                  <div className="flex justify-center gap-5 mt-4">

                    <div className="flex items-center gap-2">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: SCORE_PIE_COLORS[0] }}
                      />
                      <span className="text-sm text-slate-600">
                        Passed
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: SCORE_PIE_COLORS[1] }}
                      />
                      <span className="text-sm text-slate-600">
                        Failed
                      </span>
                    </div>

                    {notAssessedCount > 0 && (
                      <div className="flex items-center gap-2">
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{ backgroundColor: SCORE_PIE_COLORS[2] }}
                        />
                        <span className="text-sm text-slate-600">
                          Not Assessed
                        </span>
                      </div>
                    )}

                  </div>

                  {/* Donut */}
                  <div className="flex justify-center">
                    <ResponsiveContainer width="100%" height={280}>
                      
                      <PieChart>
                        <Pie
                          data={pieData}
                          activeShape={renderActiveShape}
                          onMouseEnter={(_, index) => setActiveIndex(index)}
                          dataKey="value"
                          cx="50%"
                          cy="50%"
                          innerRadius={65}
                          outerRadius={115}
                          stroke="#fff"
                          strokeWidth={4}
                          cornerRadius={6}
                        >
                          {pieData.map((_, idx) => (
                            <Cell
                              key={idx}
                              fill={SCORE_PIE_COLORS[idx % SCORE_PIE_COLORS.length]}
                            />
                          ))}
                        </Pie>

                        {/* Center Label */}
                        <text
                          x="50%"
                          y="46%"
                          textAnchor="middle"
                          dominantBaseline="middle"
                        >
                          <tspan
                            fontSize="34"
                            fontWeight="700"
                            fill="#0F172A"
                          >
                            {(
                              (pieData[0]?.value /
                                ((pieData[0]?.value ?? 0) +
                                  (pieData[1]?.value ?? 0) || 1)) *
                              100
                            ).toFixed(1)}
                            %
                          </tspan>

                          <tspan
                            x="50%"
                            dy="22"
                            fontSize="13"
                            fill="#64748B"
                          >
                            {`passed of ${totalChecks} assessed`}
                          </tspan>
                        </text>

                        <RTooltip content={<CustomTooltip />} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  {notAssessedCount > 0 && (
                    <p className="mt-1 text-center text-[11px] leading-snug text-slate-500">
                      {notAssessedCount} control{notAssessedCount !== 1 ? 's' : ''} could not be assessed on this node — excluded from this score, counted as neither a pass nor a fail.
                    </p>
                  )}

                  {/* KPI Cards */}
                  <div className="grid grid-cols-4 gap-3 mt-2">

                    <div className="rounded-xl bg-[#136f63]/10 py-3 text-center">
                      <div className="text-2xl font-bold text-[#136f63]">
                        {passCount}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        Passed
                      </div>
                    </div>

                    <div className="rounded-xl bg-[#ab3428]/15 py-3 text-center">
                      <div className="text-2xl font-bold text-[#ab3428]">
                        {failCount}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        Failed
                      </div>
                    </div>

                    <div className="rounded-xl bg-slate-200/60 py-3 text-center">
                      <div className="text-2xl font-bold text-slate-600">
                        {notAssessedCount}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        Not Assessed
                      </div>
                    </div>

                    <div className="rounded-xl bg-[#023047]/10 py-3 text-center">
                      <div className="text-2xl font-bold text-[#023047]">
                        {totalChecks}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        Assessed
                      </div>
                    </div>

                  </div>

                  {/* Legend */}

                </div>
              ) : (
                <div className="flex items-center justify-center h-[300px] text-gray-300">
                  <i className="fa fa-chart-pie text-6xl" />
                </div>
              )}
            </div>
          </div>)
        }

        {!oneDeviceCompliance && (
          <div className="w-full lg:w-96 shrink-0 flex flex-col">

            <div className="bg-blue-50 rounded-xl border border-blue-200 overflow-hidden">
              <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-slate-700 flex items-center justify-between">
                <span className="font-semibold text-white text-base">Compliance Score</span>
              </div>

              {fullyCompliantChartData.length > 0 && !noWindowsOnline && orgSnapshotListReconciles ? (
                <div className="p-4">

                  <div className="flex justify-center gap-5 mt-4">

                    <div className="flex items-center gap-2">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: PIE_COLORS[0] }}
                      />
                      <span className="text-sm text-slate-600">
                        Fully Compliant
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: PIE_COLORS[1] }}
                      />
                      <span className="text-sm text-slate-600">
                        Not Fully Compliant
                      </span>
                    </div>

                  </div>

                  {/* Donut */}
                  <div className="flex justify-center">
                    <ResponsiveContainer width="100%" height={280}>
                      
                      <PieChart>
                        <Pie
                          data={fullyCompliantChartData}
                          activeShape={renderActiveShape}
                          onMouseEnter={(_, index) => setActiveIndex(index)}
                          dataKey="value"
                          cx="50%"
                          cy="50%"
                          innerRadius={65}
                          outerRadius={115}
                          stroke="#fff"
                          strokeWidth={4}
                          cornerRadius={6}
                        >
                          {fullyCompliantChartData.map((_, idx) => (
                            <Cell
                              key={idx}
                              fill={PIE_COLORS[idx % PIE_COLORS.length]}
                            />
                          ))}
                        </Pie>

                        {/* Center Label */}
                        <text
                          x="50%"
                          y="46%"
                          textAnchor="middle"
                          dominantBaseline="middle"
                        >
                          <tspan
                            fontSize="34"
                            fontWeight="700"
                            fill="#0F172A"
                          >
                            {(
                              totalNodes ?
                              ((fullyCompliantNodes ?? 0) / totalNodes) * 100 : 0
                            ).toFixed(1)}
                            %
                          </tspan>

                          <tspan
                            x="50%"
                            dy="22"
                            fontSize="13"
                            fill="#64748B"
                          >
                            {`fully compliant of ${totalNodes ?? 0} nodes with results`}
                          </tspan>
                        </text>

                        <RTooltip content={<CustomTooltip />} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  {((orgHistory?.[0]?.windows_hosts ?? 0) - (orgHistory?.[0]?.windows_with_results ?? 0)) > 0 && (
                    <p className="mt-1 text-center text-[11px] leading-snug text-slate-500">
                      {(orgHistory[0].windows_hosts ?? 0) - (orgHistory[0].windows_with_results ?? 0)} Windows host{((orgHistory[0].windows_hosts ?? 0) - (orgHistory[0].windows_with_results ?? 0)) !== 1 ? 's' : ''} produced no result in this run — excluded from this score.
                    </p>
                  )}

                  {/* KPI Cards */}
                  <div className="grid grid-cols-3 gap-3 mt-2">

                    <div className="rounded-xl bg-[#136f63]/10 py-3 text-center">
                      <div className="text-2xl font-bold text-[#136f63]">
                        {fullyCompliantNodes ?? 0}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        Compliant
                      </div>
                    </div>

                    <div className="rounded-xl bg-[#ab3428]/15 py-3 text-center">
                      <div className="text-2xl font-bold text-[#ab3428]">
                        {(totalNodes || 0) - (fullyCompliantNodes || 0)}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        Non-Compliant
                      </div>
                    </div>

                    <div className="rounded-xl bg-[#023047]/10 py-3 text-center">
                      <div className="text-2xl font-bold text-[#023047]">
                        {totalNodes ?? 0}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        Total
                      </div>
                    </div>

                  </div>

                  {/* Legend */}

                </div>
              ) : !noWindowsOnline && !orgSnapshotListReconciles ? (
                // Evidence gap, not a score: the stored snapshot's compliant-node count
                // does not match the length of its own evidence list (see
                // orgSnapshotListReconciles above), so there is no trustworthy number to
                // draw a donut from. Showing the raw scalar here would be the exact
                // "N/M = X% Fully Compliant, evidence list empty" leak this guards
                // against — reports.ts's PDF already refuses to render this section on the
                // identical mismatch rather than print an unsubstantiated figure.
                <div className="flex flex-col items-center justify-center h-[27rem] gap-2 px-6 text-center">
                  <i className="fa fa-triangle-exclamation text-3xl text-amber-500" aria-hidden />
                  <p className="text-sm font-semibold text-slate-700">Compliant-node count unavailable</p>
                  <p className="text-xs text-slate-500">
                    The saved snapshot&apos;s compliant-node count doesn&apos;t match its own evidence list, so it
                    can&apos;t be shown here. Run a fresh compliance sweep to refresh it.
                  </p>
                </div>
              ) : (
                <div className="flex items-center justify-center h-[27rem] text-gray-300">
                  <i className="fa fa-chart-pie text-6xl" />
                </div>
              )}
            </div>
          </div>)
        }
          </div>
        </>)}
  
        {/* History trend chart */}
        {!oneDeviceCompliance && !pointsLoading && (<div className="bg-white rounded-xl border border-gray-200 overflow-hidden mt-4">
          <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
            <span className="font-semibold text-white text-base">Organization IRDAI Compliance History</span>
            {!orgHistoryLoading && orgHistory.length > 0 && (
              <span className="inline-flex items-center rounded-full bg-blue-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                <i className="fa fa-arrow-down-wide-short text-slate-400 mr-2" />
                  {orgHistory.length} record{orgHistory.length > 1 ? 's' : ''}
                </span>
            )}
          </div>
          <div className="p-4 bg-blue-50">
            {orgHistoryLoading ? (
              <div className="flex items-center justify-center h-[180px]">
                <DuoSpinner size="md" className="text-rose-400" />
              </div>
            ) : chartOrgData.length >= 2 ? (
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartOrgData} margin={{ top: 8, right: 20, bottom: 4, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#d8d8d8" />
                  <XAxis
                    dataKey="label"
                    tick={({ x, y, payload }) => {
                      const [date, time] = String(payload.value).split('|');
  
                      return (
                        <g transform={`translate(${x},${y})`}>
                          <text
                            textAnchor="middle"
                            fill="#666"
                            fontSize={11}
                          >
                            <tspan x="0" dy="0">
                              {date}
                            </tspan>
                            <tspan x="0" dy="12">
                              {time}
                            </tspan>
                          </text>
                        </g>
                      );
                    }}
                  />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} tickLine={false} unit="%" width={38} />
                  <RTooltip
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;

                    const point = payload[0].payload;

                    return (
                      <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-lg">
                        <div className="font-medium text-slate-800">
                          {point.tooltip}
                        </div>

                        <div className="mt-2 text-rose-600">
                          Pass Rate: {point.percent.toFixed(2)}%
                        </div>

                        <div className="mt-1 text-slate-600">
                          Windows Nodes Processed: {point.nodeCount}
                        </div>
                      </div>
                    );
                  }}
                />
                  <Legend iconType="circle" iconSize={10} wrapperStyle={{ fontSize: 12 }} />
                  <Line
                    type="monotone"
                    dataKey="percent"
                    name="Pass rate %"
                    stroke="#e11d48"
                    strokeWidth={2}
                    dot={{ r: 3, fill: '#e11d48' }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : chartOrgData.length === 1 ? (
              <div className="flex items-center justify-center h-[180px] text-gray-400 text-sm text-center">
                Only 1 record — run another compliance check to see the trend.
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-[180px] text-gray-400">
                <i className="fa fa-chart-line text-4xl mb-3 opacity-20" />
                <p className="text-sm font-medium">No history yet</p>
                <p className="text-xs mt-1">History builds as you run compliance checks</p>
              </div>
            )}
          </div>
        </div>)}
  
        {/* History trend chart */}
        {oneDeviceCompliance && !pointsLoading && (<div className="bg-white rounded-xl border border-gray-200 overflow-hidden mt-4">
          <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
            <span className="font-semibold text-white text-base">Node IRDAI Compliance History</span>
            {!historyLoading && history.length > 0 && (
              <span className="inline-flex items-center rounded-full bg-blue-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                <i className="fa fa-arrow-down-wide-short text-slate-400 mr-2" />
                {history.length} record{history.length > 1 ? 's' : ''}
              </span>
            )}
          </div>
          <div className="p-4">
            {historyLoading ? (
              <div className="flex items-center justify-center h-[180px]">
                <DuoSpinner size="md" className="text-rose-400" />
              </div>
            ) : chartData.length >= 2 ? (
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartData} margin={{ top: 8, right: 20, bottom: 4, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#d8d8d8" />
                  <XAxis
                    dataKey="label"
                    tick={({ x, y, payload }) => {
                      const [date, time] = String(payload.value).split('|');
  
                      return (
                        <g transform={`translate(${x},${y})`}>
                          <text
                            textAnchor="middle"
                            fill="#666"
                            fontSize={11}
                          >
                            <tspan x="0" dy="0">
                              {date}
                            </tspan>
                            <tspan x="0" dy="12">
                              {time}
                            </tspan>
                          </text>
                        </g>
                      );
                    }}
                  />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} tickLine={false} unit="%" width={38} />
                  <RTooltip
                    formatter={(value) => [`${Number(Array.isArray(value) ? value[0] : value) || 0}%`, 'Pass rate']}
                    labelFormatter={(label: React.ReactNode, payload?: unknown) => {
                      const items = Array.isArray(payload) ? payload as Array<{ payload?: { tooltip?: string } }> : [];
                      return items[0]?.payload?.tooltip ?? label;
                    }}
                  />
                  <Legend iconType="circle" iconSize={10} wrapperStyle={{ fontSize: 12 }} />
                  <Line
                    type="monotone"
                    dataKey="percent"
                    name="Pass rate %"
                    stroke="#e11d48"
                    strokeWidth={2}
                    dot={{ r: 3, fill: '#e11d48' }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : chartData.length === 1 ? (
              <div className="flex items-center justify-center h-[180px] text-gray-400 text-sm text-center">
                Only 1 record — run another compliance check to see the trend.
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-[180px] text-gray-400">
                <i className="fa fa-chart-line text-4xl mb-3 opacity-20" />
                <p className="text-sm font-medium">No history yet</p>
                <p className="text-xs mt-1">History builds as you run compliance checks</p>
              </div>
            )}
          </div>
        </div>)}
    </div>
  );
}