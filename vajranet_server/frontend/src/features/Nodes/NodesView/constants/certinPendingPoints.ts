/**
 * CERT-In pending-points metadata for NodesViewCertInCompliance — the set of
 * guidelines Vajra answers automatically. Anything not listed here falls back
 * to the manual Yes/No checklist.
 */

export const CERTIN_PENDING_POINTS: Record<string, { label: string }> = {
  '1.4': {
    label: 'Whether inventory of authorized hardware and & software is maintained.',
  },
  '1.10': {
    label: 'Whether host firewall is configured in all systems to restrict lateral movement within the same network segment?',
  },
  '1.12': {
    label: 'Is Network firewall configured for the ministry/department and network access is configured as per the requirements of the official work?',
  },
  '2.6': { // Websocket wifi control data point
    label: 'Whether there are tools in the WLAN platform to identify rogue Access Point or those potentially spoofing corporate SSIDs?',
  },
  '3.3': { 
    label: 'Whether OS update is set to auto-update from a trusted source.', // Rename according to API
  },
  // 3.4 (Government offered enterprise Antivirus/EDR client) is not listed, and
  // that is not a statement that the node has no antivirus/EDR — Vajra IS the EDR
  // running on these endpoints. The control names a specific Government-offered
  // product, and whether Vajra (or anything else installed here) is on that
  // Government list is a tenant fact the platform does not hold: no approved
  // product list is stored and nothing is compared against one. So it can be
  // neither passed nor failed here, and falls back to the manual Yes/No checklist.
  '3.7': {
    label: 'Whether security of password enforced as per the guidelines?',
  },
  '3.8': { // Webscoket USB
    label: 'Whether it is ensured to allow only authorized USB storage devices, external storage devices?', // rENAME according to API
  },
  // 4.1 is answered from the endpoint's OWN advanced audit policy: baseline
  // command keys 5-16, the twelve `auditpol /get /subcategory:` probes stored in
  // compliance_results. All twelve auditing Success and Failure is a pass, any
  // measured as off is a fail, and an absent or stale baseline is "not assessed".
  // It is never inferred from agent check-in, and never from Vajra holding
  // telemetry — CERT-In Direction (iv) obligates the entity for the logs of its
  // own ICT systems.
  '4.1': {
    label: 'Whether logging is enabled on all ICT systems as per the guidelines?',
  },
  // 4.2 (180-day log retention) is not listed: the control concerns the logs of
  // the entity's own ICT systems, which the entity is obliged to retain. Vajra
  // does not measure that, and its retention of the telemetry it collects
  // itself answers a different question. It falls back to the manual Yes/No
  // checklist rather than being asserted without evidence.
  '5.8': {
    label: 'Whether unwanted or unused OS components, services, ports, applications are uninstalled or disabled?',
  },
  // 5.10 (Antivirus/EDR client recommended by CERT-In and NIC-CERT) is not listed
  // for the same reason as 3.4. Vajra's agent being installed and running does
  // evidence that an EDR is present on the node, but not that the specific client
  // CERT-In and NIC-CERT recommend is the one installed — that requires the
  // CERT-In/NIC-CERT recommended-product list, which the platform does not hold.
  // Absence here means "not assessed", never "no antivirus/EDR on this node".
  // 5.11 is answered from windows_security_products.signatures_up_to_date — the
  // Windows Security Center report of whether each running antivirus product's
  // definitions are current — corroborated where available by the live Defender
  // signature date (read-only PowerShell key 64). It is still NOT answered from
  // Windows Update history: OS patch currency is not antivirus signature
  // currency.
  '5.11': {
    label: 'Whether provision is made to update Antivirus client and Server with the latest patches/updates?',
  },
};

// STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS — Class A controls, confirmed by the 2026-09-03
// live-sweep verification pass (see the compliance-controls-removal task doctrine).
//
// Class A vs Class B distinction:
//   Class A = STRUCTURALLY UNMEASURABLE. Every code path for this key in
//     utils/certinComplianceChecks.ts resolves unconditionally to notAssessed() — there is no
//     branch, on any host, on any run, that can ever produce a measured pass or fail, because
//     no evidence source exists for it. This is the removal-candidate set.
//   Class B = TRANSIENTLY UNASSESSED ON SOME HOSTS. The evaluator has a real, reachable
//     pass/fail branch and does produce measured verdicts on most swept hosts; a control
//     rendering "not assessed" for some or even all hosts on ONE sweep is NOT evidence of
//     Class A — that determination must come from the evaluator code, never from a single
//     run's numbers. 3.3 (OS auto-update source) was checked and confirmed Class B: it has a
//     real, reachable, fleet-history-evidenced fail branch (windows_security_center.autoupdate
//     = 'Poor'/'Error'), it simply had no host in the 'Poor'/'Error' state on the sweep that
//     prompted this review — it is deliberately excluded from this set.
//
// This set was derived by reading every branch of every key in utils/certinComplianceChecks.ts
// and cross-checking against the live fleet DB on 2026-09-03. Consumers (UI table + PDF/report
// generation) should filter rendered/exported rows against this set so both surfaces drop the
// same controls in lockstep.
export const STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS: ReadonlySet<string> = new Set([
  '1.12',
  '2.6',
  '5.8',
]);

// CERTIN_AUTOMATED_POINT_DETAILS — tooltip metadata for the 7 CERT-In points Vajra answers
// automatically (CERTIN_PENDING_POINTS minus STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS). Mirrors
// SEBI_HOT_REASON_DETAIL in sebiHotGuidelines.ts: `tooltip` is the short citation shown in the
// InfoTooltip header, `reason` is the always-shown factual "what's measured" + "To become
// compliant: ..." paragraph, `detail` is a short one-line summary kept for parity with the SEBI
// constant's shape (not currently rendered).
//
// `tooltip` is not a regulatory clause number: the CERT-In checklist JSON
// (public/certin-compliance.json) carries no per-point clause/annexure citation beyond the
// point's own marker and the name of the checklist it belongs to, so that is what is cited here
// rather than inventing a clause number that does not exist in the source data.
//
// Every `reason` below was written by reading the live evaluator branch(es) for that marker in
// utils/certinComplianceChecks.ts in full (2026-09-07) — it describes what is actually measured
// right now, not a generic capability claim. Two points are structurally incapable of a
// measured pass or fail respectively, and say so explicitly rather than implying otherwise:
//   - 3.3 (OS auto-update source) has no `compliant: true` branch at all: even when Windows
//     Security Center reports Automatic Updates healthy, the control also requires the update
//     SOURCE to be a trusted one, which is not measured, so that case resolves to not-assessed
//     rather than a pass. A full "Compliant" verdict is not something Vajra can show for this
//     control, ever, even when the node genuinely is compliant.
//   - 1.4 (authorized hardware/software inventory) has no `compliant: false` branch: the
//     evaluator either finds a populated inventory (pass) or has no usable data (not-assessed);
//     it never asserts a measured "this node's inventory is missing/unauthorized" negative.
// 4.1's remediation deliberately does not claim that a pass discharges CERT-In Direction (iv):
// that direction obligates the entity for the RETENTION of its own ICT system logs, a different
// question from whether audit-log GENERATION is enabled, which is all 4.1 measures.
export const CERTIN_AUTOMATED_POINT_DETAILS: Record<string, { tooltip: string; reason: string; detail: string }> = {
  '1.4': {
    tooltip: 'CERT-In LAN Security Checklist — Point 1.4',
    reason: 'Vajra measures whether it holds a POPULATED hardware and software inventory for this node: at least 3 of {vendor, model, CPU, RAM, OS name} present, and a non-empty installed-software/package list. It does not measure whether that inventory is of AUTHORIZED assets specifically — no organisation-approved hardware/software baseline is stored to compare against, so that half of the control can never be confirmed here, pass or fail. This control also has no measured-fail state in Vajra: an incomplete inventory resolves to Not Assessed, never a "not authorized" finding. To become compliant: ensure the Vajra Agent is installed, running, and has successfully reported both an installed-software/package list and hardware details (vendor, model, CPU, RAM) for this node at least once — that clears Vajra\'s own populated-inventory check. Confirming the inventory is of AUTHORIZED assets remains an activity the organization must perform against its own asset baseline; Vajra cannot assess that half.',
    detail: 'Passes when hardware + software inventory is populated; the "authorized" half and any fail state are not measurable here.',
  },
  '1.10': {
    tooltip: 'CERT-In LAN Security Checklist — Point 1.10',
    reason: 'Vajra checks this node\'s Windows Firewall in three stages: (1) whether the firewall is switched off or its default inbound action is Allow on any profile (live PowerShell, or Windows Security Center firewall-product state as a fallback); (2) whether any enabled inbound Allow rule opens an SMB (139/445), RDP (3389) or WinRM (5985/5986) port to the whole segment ("*", Any, or LocalSubnet) — the remote-service ports MITRE ATT&CK T1021 moves laterally over; the stock RPC/NetBIOS rules on 135/137/138 are deliberately excluded so the control does not fire on default discovery traffic. A pass additionally requires every profile to be confirmed enabled with default inbound Block. To become compliant: in Windows Defender Firewall with Advanced Security, ensure every profile (Domain/Private/Public) is Enabled with Default Inbound Action set to Block, then review every enabled inbound Allow rule and either disable it or restrict its Remote address to specific management IPs/subnets instead of Any/LocalSubnet for any rule permitting port 139, 445, 3389, 5985 or 5986.',
    detail: 'Fails on a disabled/Allow-default profile or a segment-wide inbound Allow rule on an SMB/RDP/WinRM port; passes only once all profiles are confirmed Block-by-default with no such rule.',
  },
  '3.3': {
    tooltip: 'CERT-In Desktop/Laptop/Printer Security Checklist — Point 3.3',
    reason: 'Vajra reads windows_security_center.autoupdate for this node. "Poor" or "Error" is treated as a measured failure. Any other value, including "Good", is Not Assessed rather than a pass: the control also requires the update SOURCE to be a trusted one, and Vajra collects no Windows Update policy values (WUServer/AUOptions) or approved-source list to verify that half. This control therefore has no measured-pass state in Vajra at all, even when the node is genuinely configured correctly. To become compliant: clear the FAIL state by fixing Automatic Updates health in Windows Security Center (turn Automatic Updates back on / resolve whatever is reporting it as Poor or Error) — this is the only outcome Vajra can move for this control. It cannot produce a "Compliant" verdict for 3.3 even after that fix, since update-source trust is outside what it measures.',
    detail: 'Fails only when Automatic Updates is reported Poor/Error; every other state, including healthy, is Not Assessed — this control has no measured-pass state.',
  },
  '3.7': {
    tooltip: 'CERT-In Desktop/Laptop/Printer Security Checklist — Point 3.7',
    reason: 'Vajra reads this node\'s Windows security profile (minimum password length, complexity, password history, lockout threshold), falling back to the baseline \'net accounts\' minimum-length probe when the profile is unavailable. It fails when the minimum length is below 8 characters, complexity is switched off, password history is 0, or the lockout threshold is 0. To become compliant: in Local Security Policy / Group Policy (Account Policies -> Password Policy and Account Lockout Policy), set Minimum password length to at least 8 characters, enable "Password must meet complexity requirements", set "Enforce password history" to at least 1 remembered password, and set Account lockout threshold to a value greater than 0. The 8-character minimum is a Vajra platform default used for this baseline check, not a figure this control text itself specifies.',
    detail: 'Fails on minimum length < 8, complexity off, history 0, or lockout threshold 0 (Windows security profile, or net accounts as fallback).',
  },
  '3.8': {
    tooltip: 'CERT-In Desktop/Laptop/Printer Security Checklist — Point 3.8',
    reason: 'Vajra queries live USB telemetry for this node (Windows: PowerShell key 54; Linux: the removableDevice agent) and reads whether removable storage is reported enabled or disabled. Compliant means storage is reported disabled; permitted (enabled) storage is a measured fail. If the query returns neither state, 3.8 is left Not Assessed rather than guessed. To become compliant: disable removable/USB storage on this endpoint — for example via Group Policy ("Removable Storage Access: All Removable Storage classes: Deny all access") or by setting the USBSTOR service Start value to 4 in the registry — so the next live query reports storage as disabled.',
    detail: 'Passes only when live USB telemetry reports removable storage disabled; enabled storage is a measured fail.',
  },
  '4.1': {
    tooltip: 'CERT-In Logging Compliance Checklist — Point 4.1',
    reason: 'Vajra reads this node\'s OWN advanced audit policy: 12 `auditpol /get /subcategory:` probes (Special Logon, Credential Validation, Computer Account Management, Other Account Management Events, Security Group Management, User Account Management, Process Creation, Plug and Play Events, Account Lockout, Logon, IPsec Driver, Security System Extension) from the last baseline sweep. All 12 auditing both Success and Failure is a pass; any measured as off is a fail; a baseline older than 90 days, absent, or only partially returned is Not Assessed. This measures whether audit-log GENERATION is enabled on this Windows endpoint only — servers, network devices and applications outside Vajra-managed Windows endpoints are not covered, and CERT-In Direction (iv), the entity\'s own obligation to RETAIN its ICT systems\' logs, is a separate question this control does not answer; Vajra holding a copy of collected telemetry does not discharge that retention obligation. To become compliant: on this endpoint, run `auditpol /set /subcategory:"<name>" /success:enable /failure:enable` for each of the 12 subcategories above (or configure them via Advanced Audit Policy Configuration in Group Policy), then re-run the Vajra compliance baseline sweep so a fresh (under 90 days old) result is on record.',
    detail: 'Passes only when all 12 measured advanced-audit-policy subcategories audit Success and Failure on a baseline under 90 days old; measures generation only, never retention.',
  },
  '5.11': {
    tooltip: 'CERT-In Server Security Checklist — Point 5.11',
    reason: 'Vajra reads windows_security_products.signatures_up_to_date for every running antivirus product Windows Security Center reports on this node, corroborated (when Defender is one of them) by live Defender signature-date telemetry against a 7-day currency bound. Any running product reported with stale definitions, or a Defender signature set older than 7 days, is a measured fail; no running antivirus product, or no signature-currency value reported, is Not Assessed rather than a fail. Windows Update install history is deliberately not used — that is OS patch currency, not antivirus signature currency. To become compliant: ensure the antivirus product actually running on this node updates its definitions (for Defender, `Update-MpSignature` or "Check for updates" in Windows Security) so Windows Security Center reports signatures_up_to_date, and so any Defender signature set is refreshed within the 7-day bound this check uses — a Vajra platform default, not a figure this control text itself specifies.',
    detail: 'Fails when a running antivirus product\'s definitions are stale, or Defender signatures exceed 7 days old; passes when the running product(s) report current definitions.',
  },
};
