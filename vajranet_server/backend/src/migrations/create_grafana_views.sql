-- View 1: CVE summary per host, aggregated from vulnexus_host_vulnerabilities.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_host_cve_summary AS
SELECT
  LOWER(n.host_identifier) AS host_identifier,
  MAX(n.hostname) AS hostname,
  MAX(n.os_name) AS os_name,
  MAX(n.os_platform) AS os_platform,
  COUNT(DISTINCT hv.cve_id) AS unique_cves,
  COUNT(DISTINCT p.name) AS vulnerable_sw_count,
  COUNT(*) FILTER (WHERE hv.severity = 'CRITICAL') AS critical_cves,
  COUNT(*) FILTER (WHERE hv.severity = 'HIGH') AS high_cves,
  COUNT(*) FILTER (WHERE hv.severity = 'MEDIUM') AS medium_cves,
  COUNT(*) FILTER (WHERE hv.severity = 'LOW') AS low_cves,
  COALESCE(MAX(hv.cvss_score), 0) AS max_cvss_score,
  ROUND(AVG(hv.cvss_score), 1) AS avg_cvss_score,
  NOW() AS refreshed_at
FROM vulnexus_host_vulnerabilities hv
JOIN programs p ON p.id = hv.program_id
JOIN nodes n ON LOWER(n.host_identifier) = LOWER(p.host_identifier)
GROUP BY LOWER(n.host_identifier);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_host_cve_summary_host_id ON mv_host_cve_summary (host_identifier);

-- View 2: flat CVE-to-software-to-host mapping, for Grafana table panels.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_software_cve_flat AS
SELECT
  p.host_identifier,
  n.hostname,
  p.name AS software_name,
  p.version AS software_version,
  p.publisher,
  hv.cve_id,
  hv.severity,
  hv.cvss_score,
  hv.match_source,
  hv.detected_at,
  cv.description AS cve_description,
  cv.published AS cve_published,
  cv.cvss3_score,
  cv.cvss3_severity
FROM vulnexus_host_vulnerabilities hv
JOIN programs p ON p.id = hv.program_id
JOIN nodes n ON LOWER(n.host_identifier) = LOWER(p.host_identifier)
LEFT JOIN vulnexus_nvd_cves1 cv ON cv.cve_id = hv.cve_id;

CREATE INDEX IF NOT EXISTS idx_mv_software_cve_flat_host_id ON mv_software_cve_flat (host_identifier);
CREATE INDEX IF NOT EXISTS idx_mv_software_cve_flat_severity ON mv_software_cve_flat (severity);
CREATE INDEX IF NOT EXISTS idx_mv_software_cve_flat_cvss_score ON mv_software_cve_flat (cvss_score DESC);

-- View 3: CVE detection trend, a time series for Grafana.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_cve_detection_trend AS
SELECT
  date_trunc('day', hv.detected_at) AS day,
  hv.severity,
  COUNT(*) AS new_detections,
  COUNT(DISTINCT hv.cve_id) AS unique_cves
FROM vulnexus_host_vulnerabilities hv
WHERE hv.detected_at IS NOT NULL
GROUP BY day, hv.severity
ORDER BY day;

CREATE INDEX IF NOT EXISTS idx_mv_cve_detection_trend_day ON mv_cve_detection_trend (day);

-- View 4: multi-framework compliance trend.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_compliance_trend AS
SELECT 'Vajra' AS framework, to_timestamp(snapshot_at) AS snapshot_time,
  total_nodes, windows_with_results, COALESCE(jsonb_array_length(fully_compliant_nodes_list), 0) AS fully_compliant_nodes,
  avg_compliance_percent, strong_count, moderate_count, needs_attention_count
FROM historical_compliance
UNION ALL
SELECT 'CERT-In', to_timestamp(snapshot_at),
  total_nodes, windows_with_results, COALESCE(jsonb_array_length(fully_compliant_nodes_list), 0) AS fully_compliant_nodes,
  avg_compliance_percent, strong_count, moderate_count, needs_attention_count
FROM certin_historical_compliance
UNION ALL
SELECT 'SEBI', to_timestamp(snapshot_at),
  total_nodes, windows_with_results, COALESCE(jsonb_array_length(fully_compliant_nodes_list), 0) AS fully_compliant_nodes,
  avg_compliance_percent, strong_count, moderate_count, needs_attention_count
FROM sebi_historical_compliance
UNION ALL
SELECT 'IRDAI', to_timestamp(snapshot_at),
  total_nodes, windows_with_results, COALESCE(jsonb_array_length(fully_compliant_nodes_list), 0) AS fully_compliant_nodes,
  avg_compliance_percent, strong_count, moderate_count, needs_attention_count
FROM irdai_historical_compliance
ORDER BY snapshot_time;

-- View 5: alert severity by MITRE technique.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_alert_mitre_summary AS
SELECT
  technique,
  technique_id,
  severity,
  COUNT(*) AS alert_count,
  COUNT(DISTINCT host_identifier) AS affected_hosts,
  COUNT(*) FILTER (WHERE is_open = true) AS open_count
FROM alerts
WHERE is_alert = true
GROUP BY technique, technique_id, severity;

-- View 6: patch gap analysis, patches against open CVEs per host.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_patch_gap AS
SELECT
  n.host_identifier,
  n.hostname,
  COUNT(DISTINCT pa.hotfix_id) AS installed_patches,
  (SELECT COUNT(*) FROM vulnexus_host_vulnerabilities hv2
   JOIN programs p2 ON p2.id = hv2.program_id
   WHERE LOWER(p2.host_identifier) = LOWER(n.host_identifier)) AS open_cves,
  MAX(pa.installed_on) AS last_patch_date
FROM nodes n
LEFT JOIN patches pa ON LOWER(pa.host_identifier) = LOWER(n.host_identifier)
GROUP BY n.host_identifier, n.hostname;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_patch_gap_host_id ON mv_patch_gap (host_identifier);

-- View 7: Linux package CVE summary (deb + rpm).
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_linux_package_cves AS
SELECT
  'deb' AS pkg_type,
  pc.package_id,
  dp.host_identifier,
  n.hostname,
  dp.name AS package_name,
  dp.version,
  pc.cve_id,
  cv.cvss3_severity AS severity,
  cv.cvss3_score,
  pc.patched_version,
  pc.detected_at
FROM vulnexus_package_cves pc
JOIN deb_packages dp ON dp.id = pc.package_id
JOIN nodes n ON LOWER(n.host_identifier) = LOWER(dp.host_identifier)
LEFT JOIN vulnexus_nvd_cves1 cv ON cv.cve_id = pc.cve_id
UNION ALL
SELECT
  'rpm',
  rc.package_id,
  rp.host_identifier,
  n.hostname,
  rp.name,
  rp.version,
  rc.cve_id,
  cv.cvss3_severity,
  cv.cvss3_score,
  rc.patched_version,
  rc.created_at AS detected_at
FROM vulnexus_rpm_package_cves rc
JOIN rpm_packages rp ON rp.id = rc.package_id
JOIN nodes n ON LOWER(n.host_identifier) = LOWER(rp.host_identifier)
LEFT JOIN vulnexus_nvd_cves1 cv ON cv.cve_id = rc.cve_id;

CREATE INDEX IF NOT EXISTS idx_mv_linux_package_cves_host_id ON mv_linux_package_cves (host_identifier);
CREATE INDEX IF NOT EXISTS idx_mv_linux_package_cves_severity ON mv_linux_package_cves (severity);

-- Supplementary indexes on the base tables the views read.
CREATE INDEX IF NOT EXISTS idx_hv_program_id ON vulnexus_host_vulnerabilities(program_id);
CREATE INDEX IF NOT EXISTS idx_hv_severity ON vulnexus_host_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_hv_detected_at ON vulnexus_host_vulnerabilities(detected_at);
CREATE INDEX IF NOT EXISTS idx_programs_host ON programs(host_identifier);
CREATE INDEX IF NOT EXISTS idx_alerts_host_open ON alerts(host_identifier) WHERE is_open = true AND is_alert = true;
CREATE INDEX IF NOT EXISTS idx_patches_host ON patches(host_identifier);

-- Refresh scheduling is deliberately not done here. pg_cron requires its
-- extension, and every cron.job it manages, to live in the single database
-- cron.database_name names (default 'postgres'), not in this one. Calling
-- cron.schedule() from a connection to this database either errors, because
-- the "cron" schema does not exist here, or would silently register a job
-- pg_cron never runs, since it only reads jobs from cron.database_name.
-- Scheduling therefore happens in grafana/setup.sh via
-- cron.schedule_in_database(), run against cron.database_name and targeting
-- this database by name. If that step fails or is skipped (setup.sh prints
-- "Warning: could not create pg_cron extension"), these materialized views
-- simply do not auto-refresh; nothing here can detect that from inside this
-- database's own migration.
