-- Fleet DB: cve_id indexes on the vulnexus match tables.
--
-- getVulnerabilityDetail (controllers/vulnerabilities/vulnexus_read.ts) queries
-- `WHERE cve_id = $1` against vulnexus_host_vulnerabilities, vulnexus_package_cves
-- and vulnexus_rpm_package_cves on every per-CVE detail request, but none of
-- these externally-owned tables ship a cve_id index, so each request forces a
-- sequential scan. This mirrors the existing idx_hv_program_id/idx_hv_severity/
-- idx_hv_detected_at supplementary indexes this repo already adds on
-- vulnexus_host_vulnerabilities in create_grafana_views.sql.
--
-- Run this against the `fleet` database (POSTGRES_DB1). Safe to re-run:
-- IF NOT EXISTS guards every statement. CONCURRENTLY cannot run inside a
-- transaction block, so apply with autocommit on, e.g.
-- `psql -f add_vulnexus_cve_indexes.sql`.
--
-- No idx_hv_cve_id here: 009_add_vulnexus_host_vulnerabilities_cve_index.sql
-- already added idx_hv_cve_id_cvss (cve_id, cvss_score DESC NULLS LAST) on
-- this same table — cve_id already leads that composite index, so a second,
-- narrower cve_id-only index here would be pure redundant write overhead.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pc_cve_id ON vulnexus_package_cves(cve_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rc_cve_id ON vulnexus_rpm_package_cves(cve_id);
