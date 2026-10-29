/** `alerts.alert_type` literal constants shared between the writer (websocket/node.ts) and readers (controllers/alerts/*, controllers/general-graphs/*) (no env). */

/** alert_type written for every ClamAV on-demand/scheduled scan result (clean, error, or infected). */
export const ALERT_TYPE_CLAMAV_SCAN = 'ClamAV Scan';

/** alert_type written for a ClamAV malware detection (open until resolved). */
export const ALERT_TYPE_CLAMAV_ALERT = 'ClamAV Alert';

/** alert_type written for a USB device connect/policy-violation event. */
export const ALERT_TYPE_USB_DEVICE = 'USB Device Alert';

/**
 * SQL boolean-expression fragments (reference the `a` alias for the `alerts`
 * table) matching each normalized severity bucket against the raw,
 * inconsistently-cased/worded `alerts.severity` column. Shared verbatim
 * between alert_list.ts and alert_list_my.ts so their severity filter and
 * per-severity counts stay in lockstep.
 */
export const ALERT_SEVERITY_SQL_CONDITIONS: Record<string, string> = {
  critical: `(
    LOWER(TRIM(COALESCE(a.severity, ''))) IN ('critical', 'severe')
    OR TRIM(COALESCE(a.severity, '')) IN ('4', '5')
  )`,
  high: `(
    LOWER(TRIM(COALESCE(a.severity, ''))) = 'high'
    OR TRIM(COALESCE(a.severity, '')) = '3'
  )`,
  medium: `(
    LOWER(TRIM(COALESCE(a.severity, ''))) IN ('medium', 'moderate')
    OR TRIM(COALESCE(a.severity, '')) = '2'
  )`,
  low: `(
    LOWER(TRIM(COALESCE(a.severity, ''))) = 'low'
    OR TRIM(COALESCE(a.severity, '')) = '1'
  )`,
};
