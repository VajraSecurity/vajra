/**
 * Build-time feature flags (Vite env). A flag is ON only when its env var is
 * exactly the string 'true'; unset means OFF.
 *
 * VITE_RULE_ENGINE_ENABLED — shows the Rule Engine sidebar entry and the
 * /rule-engine page. Hidden by default until the rule engine backend
 * (RULE_ENGINE_API_URL) is set up for the deployment.
 */
export const RULE_ENGINE_ENABLED = import.meta.env.VITE_RULE_ENGINE_ENABLED === 'true';
