// Agent-facing endpoints. These are called by the endpoint agent, NOT by the
// dashboard, so they deliberately do not require a JWT session cookie. Trust
// does not come from the transport here: archives are verified by the agent
// against a signed manifest. Requests are rate-limited.

import { Router } from 'express';
import { provisionAgentCert } from '../../controllers/nodes';
import { servePatchArchive } from '../../controllers/nodes/patch_bundles_build';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// GET /api/agent/patch-archives/:filename — signed Patch Bundle archive
// download, the server-hosted archive_url target. Same no-JWT trust
// model as /manifest above: the archive_sha256 in the signed manifest (and
// each file's own hash after extraction) is what the agent actually trusts,
// not this transport.
router.get('/patch-archives/:filename', [apiDataLimiter], servePatchArchive);

// POST /api/agent/provision-cert — mTLS cert provisioning: agent submits a
// CSR plus the one-time token an admin generated for its host_identifier,
// gets back a signed mTLS client certificate. No JWT — the token itself is
// the auth. NOT osquery's own enrollment (separate C++ fleet server,
// separate TLS listener, unrelated to this endpoint).
router.post('/provision-cert', [apiMutationLimiter], provisionAgentCert);

export default router;
