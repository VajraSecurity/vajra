import { Router } from 'express';

import auth from './auth';
import nodes from './nodes';
import alerts from './alerts';
import graph from './graphs';
import windows from './windows';
import users from './users';
import ai from './ai';
import threatHunting from './threat-hunting';
import compliancePdf from './compliance_pdf';
import network from './network';
import dataRetention from './data-retention';
import nessus from './nessus';
import openvas from './openvas';
import endpointGroups from './endpoint-groups';
import policies from './policies';
import burpsuite from './burpsuite';
import agent from './agent';
import nodeAssignmentRules from './node-assignment-rules';
import patch from './patch';
import windowsPatchManagement from './windowsPatchManagement';
import vulnerabilities from './vulnerabilities';
import domainReputation from './domain-reputation';
import assets from './assets';
import ruleEngine from './rule-engine';
import fim from './fim';

const router = Router();

router.get('/', (_req, res) => {
	res.status(200).send("Hey, welcome to Vajra");
});

router.use('/auth', auth);
router.use('/nodes', nodes);
router.use('/alerts', alerts);
router.use('/graph', graph);
router.use('/windows', windows);
router.use('/users', users);
router.use('/ai', ai);
router.use('/threat-hunting', threatHunting);
router.use('/compliance', compliancePdf);
router.use('/network', network);
router.use('/data-retention', dataRetention);
router.use('/nessus', nessus);
router.use('/openvas', openvas);
router.use('/groups', endpointGroups);
router.use('/policies', policies);
router.use('/burpsuite', burpsuite);
router.use('/agent', agent);
router.use('/node-assignment-rules', nodeAssignmentRules);
router.use('/patch', patch);
// Windows maintained-app (third-party software) install/uninstall — a
// distinct base path from /patch above, which is the pre-existing, unrelated
// Linux osupdate feature.
router.use('/patch-management', windowsPatchManagement);
router.use('/vulnerabilities', vulnerabilities);
router.use('/domain-reputation', domainReputation);
// Asset identity resolution — the read-only view tying agent nodes and
// agentless scan results to one machine, plus its per-scan timeline.
router.use('/assets', assets);
// Authenticated proxy in front of the sibling vajra_server repo's
// unauthenticated internal rule engine console — see rule-engine.ts's header.
router.use('/rule-engine', ruleEngine);
// File Integrity Monitoring (policies, baselines, drift) — see routes/api/fim.ts.
router.use('/fim', fim);

export default router;
