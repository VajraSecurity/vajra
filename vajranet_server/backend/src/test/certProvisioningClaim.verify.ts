/**
 * Verification harness (TEAM 1): exercises the exact claim-UPDATE used by
 * provisionAgentCert against a real Postgres through the real TypeORM stack,
 * and compares the OLD guard (`!updateResult || updateResult.length === 0`)
 * with the NEW guard (`returningRows(...).length === 0`).
 *
 * Proves (a) the new guard still ACCEPTS a valid/active/unexpired/host-matched
 * token, and (b) it rejects every invalid state the old guard let through.
 * Local throwaway DB only.
 */
import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { SnakeNamingStrategy } from 'typeorm-naming-strategies';
import { AgentCertProvisioningToken } from '../orm/entities/fleet/AgentCertProvisioningToken';
import { returningRows, returningRowCount } from '../utils/returningRows';

const CLAIM_SQL = `UPDATE agent_cert_provisioning_tokens
   SET status = 'used', used_at = NOW()
   WHERE token_hash = $1 AND host_identifier = $2 AND status = 'active' AND expires_at > NOW()
   RETURNING id`;

type Case = {
  name: string;
  hash: string;
  host: string;
  claimHash: string;
  claimHost: string;
  status: string;
  expiresInMs: number;
  usedAt?: Date | null;
  revokedAt?: Date | null;
  shouldSucceed: boolean;
};

async function main() {
  const ds = new DataSource({
    type: 'postgres',
    host: '/var/run/postgresql',
    username: process.env.USER,
    database: 'zz_typeorm_verify',
    entities: [AgentCertProvisioningToken],
    namingStrategy: new SnakeNamingStrategy(),
    synchronize: true,
    logging: false,
  });
  await ds.initialize();
  const repo = ds.getRepository(AgentCertProvisioningToken);

  const H = 'host-A-11111111-2222-3333-4444-555555555555';
  const OTHER = 'host-B-99999999-8888-7777-6666-555555555555';

  const cases: Case[] = [
    { name: 'VALID active, unexpired, host matches', hash: 'h_valid', host: H, claimHash: 'h_valid', claimHost: H, status: 'active', expiresInMs: 3600_000, shouldSucceed: true },
    { name: 'VALID active, expires in 2s (still unexpired)', hash: 'h_soon', host: H, claimHash: 'h_soon', claimHost: H, status: 'active', expiresInMs: 2_000, shouldSucceed: true },
    { name: 'EXPIRED token', hash: 'h_exp', host: H, claimHash: 'h_exp', claimHost: H, status: 'active', expiresInMs: -1_000, shouldSucceed: false },
    { name: 'ALREADY USED token', hash: 'h_used', host: H, claimHash: 'h_used', claimHost: H, status: 'used', expiresInMs: 3600_000, usedAt: new Date(), shouldSucceed: false },
    { name: 'REVOKED token', hash: 'h_rev', host: H, claimHash: 'h_rev', claimHost: H, status: 'revoked', expiresInMs: 3600_000, revokedAt: new Date(), shouldSucceed: false },
    { name: 'HOST MISMATCH (token for A, claimed as B)', hash: 'h_mis', host: H, claimHash: 'h_mis', claimHost: OTHER, status: 'active', expiresInMs: 3600_000, shouldSucceed: false },
    { name: 'UNKNOWN token hash', hash: 'h_known', host: H, claimHash: 'h_does_not_exist', claimHost: H, status: 'active', expiresInMs: 3600_000, shouldSucceed: false },
  ];

  let failures = 0;
  const check = (name: string, ok: boolean, detail = '') => {
    console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (detail ? ' :: ' + detail : ''));
    if (!ok) failures++;
  };

  let oldWronglyAccepted = 0;
  for (const c of cases) {
    await repo.clear();
    await repo.save(repo.create({
      tokenHash: c.hash,
      hostIdentifier: c.host,
      issuedById: 1,
      issuedByEmail: 'admin@test.local',
      status: c.status as any,
      expiresAt: new Date(Date.now() + c.expiresInMs),
      usedAt: c.usedAt ?? null,
      revokedAt: c.revokedAt ?? null,
    }));

    const raw = await ds.query(CLAIM_SQL, [c.claimHash, c.claimHost]);

    // OLD guard, verbatim from the pre-fix source.
    const oldRejects = !raw || (raw as any).length === 0;
    // NEW guard.
    const newRejects = returningRows<{ id: number }>(raw).length === 0;

    const newAccepts = !newRejects;
    check('[' + c.name + '] NEW guard ' + (c.shouldSucceed ? 'ACCEPTS' : 'REJECTS'),
      newAccepts === c.shouldSucceed,
      'rawShape=' + JSON.stringify(raw) + ' returningRowCount=' + returningRowCount(raw));

    if (!c.shouldSucceed && !oldRejects) oldWronglyAccepted++;

    // Confirm the row was actually claimed (or not) in the database.
    const after = await repo.findOne({ where: { tokenHash: c.hash } });
    if (c.shouldSucceed) {
      check('[' + c.name + '] row marked used in DB', after?.status === 'used' && after?.usedAt !== null);
    } else if (c.hash !== 'h_known') {
      check('[' + c.name + '] row NOT consumed in DB', after?.status === c.status);
    }
  }

  check('OLD guard wrongly accepted every invalid case (confirms the bug the fix closes)',
    oldWronglyAccepted === cases.filter((c) => !c.shouldSucceed).length,
    'oldWronglyAccepted=' + oldWronglyAccepted + '/' + cases.filter((c) => !c.shouldSucceed).length);

  // Double-claim: a valid token must succeed exactly once.
  await repo.clear();
  await repo.save(repo.create({
    tokenHash: 'h_once', hostIdentifier: H, issuedById: 1, issuedByEmail: 'a@b.c',
    status: 'active' as any, expiresAt: new Date(Date.now() + 3600_000), usedAt: null, revokedAt: null,
  }));
  const first = returningRows(await ds.query(CLAIM_SQL, ['h_once', H])).length;
  const second = returningRows(await ds.query(CLAIM_SQL, ['h_once', H])).length;
  check('valid token is claimable exactly once (1 then 0)', first === 1 && second === 0, 'first=' + first + ' second=' + second);

  await ds.destroy();
  console.log(failures === 0 ? 'ALL CHECKS PASSED' : String(failures) + ' CHECK(S) FAILED');
  process.exit(failures === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(2); });
