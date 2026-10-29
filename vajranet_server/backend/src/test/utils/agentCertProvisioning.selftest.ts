/**
 * Self-contained test for agent mTLS cert-provisioning CSR signing. No test
 * framework required — run with ts-node:
 *
 *   node_modules/.bin/ts-node src/test/utils/agentCertProvisioning.selftest.ts
 *
 * Builds a throwaway Agent CA and agent keypair/CSR with the openssl CLI
 * (same tool signAgentCsr itself shells out to), points AGENT_CA_DIR at the
 * throwaway CA, and asserts: a valid CSR gets signed with CN forced to the
 * requested host_identifier, the issued cert verifies against the CA, a CSR
 * whose own subject claims a DIFFERENT identity still gets the forced CN
 * (the security property the whole design depends on), and malformed/invalid
 * inputs are rejected. Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

function main() {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vajra-cert-provision-selftest-'));
  process.env.AGENT_CA_DIR = workDir;

  // Build a throwaway CA (same commands as in .env.example).
  const caKey = path.join(workDir, 'agent-ca.key');
  const caCert = path.join(workDir, 'agent-ca.crt');
  execFileSync('openssl', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', caKey]);
  execFileSync('openssl', [
    'req', '-x509', '-new', '-key', caKey, '-sha256', '-days', '3650',
    '-subj', '/O=Vajra/OU=EDR/CN=Test Agent CA', '-out', caCert,
  ]);

  // agentCertProvisioning.ts reads AGENT_CA_DIR at module load time via a
  // top-level `const CA_DIR = ...`, so it must be imported AFTER the env var
  // is set above, not hoisted to the top of this file.
  const { signAgentCsr, caFilesAvailable, getAgentCaCertPem } = require('../../utils/agentCertProvisioning');

  assert.strictEqual(caFilesAvailable(), true, 'CA files should be detected once written');
  assert.ok(getAgentCaCertPem().includes('BEGIN CERTIFICATE'), 'CA cert PEM should be readable');

  function makeCsr(cn: string): string {
    const keyPath = path.join(workDir, `${cn.replace(/[^a-z0-9]/gi, '_')}.key`);
    const csrPath = path.join(workDir, `${cn.replace(/[^a-z0-9]/gi, '_')}.csr`);
    execFileSync('openssl', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', keyPath]);
    execFileSync('openssl', ['req', '-new', '-key', keyPath, '-subj', `/O=Vajra/OU=Agent/CN=${cn}`, '-out', csrPath]);
    return fs.readFileSync(csrPath, 'utf-8');
  }

  function certCN(certPem: string): string {
    const out = execFileSync('openssl', ['x509', '-noout', '-subject', '-nameopt', 'RFC2253'], { input: certPem }).toString();
    const m = out.match(/CN=([^,\n]+)/);
    return m ? m[1].trim() : '';
  }

  function verifyChain(certPem: string): boolean {
    try {
      execFileSync('openssl', ['verify', '-CAfile', caCert], { input: certPem });
      return true;
    } catch {
      return false;
    }
  }

  async function run() {
    // 1. Valid CSR, CN forced to the requested host_identifier and matches the CSR's own.
    const csr1 = makeCsr('host-real-1');
    const cert1 = await signAgentCsr(csr1, 'host-real-1');
    assert.strictEqual(certCN(cert1), 'host-real-1', 'issued cert CN should equal host_identifier');
    assert.ok(verifyChain(cert1), 'issued cert should verify against the CA');

    // 2. Security property: CSR self-declares a DIFFERENT CN than the
    // host_identifier the token is bound to — the issued cert must ignore
    // the CSR's own subject entirely and use the server-forced identity.
    const csrClaimingOther = makeCsr('attacker-claimed-identity');
    const cert2 = await signAgentCsr(csrClaimingOther, 'host-real-2');
    assert.strictEqual(
      certCN(cert2),
      'host-real-2',
      "issued cert must use the token's bound host_identifier, not the CSR's own claimed subject",
    );

    // 2b. Concurrency: fire several signing calls at once and confirm every
    // one succeeds with a distinct, chain-verifying, correctly-CN'd cert —
    // regression check for the signQueue serialization around the shared
    // agent-ca.srl file (OpenSSL's -CAcreateserial has no locking of its own,
    // so unserialized concurrent calls can race on it).
    const concurrentHosts = ['host-concurrent-1', 'host-concurrent-2', 'host-concurrent-3', 'host-concurrent-4'];
    const concurrentCerts = await Promise.all(
      concurrentHosts.map((h) => signAgentCsr(makeCsr(h), h)),
    );
    concurrentHosts.forEach((h, i) => {
      assert.strictEqual(certCN(concurrentCerts[i]), h, `concurrent cert #${i} should have CN ${h}`);
      assert.ok(verifyChain(concurrentCerts[i]), `concurrent cert #${i} should verify against the CA`);
    });
    const serialNumbers = new Set(
      concurrentCerts.map((c) => execFileSync('openssl', ['x509', '-noout', '-serial'], { input: c }).toString().trim()),
    );
    assert.strictEqual(serialNumbers.size, concurrentHosts.length, 'concurrent signing must not produce duplicate serial numbers');

    // 3. Missing CA -> rejected.
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vajra-cert-provision-selftest-noca-'));
    const prevDir = process.env.AGENT_CA_DIR;
    process.env.AGENT_CA_DIR = emptyDir;
    delete require.cache[require.resolve('../../utils/agentCertProvisioning')];
    const { signAgentCsr: signWithNoCa } = require('../../utils/agentCertProvisioning');
    await assert.rejects(() => signWithNoCa(csr1, 'host-real-1'), /Agent CA not provisioned/, 'missing CA must be rejected');
    process.env.AGENT_CA_DIR = prevDir;
    delete require.cache[require.resolve('../../utils/agentCertProvisioning')];

    // 4. Invalid host_identifier (characters that could confuse -subj parsing).
    const { signAgentCsr: signAgain } = require('../../utils/agentCertProvisioning');
    await assert.rejects(() => signAgain(csr1, '../../etc/passwd'), /Invalid host_identifier/, 'path-like host_identifier must be rejected');
    await assert.rejects(() => signAgain(csr1, 'host/CN=evil'), /Invalid host_identifier/, 'subj-breaking host_identifier must be rejected');

    // 5. Malformed CSR PEM.
    await assert.rejects(() => signAgain('not a csr', 'host-real-1'), /Malformed CSR PEM/, 'malformed CSR must be rejected');

    // 6. Oversized CSR.
    await assert.rejects(
      () => signAgain('-----BEGIN CERTIFICATE REQUEST-----\n' + 'A'.repeat(9000) + '\n-----END CERTIFICATE REQUEST-----', 'host-real-1'),
      /Invalid or oversized CSR/,
      'oversized CSR must be rejected',
    );

    console.log('agentCertProvisioning.selftest: all checks passed');
  }

  run()
    .then(() => {
      fs.rmSync(workDir, { recursive: true, force: true });
      process.exit(0);
    })
    .catch((err) => {
      console.error(err);
      fs.rmSync(workDir, { recursive: true, force: true });
      process.exit(1);
    });
}

main();
