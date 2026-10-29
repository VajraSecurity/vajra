/**
 * Pure, dependency-free helpers for the server-side "build a Patch Bundle
 * from a folder" pipeline (controllers/nodes/patch_bundles_build.ts).
 * Deliberately has NO import of express/TypeORM/../../index or anything
 * else that would transitively pull in server bootstrap — same rationale as
 * patchPackageValidation.ts's header comment: index.ts has a top-level
 * express()/IIFE bootstrap, so any module that imports it (even just for
 * dbSourceConnection) cannot be safely imported by a standalone selftest run
 * via plain ts-node. patch_bundles_build.ts imports these directly rather
 * than redefining them, so there is exactly one source of truth for this
 * validation/extraction logic, exercised by
 * patchBundleBuild.selftest.ts without booting the real server.
 */
import { execFile } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

// Bare directory-name only (no '/', no '..') — same discipline as the Go
// agent's isBareFilename (bundle_manifest.go). `source_dir` names a
// SUBDIRECTORY of PATCH_BUNDLE_STAGING_DIR, never an arbitrary path.
export const BARE_DIR_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
export const OS_MATCH_RE = /^[A-Za-z0-9][A-Za-z0-9._+ -]{0,127}$/;
export const CHANNEL_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const VERSION_FIELD_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;

export class BinaryMissingError extends Error {}

/**
 * Resolves `sourceDirName` (already BARE_DIR_NAME_RE-checked by the caller)
 * under `root` and verifies — via realpath, so a symlink planted inside the
 * root can't escape it — that the resolved path is still inside the root.
 * Mirrors the containment discipline bundle_extract.go applies on the agent
 * side for exactly the same reason. `root` is passed in (rather than read
 * from PATCH_BUNDLE_STAGING_DIR directly) so this stays pure/testable — the
 * caller in patch_bundles_build.ts resolves the env var and passes it here.
 */
export async function resolveWithinRoot(root: string, name: string): Promise<string> {
  const rootReal = await fs.promises.realpath(root);
  const candidate = path.join(rootReal, name);
  const candidateReal = await fs.promises.realpath(candidate);
  const prefix = rootReal.endsWith(path.sep) ? rootReal : rootReal + path.sep;
  if (candidateReal !== rootReal && !candidateReal.startsWith(prefix)) {
    throw new Error('path resolves outside the given root');
  }
  return candidateReal;
}

/** Fixed-argv, no-shell metadata extraction — never trusts the filename. */
export async function extractDebMetadata(absPath: string): Promise<{ name: string; version: string; arch: string }> {
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync('dpkg-deb', ['-f', absPath, 'Package', 'Version', 'Architecture']));
  } catch (e: any) {
    if (e?.code === 'ENOENT') throw new BinaryMissingError('dpkg-deb not found on this server — install dpkg-dev to build deb bundles');
    throw new Error(`dpkg-deb failed on ${path.basename(absPath)}: ${e.message}`, { cause: e });
  }
  const fields: Record<string, string> = {};
  for (const line of stdout.split('\n')) {
    const m = line.match(/^([A-Za-z]+):\s*(.*)$/);
    if (m) fields[m[1]] = m[2].trim();
  }
  if (!fields.Package || !fields.Version || !fields.Architecture) {
    throw new Error(`dpkg-deb returned incomplete metadata for ${path.basename(absPath)}`);
  }
  return { name: fields.Package, version: fields.Version, arch: fields.Architecture };
}

export async function extractRpmMetadata(absPath: string): Promise<{ name: string; version: string; arch: string }> {
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync('rpm', ['-qp', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}', absPath]));
  } catch (e: any) {
    if (e?.code === 'ENOENT') throw new BinaryMissingError('rpm not found on this server — install rpm to build rpm bundles');
    throw new Error(`rpm failed on ${path.basename(absPath)}: ${e.message}`, { cause: e });
  }
  const fields = stdout.trim().split(/\s+/);
  if (fields.length !== 3 || fields.some((f) => !f)) {
    throw new Error(`rpm returned unexpected metadata for ${path.basename(absPath)}: ${JSON.stringify(stdout)}`);
  }
  return { name: fields[0], version: fields[1], arch: fields[2] };
}

export function sha256File(absPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(absPath);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Returns the subset of `filenames` (each resolved under `dir`) that are
 * symlinks. Checked with lstat (never stat, which follows the link) so this
 * can't be bypassed by the symlink's target happening to be a regular file.
 * A symlink in the staging directory is inert either way by the time it
 * would reach an agent (tar, called without -h/--dereference, stores the
 * symlink itself; the agent's flat-archive extraction rejects any
 * non-regular tar entry outright before writing a byte — see
 * the Linux agent: osupdate/bundle_extract.go), but rejecting it here turns
 * a confusing "build succeeds, every install then fails" surprise into an
 * immediate, clear error at build time.
 */
export async function findSymlinks(dir: string, filenames: string[]): Promise<string[]> {
  const symlinks: string[] = [];
  for (const filename of filenames) {
    if ((await fs.promises.lstat(path.join(dir, filename))).isSymbolicLink()) symlinks.push(filename);
  }
  return symlinks;
}
