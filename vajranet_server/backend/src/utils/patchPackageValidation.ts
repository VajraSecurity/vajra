/**
 * Pure, dependency-free validation for the per-package upgrade request shape
 * (mode:'packages' on POST /api/patch/apply). Deliberately has NO import of
 * express/TypeORM/../../index or anything else that would transitively pull
 * in server bootstrap — same rationale as patchBundle.ts's header comment:
 * this module needs to be safely importable by a standalone selftest script
 * (patchPackageValidation.selftest.ts) via plain ts-node, without booting
 * the real server or attempting a DB connection.
 *
 * controllers/nodes/patch_management.ts imports these directly rather than
 * redefining them, so there is exactly one source of truth for the shape
 * this backend accepts.
 */

// Mirrors the Linux agent: osupdate/upgrade_packages.go's maxPackages
// exactly — both sides cap independently so a compromised/buggy backend
// can't hand the agent an unbounded argv either.
export const MAX_PACKAGES_PER_HOST = 500;

// Mirrors the Linux agent: osupdate/upgrade_packages.go's packageNameRe
// exactly — kept in sync deliberately, since this is the first, defense-in-
// depth validation layer in front of the agent's own allowlist gate, not a
// replacement for it (the agent re-validates independently, see that file).
export const PACKAGE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9.+_:-]{0,127}$/;

// Only apt/dnf/yum have clean single-package upgrade semantics today —
// zypper's native op is patch-based (not package-based), pacman/apk are
// excluded pending real fleet demand. Matches
// the Linux agent: osupdate/upgrade_packages.go's packageCapableManagers.
export const PACKAGE_CAPABLE_MANAGERS = new Set(['apt', 'dnf', 'yum']);

/**
 * Shape-validates the per-host package selection for mode==='packages':
 * every host in `hosts` must have a non-empty, capped, PACKAGE_NAME_RE-clean
 * list. This only checks shape — applyPatchUpgrade additionally checks each
 * name is actually one of that host's currently-known available updates
 * (patch_available_updates) before dispatching, since a host being present
 * here doesn't prove the agent ever offered these exact packages.
 */
export function validatePackagesByHost(hosts: string[], input: unknown): Record<string, string[]> | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const map = input as Record<string, unknown>;
  const result: Record<string, string[]> = {};
  for (const host of hosts) {
    const list = map[host];
    if (!Array.isArray(list) || list.length === 0 || list.length > MAX_PACKAGES_PER_HOST) return null;
    const names = list.map((p) => (typeof p === 'string' ? p : ''));
    if (names.some((n) => !PACKAGE_NAME_RE.test(n))) return null;
    result[host] = [...new Set(names)];
  }
  return result;
}
