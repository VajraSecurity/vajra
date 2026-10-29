/**
 * Self-contained test for utils/urlIdentity.ts's normalizeBurpTarget --
 * the pure, DB-free URL-to-grouping-key normalization backing the "Burp Suite
 * Assets" list/detail endpoints (controllers/burpsuiteAssets/).
 *
 *   node_modules/.bin/ts-node src/test/utils/urlIdentity.selftest.ts
 *
 * Imports ONLY utils/urlIdentity.ts, which has no imports of its own (see its
 * header comment) -- so this file never risks pulling in ../../index and its
 * server-bootstrap IIFE the way a controller import would.
 *
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';

import { normalizeBurpTarget } from '../../utils/urlIdentity';

function main() {
  // ==================== www.-stripping ====================

  assert.strictEqual(normalizeBurpTarget('https://www.example.com/'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('https://www.example.com'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('https://WWW.EXAMPLE.COM/'), 'example.com');

  // Not a "www." label -- must NOT be stripped.
  assert.strictEqual(normalizeBurpTarget('https://wwwexample.com/'), 'wwwexample.com');
  assert.strictEqual(normalizeBurpTarget('https://www2.example.com/'), 'www2.example.com');
  // A bare "www." host with nothing after it: stripping would produce an
  // empty string, which is not what "the www label stripped" means here.
  assert.strictEqual(normalizeBurpTarget('https://www./'), 'www.');

  // ==================== default-port omission ====================

  assert.strictEqual(normalizeBurpTarget('https://example.com:443/'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('http://example.com:80/'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('https://example.com/'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('http://example.com/'), 'example.com');

  // ==================== non-default-port retention ====================

  assert.strictEqual(normalizeBurpTarget('http://example.com:8080/'), 'example.com:8080');
  assert.strictEqual(normalizeBurpTarget('https://example.com:8443/'), 'example.com:8443');
  // Cross-scheme default ports must NOT be treated as default for the other
  // scheme: http on 443 and https on 80 are both non-default and must survive.
  assert.strictEqual(normalizeBurpTarget('http://example.com:443/'), 'example.com:443');
  assert.strictEqual(normalizeBurpTarget('https://example.com:80/'), 'example.com:80');

  // ==================== uppercase host normalization ====================

  assert.strictEqual(normalizeBurpTarget('https://EXAMPLE.com:443/'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('HTTPS://Example.Com/Login'), 'example.com');

  // ==================== path / query / fragment stripping ====================

  assert.strictEqual(normalizeBurpTarget('https://www.example.com/login?x=1'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('https://example.com/a/b/c'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('https://example.com/?a=1&b=2'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('https://example.com/#section'), 'example.com');
  assert.strictEqual(normalizeBurpTarget('https://example.com:8080/path?q=1#frag'), 'example.com:8080');
  // No trailing slash on a bare-host result, even when the input had none.
  assert.strictEqual(normalizeBurpTarget('https://example.com'), 'example.com');

  // ==================== malformed URL -> null, never throws ====================

  assert.strictEqual(normalizeBurpTarget(''), null);
  assert.strictEqual(normalizeBurpTarget('not a url'), null);
  assert.strictEqual(normalizeBurpTarget('example.com'), null); // no scheme
  assert.strictEqual(normalizeBurpTarget('   '), null);
  assert.strictEqual(normalizeBurpTarget('http://'), null);

  // ==================== two targets that are the same logical asset ====================

  // The whole point of this function: these must all normalize identically.
  const variants = [
    'https://www.example.com/login?x=1',
    'https://example.com/',
    'https://EXAMPLE.com:443/',
    'https://example.com',
    'https://www.example.com',
  ];
  const normalized = new Set(variants.map(normalizeBurpTarget));
  assert.strictEqual(normalized.size, 1, 'every same-host variant must normalize to one key');
  assert.strictEqual([...normalized][0], 'example.com');

  console.log('urlIdentity.selftest: all checks passed');
}

main();
