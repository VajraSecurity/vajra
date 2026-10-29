/**
 * Known cases where a maintained_apps catalog entry's word-boundary fuzzy
 * match (see MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL below, used by
 * windows_patch_management.ts's getAvailability and websocket/node.ts's
 * patch_job_push completion handler — both apply the same word-boundary
 * regex to guard against substring false positives, e.g. "Arc" wrongly
 * matching "Microsoft.Windows.Search") can never match the real installed
 * program name, because Windows records some Microsoft Store / OEM
 * installs under a package identifier that glues two words together with
 * no separator — e.g. Spotify's Store package shows up as
 * "SpotifyAB.SpotifyMusic", not "Spotify". The word-boundary fix has no
 * word-break at that position, so it correctly (per its own rule) declines
 * to match it — the alternative, treating an uppercase letter as an
 * implicit boundary, would make "Arc" match "ArcGIS" (a real, unrelated
 * product), reintroducing the exact class of bug the boundary fix exists
 * to prevent.
 *
 * This list closes that gap with exact literal aliases instead. Add an entry
 * only after confirming the program name against a real programs row; never
 * add a speculative Store package ID.
 */
export const KNOWN_STORE_PACKAGE_ALIASES: ReadonlyArray<{ slug: string; programName: string }> = [
  { slug: 'spotify', programName: 'SpotifyAB.SpotifyMusic' },
  { slug: 'dropbox', programName: 'C27EB4BA.DropboxOEM' },
];

/**
 * SQL VALUES fragment for KNOWN_STORE_PACKAGE_ALIASES, for inlining (not
 * parameter-binding) into MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL below.
 * Safe to inline as string-built SQL: every value comes from the hardcoded
 * literal array above, never from user input or a DB read — single quotes
 * are still doubled defensively in case a future alias needs one.
 *
 * Empty when KNOWN_STORE_PACKAGE_ALIASES is empty — do not use this
 * directly in a `VALUES (...)` clause without checking
 * KNOWN_STORE_PACKAGE_ALIASES.length first; `VALUES ()` with zero rows is
 * a Postgres syntax error, not an empty result set. Use
 * MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL below instead, which already
 * guards against that.
 */
export const KNOWN_STORE_PACKAGE_ALIASES_SQL_VALUES = KNOWN_STORE_PACKAGE_ALIASES.map(
  (a) => `('${a.slug.replace(/'/g, "''")}', '${a.programName.replace(/'/g, "''")}')`,
).join(', ');

/**
 * The full maintained_apps match condition, shared verbatim by
 * getAvailability (windows_patch_management.ts) and the post-install
 * programs.version UPDATE (websocket/node.ts) — inline this directly
 * inside their `JOIN maintained_apps ma ON <base condition> AND (
 * ${MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL} )`. Exported as one constant
 * rather than copy-pasted so the read and write paths cannot drift apart.
 *
 * Three ways an installed program name can match a catalog row:
 *  1. fuzzy_match_name=true: a word-boundary match — the matched
 *     substring must be preceded by start-of-string or a non-alphanumeric
 *     char, and followed by end-of-string or a non-alphanumeric char. NOT
 *     a bare substring ILIKE: '%Arc%' matches any name that merely
 *     *contains* "arc", e.g. "Microsoft.Windows.Search" (Se-ARC-h).
 *     display_name_match is regex-escaped first since several catalog
 *     entries contain regex metacharacters verbatim (e.g. "4K Video
 *     Downloader+", "Adobe Acrobat DC (64-bit)"). Deliberately not Postgres's
 *     built-in ARE word-boundary escapes (m-boundary/M-boundary): those require
 *     the matched boundary character itself to be a word character, which
 *     breaks entries ending in punctuation like "(64-bit)" or "Downloader+";
 *     checking the character just outside the match works regardless of the
 *     pattern's own edge characters.
 *  2. fuzzy_match_name=false: an exact (case-insensitive) match.
 *  3. An exact alias from KNOWN_STORE_PACKAGE_ALIASES above,
 *     for the handful of Store/OEM package names (1) can never reach.
 *     Both sides of the slug comparison are lower-cased defensively —
 *     maintained_apps.slug is lowercase by convention, not by DB
 *     constraint, so this doesn't rely on that convention holding.
 *     Omitted entirely (not emitted as `OR EXISTS (VALUES ())`) when
 *     KNOWN_STORE_PACKAGE_ALIASES is empty, since a zero-row VALUES list
 *     is a Postgres syntax error, not an empty result set — clause 3
 *     disappearing from the OR-chain is safe, an empty VALUES () is not.
 */
export const MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL = [
  // The strpos() test in front of the regex is a cost guard, not an extra
  // filter. For an ASCII pattern it is a necessary condition for the regex
  // beside it, so ANDing it in cannot change which pairs match, only how many
  // regexes get compiled: display_name_match is regex-escaped below so the
  // pattern's middle matches it literally, and for ASCII `~*` folds each
  // character c to exactly {lower(c), upper(c)} — which is what
  // strpos(LOWER(..), LOWER(..)) > 0 tests.
  //
  // That implication fails for a non-ASCII pattern, where `~*` also accepts c
  // itself: wherever lower(upper(c)) <> lower(c), the regex matches a character
  // strpos() rejects and the guard would silently drop a real match. Examples
  // are 'ς' U+03C2 vs 'Σ', 'µ' U+00B5 vs 'Μ', 'ſ' U+017F vs 'S', 'ı' U+0131 vs
  // 'I'; 'µTorrent' is a real product name, so this is not hypothetical.
  //
  // Hence the ASCII precondition: octet_length = length holds in UTF-8 exactly
  // when every character is single-byte, and a non-ASCII pattern skips the
  // guard and evaluates the regex unchanged. Do not drop that precondition on
  // the grounds that today's catalog is all ASCII — nothing enforces it.
  //
  // The guard is worth having because this clause drives a nested loop of
  // (distinct installed program names on the host) x (active catalog rows), and
  // `~*` over a runtime-built pattern can be neither indexed nor cached, so
  // Postgres compiles a fresh regex for every pair.
  `(ma.fuzzy_match_name
               AND (octet_length(ma.display_name_match) <> length(ma.display_name_match)
                    OR strpos(LOWER(lp.name), LOWER(ma.display_name_match)) > 0)
               AND lp.name ~* (
                 '(^|[^[:alnum:]])' ||
                 regexp_replace(ma.display_name_match, '([.^$*+?()\\[\\]{}|\\\\])', '\\\\\\1', 'g') ||
                 '($|[^[:alnum:]])'
               ))`,
  `(NOT ma.fuzzy_match_name AND LOWER(lp.name) = LOWER(ma.display_name_match))`,
  KNOWN_STORE_PACKAGE_ALIASES.length
    ? `EXISTS (
                 SELECT 1 FROM (VALUES ${KNOWN_STORE_PACKAGE_ALIASES_SQL_VALUES}) AS ka(alias_slug, alias_name)
                 WHERE LOWER(ka.alias_slug) = LOWER(ma.slug) AND LOWER(ka.alias_name) = LOWER(lp.name)
               )`
    : null,
]
  .filter((clause): clause is string => clause !== null)
  .join('\n               OR ');
