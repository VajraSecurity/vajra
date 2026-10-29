/**
 * Asset identity resolution: the pure normalizer and the weighted matcher.
 *
 * Feeders (backend/src/services/assetIdentity/) and the OpenVAS report handler
 * import from here rather than reaching into the individual modules.
 *
 * `normalize.ts` is deliberately DB-free and can be imported on its own by
 * anything that only needs to canonicalize a value (an nmap block parser, an
 * OpenVAS best_os_txt mapper) without pulling in typeorm or the logger.
 */

export {
  normalizeBiosUuid,
  normalizeHostname,
  normalizeIp,
  normalizeMac,
  normalizeObservation,
  normalizeOsFamily,
} from './normalize';

export {
  capMatchReason,
  resolveAsset,
  resolveAssets,
  resolveAssetWithQuerier,
  type AssetIdentityQuerier,
} from './resolveAsset';
