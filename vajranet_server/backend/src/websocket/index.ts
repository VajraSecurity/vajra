/**
 * WebSocket module: node (UI + extension) and live dashboard.
 * Mount these handlers with your WebSocket server (e.g. express-ws or ws).
 */

export {
  nodeUi,
  nodeExt,
  ridCleanupInterval,
  jobDrainInterval,
  dispatchToAgent,
  isHostConnected,
  getConnectedHostIdentifiers,
} from './node';
export type { WsLike, ReqLike } from './node';
export { liveWeb, startLiveWeb, stopLiveWeb } from './liveWeb';
export type { LiveWebWsLike } from './liveWeb';
export { ValidateMessage, ValidateExtResponse, generateUniqueID, isEqual, isNodeStatusEqual } from './utils';
export type { ParsedWebSocketMessage, ExtensionResponse } from './utils';
export type {
  NodeStatus,
  AlertStatus,
  LiveData,
  WebSocRevMessage,
  Job,
} from './types';
