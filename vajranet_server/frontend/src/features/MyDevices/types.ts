export type SecurityProductChange = {
  name: string;
  from: string;
  to: string;
};

/** A single security-product entry as reported by the backend (Windows Defender, Firewall, etc.). */
export interface SecurityProduct {
  name: string;
  state: string;
}

/** A device group, as returned by GET /groups. */
export interface DeviceGroup {
  groupId: string;
  name: string;
}

/** A single network interface entry, as returned by the node IP-list endpoint. */
export interface DeviceNetworkInterface {
  type?: string;
  priority?: number;
  address?: string;
  mask?: string;
  friendly_name?: string;
  interface?: string;
}

/** A single saved WiFi profile entry within a device's WiFi snapshot. */
export interface WifiSavedProfile {
  uuid?: string;
  ssid?: string;
  security?: string;
  security_detail?: string;
  security_risk?: string;
  auto_connect?: boolean;
}

/** Latest WiFi snapshot for a device, as returned by the WiFi-latest endpoint. */
export interface WifiSnapshot {
  is_connected?: boolean;
  connected_ssid?: string | null;
  connected_bssid?: string | null;
  connected_signal?: number | string | null;
  connected_frequency?: string | null;
  connected_channel?: string | number | null;
  connected_bitrate?: string | null;
  connected_security?: string | null;
  connected_ip?: string | null;
  recorded_at?: string | number | null;
  saved_profiles?: WifiSavedProfile[] | string;
}

/** Raw node payload as returned by the /nodes list endpoint, before display-mapping. */
export interface RawNode {
  /** Always used as a string throughout MyDevices (Set<string> selection, string-keyed lookups, etc.). */
  id: string;
  host_identifier: string;
  hostname?: string;
  os_name?: string;
  os_platform?: string;
  address?: string;
  osquery_version?: string;
  last_seen?: string | number;
  enrolled_on?: string | number;
  agent_online?: boolean;
  status?: string;
  critical?: boolean;
  isolated?: boolean;
  group_ids?: string[];
  security_products?: SecurityProduct[];
}

/**
 * Display-ready device — the raw node plus the derived fields computed by
 * the `nodesData` memo in `MyDevices/index.tsx`. Shared by the orchestrator
 * and all presentational components (table row, mobile card, actions menu)
 * since they all render the same mapped shape.
 */
export interface Device extends RawNode {
  name: string;
  os: string;
  type: string;
  ip: string;
  agent: string;
  lastSeen: string;
  enrolledDate: string;
  groupNames: string;
  groupIds: string[];
  hygieneScore: number;
  displayStatus: 'Online' | 'Active' | 'Offline';
  mac: string;
  firewallStatus: string;
  antivirusStatus: string;
  diskEncryption: string;
  patchStatus: string;
  vulnerabilities: number;
  applications: number;
}
