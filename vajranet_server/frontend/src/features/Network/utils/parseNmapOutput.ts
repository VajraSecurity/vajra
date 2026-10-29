export interface ParsedPort {
  port: string;
  protocol: string;
  state: string;
  service: string;
  version: string;
  details: string[];
}

export interface ParsedHost {
  ip: string;
  isUp: boolean;
  latency?: string;
  hostname?: string;
}

export interface ParsedNmapResult {
  hostUp: boolean;
  latency?: string;
  notShown?: string;
  ports: ParsedPort[];
  macAddress?: string;
  osGuess?: string[];
  cpe?: string[];
  uptime?: string;
  networkDistance?: string;
  tcpSequence?: string;
  deviceType?: string;
  running?: string;
  ipIdSequence?: string;
  scanSummary?: string;
  discoveredHosts: ParsedHost[];
  preScanScripts?: string[];
  rawOutput: string;
}

export interface ParsedSession {
  baseScan: ParsedNmapResult;
  advancedScans: { targetIp: string; result: ParsedNmapResult }[];
}

export function parseNmapOutput(raw: string): ParsedNmapResult {
  const result: ParsedNmapResult = {
    hostUp: false,
    ports: [],
    osGuess: [],
    discoveredHosts: [],
    preScanScripts: [],
    rawOutput: raw,
  };

  if (!raw) return result;

  const lines = raw.split('\n');
  let currentPort: ParsedPort | null = null;
  let inPortSection = false;
  let inPreScanSection = false;
  let currentHost: Partial<ParsedHost> | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for Pre-scan script results
    if (line.startsWith('Pre-scan script results:')) {
      inPreScanSection = true;
      continue;
    }

    if (inPreScanSection) {
      // If we hit another major heading or a blank line that isn't part of the script, we could exit.
      // But Nmap pre-scan scripts start with | or |_
      if (line.startsWith('| ') || line.startsWith('|_')) {
        result.preScanScripts!.push(line.replace(/^\|_?/, '').trim());
        continue;
      } else if (line.trim() === '' || line.startsWith('Stats:') || line.startsWith('Nmap scan report')) {
        inPreScanSection = false;
      }
    }

    // Check for Nmap scan report for <IP or Hostname>
    const reportMatch = line.match(/Nmap scan report for (.+)/);
    if (reportMatch) {
      inPreScanSection = false;
      if (currentHost && currentHost.ip) {
        result.discoveredHosts.push(currentHost as ParsedHost);
      }
      
      const target = reportMatch[1].trim();
      let ip = target;
      let hostname = undefined;
      
      // Sometimes it is "hostname (IP)"
      const bracketMatch = target.match(/(.+) \(([^)]+)\)/);
      if (bracketMatch) {
         hostname = bracketMatch[1];
         ip = bracketMatch[2];
      }
      
      currentHost = {
        ip,
        hostname,
        isUp: false,
      };
      continue;
    }
    
    // Check if host is up and get latency
    if (line.includes('Host is up')) {
      result.hostUp = true;
      const latencyMatch = line.match(/\(([^)]+ latency)\)/);
      if (latencyMatch) {
        result.latency = latencyMatch[1];
      }

      if (currentHost) {
        currentHost.isUp = true;
        if (latencyMatch) {
          currentHost.latency = latencyMatch[1];
        }
      }
      continue;
    }

    // Not shown ports
    if (line.startsWith('Not shown:')) {
      result.notShown = line;
    }

    // Identify start of port section
    if (line.startsWith('PORT') && line.includes('STATE') && line.includes('SERVICE')) {
      inPortSection = true;
      continue;
    }

    // Match port line: 80/tcp open http RapidLogic httpd 1.1
    // Format: <port>/<proto> <state> <service> <version>
    if (inPortSection && /^\d+\/[a-z]+/.test(line)) {
      if (currentPort) {
        result.ports.push(currentPort);
      }
      
      const parts = line.split(/\s+/);
      const portProto = parts[0].split('/');
      const state = parts[1];
      const service = parts[2] || '';
      const version = parts.slice(3).join(' ') || '';

      currentPort = {
        port: portProto[0],
        protocol: portProto[1] || '',
        state,
        service,
        version,
        details: []
      };
      continue;
    }

    // Match script lines associated with the port:
    // |_http-title: Login
    // | http-methods: 
    // |_  Supported Methods: GET HEAD POST
    if (inPortSection && currentPort && (line.startsWith('|_') || line.startsWith('| '))) {
      currentPort.details.push(line.replace(/^\|_?/, '').trim());
      continue;
    }

    // New Fields parsing (MAC, CPE, Uptime, etc.) can appear after port section, 
    // so we handle them outside of the continue blocks.
    
    // MAC Address
    if (line.startsWith('MAC Address:')) {
      result.macAddress = line.replace('MAC Address:', '').trim();
      inPortSection = false;
    }

    // CPE
    if (line.includes('CPE:')) {
      const cpeMatch = line.match(/CPE:\s*([^\s;]+)/g);
      if (cpeMatch) {
        if (!result.cpe) result.cpe = [];
        cpeMatch.forEach(c => result.cpe!.push(c.replace('CPE:', '').trim()));
      }
    }

    // Uptime guess
    if (line.startsWith('Uptime guess:')) {
      result.uptime = line.replace('Uptime guess:', '').trim();
      inPortSection = false;
    }

    // Network Distance
    if (line.startsWith('Network Distance:')) {
      result.networkDistance = line.replace('Network Distance:', '').trim();
      inPortSection = false;
    }

    // TCP Sequence Prediction
    if (line.startsWith('TCP Sequence Prediction:')) {
      result.tcpSequence = line.replace('TCP Sequence Prediction:', '').trim();
      inPortSection = false;
    }

    // Device Type
    if (line.startsWith('Device type:')) {
      result.deviceType = line.replace('Device type:', '').trim();
      inPortSection = false;
    }

    // Running (OS)
    if (line.startsWith('Running:')) {
      result.running = line.replace('Running:', '').trim();
      inPortSection = false;
    }

    // IP ID Sequence Generation
    if (line.startsWith('IP ID Sequence Generation:')) {
      result.ipIdSequence = line.replace('IP ID Sequence Generation:', '').trim();
      inPortSection = false;
    }


    // OS guesses
    if (line.startsWith('OS details:')) {
      result.osGuess?.push(line.replace('OS details:', '').trim());
      inPortSection = false;
    }
    
    if (line.startsWith('Aggressive OS guesses:')) {
      result.osGuess?.push(line.replace('Aggressive OS guesses:', '').trim());
      inPortSection = false;
    }
    
    // Service Info OS fallback
    if (line.startsWith('Service Info:')) {
      const osMatch = line.match(/OS:\s*([^;]+)/);
      if (osMatch) {
        if (!result.osGuess) result.osGuess = [];
        result.osGuess.push(osMatch[1].trim());
      }
      inPortSection = false;
    }

    // Hostname fallback from Target_Name
    if (line.includes('Target_Name:') || line.includes('Computer_Name:')) {
      const nameMatch = line.match(/Target_Name:\s*([^\s]+)/) || line.match(/Computer_Name:\s*([^\s]+)/);
      if (nameMatch && currentHost) {
        currentHost.hostname = nameMatch[1].trim();
      }
    }

    // Scan summary
    if (line.startsWith('Nmap done:')) {
      result.scanSummary = line;
      if (currentPort) {
        result.ports.push(currentPort);
        currentPort = null;
      }
      inPortSection = false;
      
      const upMatch = line.match(/\((\d+)\s+host[s]?\s+up\)/);
      if (upMatch && parseInt(upMatch[1], 10) > 0) {
        result.hostUp = true;
      }
    }
  }

  // push last host
  if (currentHost && currentHost.ip && !result.discoveredHosts.includes(currentHost as ParsedHost)) {
    result.discoveredHosts.push(currentHost as ParsedHost);
  }

  // push last port if needed
  if (currentPort && !result.ports.includes(currentPort)) {
    result.ports.push(currentPort);
  }

  return result;
}

export function parseSessionOutput(raw: string): ParsedSession {
  if (!raw) {
    return { baseScan: parseNmapOutput(''), advancedScans: [] };
  }

  const chunks = raw.split(/===== Advanced Scan \((.+)\) =====/);
  // chunks[0] is the base scan
  // chunks[1] is target IP 1, chunks[2] is output 1
  // chunks[3] is target IP 2, chunks[4] is output 2 ...

  const baseScanRaw = chunks[0].trim();
  const baseScan = parseNmapOutput(baseScanRaw);
  
  const advancedScans: { targetIp: string, result: ParsedNmapResult }[] = [];
  
  for (let i = 1; i < chunks.length; i += 2) {
    const targetIp = chunks[i].trim();
    const resultRaw = chunks[i+1] ? chunks[i+1].trim() : '';
    advancedScans.push({
      targetIp,
      result: parseNmapOutput(resultRaw)
    });
  }

  return { baseScan, advancedScans };
}
