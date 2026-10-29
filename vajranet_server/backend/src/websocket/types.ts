export interface NodeStatus{
    online: number,
    offline: number,
    total: number,
    onlineNodeHostIdentifier:Array<string>
    agentOnline:Array<string>
  }
  
  export interface AlertStatus{
    new:number
  }
  
  export interface LiveData{
    nodeStatus:NodeStatus
    alertStatus:AlertStatus
  }
  
  interface WebSocRevMessageParams{
    agent?        :  'port' | 'ip' | 'networkManager' | 'status' | 'driver' | 'powershell' | 'message' | 'removableDevice' | 'wifi' | 'bluetooth' | 'clamav' | 'packages' | 'osupdate' | 'patchManagement',
    action?       :  'allow' | 'block' | 'terminate' | 'unblock' | 'terminate-tree' | 'run' | 'message' | 'enable' | 'disable'
                     // clamav agent actions (Linux)
                     | 'ping' | 'scan' | 'contscan' | 'stats' | 'reload' | 'version'
                     // packages agent actions (Linux)
                     | 'list'
                     // osupdate agent actions (Linux patch management)
                     | 'check' | 'upgrade' | 'upgrade_packages'
                     // patchManagement agent actions (Windows maintained-app install/uninstall)
                     | 'install' | 'uninstall',
    arg1?         :  string,
    arg2?         :  string,
    /** Powershell command key(s) — used by powershell agent to select a predefined script (e.g. bluetooth enable/disable). Also reused, unchanged wire shape, as the validated package-name list for osupdate's "upgrade_packages" action. */
    command_keys? :  string[],
  }
  export interface WebSocRevMessage{
    type            : 'agent' | 'osquery', 
    params?          : WebSocRevMessageParams, 
    /** @deprecated No longer used - authentication now uses cookies. Field kept for backward compatibility. */
    token?          : string | null, 
    host_identifier : string
  }
  
  export interface Job{
    hostIdentifier  : string,
    online          : boolean
  }