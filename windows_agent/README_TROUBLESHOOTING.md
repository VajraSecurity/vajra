# Vajra EDR Client - Windows Installation Troubleshooting Guide

This document provides detailed information about all possible errors during Vajra EDR client installation and their resolutions.

---

## Table of Contents

1. [Administrative Privilege Errors](#1-administrative-privilege-errors)
2. [Windows Version Errors](#2-windows-version-errors)
3. [Lock File Errors](#3-lock-file-errors)
4. [Service Already Running Errors](#4-service-already-running-errors)
5. [Directory Creation Errors](#5-directory-creation-errors)
6. [File Copy Errors](#6-file-copy-errors)
7. [Service Creation Errors](#7-service-creation-errors)
8. [Service Start Errors](#8-service-start-errors)
9. [Understanding the Debug Output](#9-understanding-the-debug-output)
10. [Log File Analysis](#10-log-file-analysis)

---

## 1. Administrative Privilege Errors

The installer uses 4 different methods to verify administrative privileges. If all methods fail, you'll see:

```
================================================================================
 ERROR: ADMINISTRATIVE PRIVILEGES REQUIRED
================================================================================

 DEBUG INFORMATION - All 4 verification methods failed:
   Method 1 (Admin Group + Elevation): FAILED
     - Is Admin Member: false
     - Is Elevated:     false
   Method 2 (Filter Manager):          FAILED
   Method 3 (System32 Write):          FAILED
   Method 4 (Net Session):             FAILED
```

### Method 1: Admin Group Membership + Elevation Check

This method performs **two checks** to give detailed diagnostics:

#### Step 1a: Admin Group Membership (S-1-5-32-544)

| Aspect | Details |
|--------|---------|
| **What it checks** | User is member of BUILTIN\Administrators group |
| **Command** | `whoami /groups \| find "S-1-5-32-544"` |
| **SID Meaning** | S-1-5-32-544 = BUILTIN\Administrators |

#### Step 1b: Elevation Status (S-1-16-12288)

| Aspect | Details |
|--------|---------|
| **What it checks** | Process is running with High Mandatory Level (elevated) |
| **Command** | `whoami /groups \| find "S-1-16-12288"` |
| **SID Meaning** | S-1-16-12288 = High Mandatory Level (Elevated) |

#### Understanding the Results

| Is Admin Member | Is Elevated | Result | Meaning |
|-----------------|-------------|--------|---------|
| true | true | **SUCCESS** | User is admin AND process is elevated |
| true | false | **PARTIAL** | User is admin but process NOT elevated |
| false | - | **FAILED** | User is not an administrator |

#### Common Scenarios

**Scenario 1: PARTIAL (Admin but not elevated)**
```
DIAGNOSIS: You ARE an administrator but the process is NOT elevated!
SOLUTION:  Right-click the script and select "Run as administrator"
```
This happens when you double-click the script instead of "Run as administrator".

**Scenario 2: FAILED (Not an admin)**
```
DIAGNOSIS: Your account is NOT a member of the Administrators group.
SOLUTION:  Log in with an administrator account or contact IT.
```
Your user account doesn't have admin rights on this machine.

**Resolution:**
- Right-click the script and select "Run as administrator"
- If using Remote Desktop, ensure you're connected with admin credentials
- Domain Admins may not automatically have local admin rights - check with IT

### Method 2: Filter Manager (fltmc)

| Aspect | Details |
|--------|---------|
| **What it checks** | Access to Windows Filter Manager |
| **Command** | `fltmc` |
| **Why it fails** | Insufficient privileges or Filter Manager service disabled |

**Resolution:**
- Ensure the script is run as administrator
- Check if `fltMgr` service is running:
  ```cmd
  sc query fltMgr
  ```

### Method 3: System32 Write Test

| Aspect | Details |
|--------|---------|
| **What it checks** | Write access to `%SystemRoot%\System32` |
| **Command** | Creates and deletes a temporary file |
| **Why it fails** | Write protection on system directories, antivirus blocking |

**Resolution:**
- Temporarily disable real-time antivirus protection
- Check if Windows Defender Application Control (WDAC) is blocking writes
- Verify no third-party security software is blocking access

### Method 4: Net Session (Legacy)

| Aspect | Details |
|--------|---------|
| **What it checks** | Access to network session information |
| **Command** | `net session` |
| **Why it fails** | **LanmanServer service is disabled or stopped** |

**This is the most common cause of failures on Windows 11!**

**Resolution:**
1. Check LanmanServer service status:
   ```cmd
   sc query LanmanServer
   ```

2. If stopped/disabled, start it:
   ```cmd
   sc config LanmanServer start= auto
   sc start LanmanServer
   ```

3. If this is a security policy, the other 3 methods should work. If all fail, contact IT.

### Complete Admin Check Failure - What To Do

If all 4 methods fail even when running as administrator:

1. **Open elevated Command Prompt manually:**
   - Press `Win + X`
   - Select "Terminal (Admin)" or "Command Prompt (Admin)"
   - Navigate to script location and run it

2. **Check UAC settings:**
   ```cmd
   reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
   ```
   - Value should be `0x1` (enabled)

3. **Check Group Policy restrictions:**
   - Run `gpedit.msc`
   - Navigate to: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
   - Check "User Account Control" policies

4. **Verify account privileges:**
   ```cmd
   whoami /groups
   ```
   - Look for `BUILTIN\Administrators` in the output
   - Look for `Mandatory Label\High Mandatory Level`

---

## 2. Windows Version Errors

```
[-] Vajra EDR client does not support current Windows version.
[-] Vajra EDR client currently supports Windows 7, Windows 8, Windows 8.1, Windows 10 and Windows 11.
[-] Detected: Windows Unknown (Build: 0)
```

### Cause

The installer couldn't detect your Windows version from either:
- Registry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
- `ver` command output

### Debug Information

The log file will show:
```
[DEBUG] Registry Build Number: <value>
[DEBUG] Registry Major Version: <value>
[DEBUG] Product Name: <value>
```

### Resolution

1. **Verify Windows version manually:**
   ```cmd
   ver
   winver
   ```

2. **Check registry values:**
   ```cmd
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentMajorVersionNumber
   ```

3. **If values are missing:** Your Windows installation may be corrupted. Run:
   ```cmd
   sfc /scannow
   DISM /Online /Cleanup-Image /RestoreHealth
   ```

### Supported Versions

| Windows Version | Build Range | Status |
|-----------------|-------------|--------|
| Windows 7 | 6.1.x | Supported |
| Windows 8 | 6.2.x | Supported |
| Windows 8.1 | 6.3.x | Supported |
| Windows 10 | 10.0.x (< 22000) | Supported |
| Windows 11 | 10.0.x (>= 22000) | Supported |
| Windows Server | Varies | Check compatibility |

---

## 3. Lock File Errors

```
[-] Installation is already in progress. Please wait... install.lock
```

### Cause

A previous installation attempt didn't complete and left a lock file.

### Resolution

1. **Delete the lock file:**
   ```cmd
   del "<script_directory>\install.lock"
   ```

2. **Or simply re-run the script** - it automatically cleans up stale lock files on startup.

---

## 4. Service Already Running Errors

```
[-] ERROR: The Vajra EDR service is already running. Exiting...
```

### Debug Output

```
[DEBUG] Service query result (errorlevel=0):
SERVICE_NAME: vajra
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
```

### Cause

Vajra EDR is already installed and running on this system.

### Resolution

1. **If upgrading:** First uninstall the existing version:
   ```cmd
   sc stop vajra
   sc delete vajra
   rmdir /s /q "%ProgramFiles%\osquery"
   ```

2. **If reinstalling:** Use the uninstaller or run cleanup manually:
   ```cmd
   sc stop vajra
   sc delete vajra
   ```

3. **Verify service is removed:**
   ```cmd
   sc query vajra
   ```
   Should return: `The specified service does not exist as an installed service.`

---

## 5. Directory Creation Errors

```
[DEBUG] FAILED to create: C:\Program Files\osquery
[DEBUG] FAILED to create: C:\Program Files\osquery\osqueryd
```

### Cause

- Insufficient permissions to write to Program Files
- Directory already exists with restrictive permissions
- Disk full
- Antivirus blocking

### Resolution

1. **Check disk space:**
   ```cmd
   wmic logicaldisk get size,freespace,caption
   ```

2. **Check existing directory permissions:**
   ```cmd
   icacls "%ProgramFiles%\osquery"
   ```

3. **Remove existing directory:**
   ```cmd
   rmdir /s /q "%ProgramFiles%\osquery"
   ```

4. **Temporarily disable antivirus** and retry.

---

## 6. File Copy Errors

### Missing Source File

```
[DEBUG] ERROR: Source file not found: C:\path\to\installer\x64\osqueryd.exe
```

**Cause:** Installation package is incomplete or corrupted.

**Resolution:**
- Re-download the installation package
- Verify all files exist in the `x64\` subfolder:
  - `osqueryd.exe`
  - `osquery.flags`
  - `plgx_win_extension.ext.exe`
  - `websocket_extension.ext.exe`
  - `osquery.man`
  - `extensions.load`
- Verify `common\` folder contains:
  - `enrollment_secret.txt`
  - `cert.pem`
  - `extension.conf`

### Missing Certificate or Enrollment Secret

```
[-] ERROR: the certificate and enrollment secret are missing.
```

**Cause:** `common\cert.pem` or `common\enrollment_secret.txt` is not in the package. They are not
stored in the repository because they belong to your Vajra server.

**Resolution:**
- Use the `windows_agent.zip` downloaded from the Vajra web console, which includes both files, or
- Copy your Vajra C++ server's CA certificate (`ssl/myCA.pem`) to `common\cert.pem` and its
  enrollment secret to `common\enrollment_secret.txt`, then run the installer again.

### Copy Failed

```
[DEBUG] FAILED: osqueryd.exe copy failed (errorlevel=1)
```

| Error Level | Meaning | Resolution |
|-------------|---------|------------|
| 1 | General failure | Check source file exists, destination writable |
| 2 | User cancelled | N/A |
| 4 | Initialization error | Check disk, memory |
| 5 | Disk write error | Check disk space, permissions |

**Resolution:**
1. Ensure destination directory exists
2. Check disk space
3. Verify no file locks (close applications using the files)
4. Disable antivirus temporarily

---

## 7. Service Creation Errors

```
[-] FAILED to create Vajra EDR service! (errorlevel=XXXX)
```

### Error Codes

| Error Code | Name | Description | Resolution |
|------------|------|-------------|------------|
| **5** | ERROR_ACCESS_DENIED | Insufficient privileges | Run as administrator |
| **1072** | ERROR_SERVICE_MARKED_FOR_DELETE | Service is being deleted | Wait and retry, or reboot |
| **1073** | ERROR_SERVICE_EXISTS | Service already exists | Delete existing service first |
| **1078** | ERROR_DUPLICATE_SERVICE_NAME | Duplicate service name | Check for conflicting services |

### Error 5: Access Denied

```
[DEBUG] Error 5: Access denied - insufficient privileges
```

**Cause:** Not running with administrator privileges even though admin check passed.

**Resolution:**
1. Verify you're running as Local Administrator (not just Domain Admin)
2. Check if Group Policy restricts service creation
3. Try running from SYSTEM account:
   ```cmd
   psexec -s cmd.exe
   ```

### Error 1073: Service Already Exists

```
[DEBUG] Error 1073: Service already exists
```

**Resolution:**
```cmd
sc stop vajra
sc delete vajra
:: Wait a few seconds
sc query vajra  :: Should show "does not exist"
:: Re-run installer
```

---

## 8. Service Start Errors

```
[-] WARNING: Service start returned errorlevel=XXXX
```

### Error Codes

| Error Code | Name | Description | Resolution |
|------------|------|-------------|------------|
| **2** | ERROR_FILE_NOT_FOUND | Executable not found | Verify osqueryd.exe copied correctly |
| **3** | ERROR_PATH_NOT_FOUND | Path doesn't exist | Check installation directory |
| **5** | ERROR_ACCESS_DENIED | Insufficient privileges | Check service account permissions |
| **1053** | ERROR_SERVICE_REQUEST_TIMEOUT | Service didn't start in time | Check osquery logs, increase timeout |
| **1056** | ERROR_SERVICE_ALREADY_RUNNING | Service already running | OK - service is running |
| **1067** | ERROR_PROCESS_ABORTED | Process terminated unexpectedly | Check osquery logs for crash |
| **1068** | ERROR_DEPENDENCY_SERVICE_FAILED | Dependency failed | Check dependent services |
| **1069** | ERROR_SERVICE_LOGON_FAILED | Logon failure | Check service account credentials |

### Error 1053: Service Request Timeout

```
[DEBUG] Error 1053: Service did not respond in time
```

**Cause:** osqueryd.exe is taking too long to initialize.

**Resolution:**
1. Check osquery log file:
   ```
   %ProgramFiles%\osquery\log\osqueryd.results.log
   %ProgramFiles%\osquery\log\osqueryd.INFO
   ```

2. Verify flags file is valid:
   ```cmd
   type "%ProgramFiles%\osquery\osquery.flags"
   ```

3. Try starting manually with verbose logging:
   ```cmd
   "%ProgramFiles%\osquery\osqueryd\osqueryd.exe" --flagfile="%ProgramFiles%\osquery\osquery.flags" --verbose
   ```

### Error 1067: Process Terminated Unexpectedly

```
[DEBUG] Error 1067: Process terminated unexpectedly
```

**Cause:** osqueryd.exe crashed during startup.

**Resolution:**
1. Check Windows Event Viewer:
   - Application Log
   - System Log

2. Check for crash dumps:
   ```
   %LocalAppData%\CrashDumps
   ```

3. Common causes:
   - Missing Visual C++ Redistributable
   - Corrupted executable
   - Invalid configuration

4. Install Visual C++ Redistributable:
   - Download from Microsoft
   - Install the x64 version

### Error 1069: Service Logon Failed

```
[DEBUG] Error 1069: Service logon failure
```

**Cause:** The service account doesn't have "Log on as a service" right.

**Resolution:**
1. Open Local Security Policy (`secpol.msc`)
2. Navigate to: Local Policies > User Rights Assignment
3. Find "Log on as a service"
4. Add the service account (usually `LOCAL SYSTEM`)

---

## 9. Understanding the Debug Output

The installer outputs debug information in this format:

```
[+] SUCCESS messages     - Operation completed successfully
[-] ERROR messages       - Operation failed
[DEBUG] Debug info       - Detailed diagnostic information
```

### Console Output Example

```
[+] Verifying administrative privileges...
    [DEBUG] Method 1: Checking Token Integrity Level...
    [DEBUG] Method 1: FAILED - High Mandatory Level NOT found (errorlevel=1)
    [DEBUG] Method 2: Checking Filter Manager (fltmc)...
    [DEBUG] Method 2: SUCCESS - Filter Manager accessible
[+] SUCCESS: Administrative privileges verified [Method: Filter Manager]
```

This shows:
- Method 1 failed (errorlevel=1)
- Method 2 succeeded
- Admin verification passed using Method 2

---

## 10. Log File Analysis

### Log File Location

```
<script_directory>\vajra_install_log.txt
```

### Log File Structure

```
================================================================================
VAJRA EDR CLIENT INSTALLATION LOG
================================================================================
Timestamp: Wed 01/15/2025 10:30:45.00
Script Version: 1.0.0.3
Username: Administrator
Computer Name: WORKSTATION-01
User Domain: CONTOSO
Script Path: C:\Installers\vajra_install.bat
Working Directory: C:\Installers
================================================================================

[Wed 01/15/2025 10:30:45.00] [INFO] Installation started - Version 1.0.0.3
[Wed 01/15/2025 10:30:45.00] [DEBUG] Method 1: Checking Token Integrity Level
...
```

### Log Levels

| Level | Meaning |
|-------|---------|
| `DEBUG` | Detailed diagnostic information |
| `INFO` | General progress information |
| `SUCCESS` | Operation completed successfully |
| `WARNING` | Non-critical issue encountered |
| `ERROR` | Critical failure |

### Key Sections to Check

1. **Admin Check Summary:**
   ```
   ---- ADMIN CHECK SUMMARY ----
   Method 1 (Admin Group + Elevation): SUCCESS
     - Is Admin Member (S-1-5-32-544): true
     - Is Elevated (S-1-16-12288):     true
   Method 2 (Filter Manager):          FAILED
   Method 3 (System32 Write):          FAILED
   Method 4 (Net Session):             FAILED
   Final Result: adminVerified=true, adminMethod=Admin Group + Elevated Token
   ```

2. **LanmanServer Status** (if Method 4 fails):
   ```
   [LanmanServer Service Status]:
   SERVICE_NAME: LanmanServer
           STATE              : 1  STOPPED
   ```

3. **File Copy Results:**
   ```
   [SUCCESS] Copied: osqueryd.exe
   [ERROR] Source file not found: C:\path\to\file
   ```

4. **Service Operations:**
   ```
   [SUCCESS] Service created successfully
   [WARNING] Service start returned errorlevel=1053
   ```

---

## Quick Reference: Common Issues

| Symptom | Likely Cause | Quick Fix |
|---------|--------------|-----------|
| All 4 admin methods fail | Not running elevated | Right-click > Run as administrator |
| Method 1 shows PARTIAL | Admin but not elevated | Right-click > Run as administrator |
| isAdminMember=false | Not in Administrators group | Use admin account or contact IT |
| Method 4 fails, others pass | LanmanServer disabled | Ignore - other methods worked |
| All methods fail on Win11 | Strict security policies | Use elevated CMD manually |
| Service creation error 1073 | Service exists | `sc delete vajra` first |
| Service start error 1067 | Missing VC++ Runtime | Install VC++ Redistributable |
| File copy fails | Antivirus blocking | Temporarily disable AV |
| Unknown Windows version | Registry corruption | Run `sfc /scannow` |

---

## SID Reference

| SID | Name | Meaning |
|-----|------|---------|
| S-1-5-32-544 | BUILTIN\Administrators | User is member of local Administrators group |
| S-1-16-12288 | High Mandatory Level | Process is running elevated (admin mode) |
| S-1-16-8192 | Medium Mandatory Level | Process is running non-elevated (normal mode) |

---

## Contact Support

If issues persist after following this guide:

1. **Collect the log file:** `vajra_install_log.txt`
2. **Run diagnostic commands:**
   ```cmd
   systeminfo > systeminfo.txt
   whoami /all > whoami.txt
   sc query vajra > service_status.txt
   ```
3. **Contact:** your Vajra administrator or the project's issue tracker

---

*Document Version: 1.0.0.4*
*Last Updated: January 2025 (to be reviewed for the open-source release)*
