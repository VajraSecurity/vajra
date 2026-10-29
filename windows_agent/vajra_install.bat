@echo off
setlocal enabledelayedexpansion

REM Vajra EDR client installer script

set scriptVersion=1.0.1.2
set "bits32=false"
set "LogFile=%~dp0vajra_install_log.txt"
set "LockFile=%~dp0install.lock"
set "DEBUG=true"
set kServiceName=vajra
set kServiceDescription=Vajra EDR client service
set kServiceDisplayName=vajra
set kServiceBinaryPath="%ProgramFiles%\osquery\osqueryd\osqueryd.exe"
set welManifestPath="%ProgramFiles%\osquery\osquery.man"
set startupArgs=--flagfile="%ProgramFiles%\osquery\osquery.flags"

REM Initialize log file with header
if exist "%LogFile%" del "%LogFile%"
if exist "%LockFile%" del "%LockFile%"

echo ================================================================================ >> "%LogFile%"
echo VAJRA EDR CLIENT INSTALLATION LOG >> "%LogFile%"
echo ================================================================================ >> "%LogFile%"
echo Timestamp: %DATE% %TIME% >> "%LogFile%"
echo Script Version: %scriptVersion% >> "%LogFile%"
echo Username: %USERNAME% >> "%LogFile%"
echo Computer Name: %COMPUTERNAME% >> "%LogFile%"
echo User Domain: %USERDOMAIN% >> "%LogFile%"
echo Script Path: %~f0 >> "%LogFile%"
echo Working Directory: %CD% >> "%LogFile%"
echo ================================================================================ >> "%LogFile%"
echo. >> "%LogFile%"

echo [+] Installing Vajra EDR client version %scriptVersion% on your system.
echo [%DATE% %TIME%] [INFO] Installation started - Version %scriptVersion% >> "%LogFile%"

@REM ------------------------------------- Part 1 : Testing the system compatibility -------------------------------------

REM Check if lock file exists
if exist "%LockFile%" (
    echo [-] Installation is already in progress. Please wait... %LockFile%
    echo [%DATE% %TIME%] [ERROR] Lock file exists >> "%LogFile%"
    pause
    exit /b
)

REM Create the lock file
type nul > "%LockFile%"
echo [%DATE% %TIME%] [INFO] Lock file created >> "%LogFile%"

@REM ================================================================================
@REM ADMIN PRIVILEGES CHECK - Simplified and robust
@REM ================================================================================
echo.
echo [+] Verifying administrative privileges...
echo [%DATE% %TIME%] [INFO] Starting administrative privileges verification >> "%LogFile%"

set "adminVerified=false"
set "adminMethod=None"
set "isAdminMember=false"
set "isElevated=false"
set "method1Result=SKIPPED"
set "method2Result=SKIPPED"
set "method3Result=SKIPPED"
set "method4Result=SKIPPED"

REM ---- Method 1: Check elevation via High Mandatory Level ----
echo     [DEBUG] Method 1: Checking elevation status...
echo [%DATE% %TIME%] [DEBUG] Method 1: Checking elevation status >> "%LogFile%"

REM Capture whoami output for debugging
whoami /groups > "%TEMP%\vajra_whoami.txt" 2>&1
echo     [WHOAMI /GROUPS Output]: >> "%LogFile%"
type "%TEMP%\vajra_whoami.txt" >> "%LogFile%"

REM Check for High Mandatory Level (elevated) - use goto OUTSIDE if block
findstr /C:"S-1-16-12288" "%TEMP%\vajra_whoami.txt" >nul 2>&1
if %errorlevel% neq 0 goto :Method1CheckAdmin
set "isElevated=true"
set "adminVerified=true"
set "adminMethod=Elevated Process Token"
set "method1Result=SUCCESS"
echo     [DEBUG] Method 1: SUCCESS - Process is elevated ^(S-1-16-12288 found^)
echo [%DATE% %TIME%] [SUCCESS] Method 1 PASSED - Process is elevated >> "%LogFile%"
del "%TEMP%\vajra_whoami.txt" >nul 2>&1
goto :AdminCheckComplete

:Method1CheckAdmin
set "method1Result=FAILED"
REM Check for admin group membership
findstr /C:"S-1-5-32-544" "%TEMP%\vajra_whoami.txt" >nul 2>&1
if %errorlevel% neq 0 goto :Method1NotAdmin
set "isAdminMember=true"
echo     [DEBUG] User IS member of Administrators group but NOT elevated
echo [%DATE% %TIME%] [WARNING] Method 1 FAILED - Admin but not elevated >> "%LogFile%"
goto :Method1Done

:Method1NotAdmin
echo     [DEBUG] User is NOT member of Administrators group
echo [%DATE% %TIME%] [DEBUG] Method 1 FAILED - Not an administrator >> "%LogFile%"

:Method1Done
del "%TEMP%\vajra_whoami.txt" >nul 2>&1

REM ---- Method 2: Filter Manager (fltmc) ----
echo     [DEBUG] Method 2: Checking Filter Manager...
echo [%DATE% %TIME%] [DEBUG] Method 2: Checking fltmc >> "%LogFile%"

fltmc > "%TEMP%\vajra_fltmc.txt" 2>&1
if %errorlevel% neq 0 goto :Method2Failed
set "adminVerified=true"
set "adminMethod=Filter Manager"
set "method2Result=SUCCESS"
echo     [DEBUG] Method 2: SUCCESS - Filter Manager accessible
echo [%DATE% %TIME%] [SUCCESS] Method 2 PASSED - fltmc executed successfully >> "%LogFile%"
echo     [FLTMC Output]: >> "%LogFile%"
type "%TEMP%\vajra_fltmc.txt" >> "%LogFile%"
del "%TEMP%\vajra_fltmc.txt" >nul 2>&1
goto :AdminCheckComplete

:Method2Failed
set "method2Result=FAILED"
echo     [DEBUG] Method 2: FAILED - fltmc access denied
echo [%DATE% %TIME%] [DEBUG] Method 2 FAILED - fltmc access denied >> "%LogFile%"
echo     [FLTMC Output]: >> "%LogFile%"
type "%TEMP%\vajra_fltmc.txt" >> "%LogFile%"
del "%TEMP%\vajra_fltmc.txt" >nul 2>&1

REM ---- Method 3: System32 Write Test ----
echo     [DEBUG] Method 3: Testing System32 write access...
echo [%DATE% %TIME%] [DEBUG] Method 3: Testing System32 write >> "%LogFile%"

set "testFile=%SystemRoot%\System32\.vajra_test_%RANDOM%.tmp"
echo test > "%testFile%" 2>nul
if not exist "%testFile%" goto :Method3Failed
del "%testFile%" >nul 2>&1
set "adminVerified=true"
set "adminMethod=System Directory Write"
set "method3Result=SUCCESS"
echo     [DEBUG] Method 3: SUCCESS - Can write to System32
echo [%DATE% %TIME%] [SUCCESS] Method 3 PASSED - System32 writable >> "%LogFile%"
goto :AdminCheckComplete

:Method3Failed
set "method3Result=FAILED"
echo     [DEBUG] Method 3: FAILED - Cannot write to System32
echo [%DATE% %TIME%] [DEBUG] Method 3 FAILED - Cannot write to System32 >> "%LogFile%"

REM ---- Method 4: Net Session (Legacy) ----
echo     [DEBUG] Method 4: Checking net session...
echo [%DATE% %TIME%] [DEBUG] Method 4: Checking net session >> "%LogFile%"

net session > "%TEMP%\vajra_session.txt" 2>&1
if %errorlevel% neq 0 goto :Method4Failed
set "adminVerified=true"
set "adminMethod=Network Session"
set "method4Result=SUCCESS"
echo     [DEBUG] Method 4: SUCCESS - Net session accessible
echo [%DATE% %TIME%] [SUCCESS] Method 4 PASSED - net session accessible >> "%LogFile%"
del "%TEMP%\vajra_session.txt" >nul 2>&1
goto :AdminCheckComplete

:Method4Failed
set "method4Result=FAILED"
echo     [DEBUG] Method 4: FAILED - Net session access denied
echo [%DATE% %TIME%] [DEBUG] Method 4 FAILED - net session failed >> "%LogFile%"
echo     [Net Session Output]: >> "%LogFile%"
type "%TEMP%\vajra_session.txt" >> "%LogFile%"
del "%TEMP%\vajra_session.txt" >nul 2>&1

:AdminCheckComplete
echo. >> "%LogFile%"
echo ---- ADMIN CHECK SUMMARY ---- >> "%LogFile%"
echo Method 1 (Elevation):      %method1Result% >> "%LogFile%"
echo   - isAdminMember:         %isAdminMember% >> "%LogFile%"
echo   - isElevated:            %isElevated% >> "%LogFile%"
echo Method 2 (Filter Manager): %method2Result% >> "%LogFile%"
echo Method 3 (System32 Write): %method3Result% >> "%LogFile%"
echo Method 4 (Net Session):    %method4Result% >> "%LogFile%"
echo Final: adminVerified=%adminVerified%, method=%adminMethod% >> "%LogFile%"
echo ----------------------------- >> "%LogFile%"
echo. >> "%LogFile%"

if "%adminVerified%"=="true" goto :AdminCheckPassed

REM Admin check failed - show error and exit
echo.
echo ================================================================================
echo  ERROR: ADMINISTRATIVE PRIVILEGES REQUIRED
echo ================================================================================
echo.
echo  This installer must be run with administrative privileges.
echo.
echo  All 4 verification methods failed:
echo    Method 1 (Elevation):      %method1Result%
echo    Method 2 (Filter Manager): %method2Result%
echo    Method 3 (System32 Write): %method3Result%
echo    Method 4 (Net Session):    %method4Result%
echo.
echo  SOLUTION: Right-click the script and select "Run as administrator"
echo.
echo  Diagnostic Info:
echo    Username: %USERNAME%
echo    Computer: %COMPUTERNAME%
echo    Log File: %LogFile%
echo.
echo ================================================================================
echo [%DATE% %TIME%] [ERROR] Admin verification FAILED >> "%LogFile%"
if exist "%LockFile%" del "%LockFile%"
echo.
echo Press any key to exit...
pause
exit /b 1

:AdminCheckPassed
echo [+] SUCCESS: Administrative privileges verified [Method: %adminMethod%]
echo [%DATE% %TIME%] [SUCCESS] Admin verified via: %adminMethod% >> "%LogFile%"

@REM ================================================================================
@REM WINDOWS VERSION DETECTION - Simplified like original
@REM ================================================================================
echo.
echo [+] Detecting Windows version...

set "windows_version=Unknown"
set "windows_build=0"
set "windows_major=0"

REM Get Windows version from registry
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber 2^>nul ^| find "CurrentBuildNumber"') do set "windows_build=%%a"
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentMajorVersionNumber 2^>nul ^| find "CurrentMajorVersionNumber"') do set /a "windows_major=%%a"
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName 2^>nul ^| find "ProductName"') do set "windows_product=%%a %%b"

REM Fallback to ver command
if "!windows_build!"=="0" (
    for /f "tokens=4-5 delims=. " %%i in ('ver') do set "VERSION=%%i.%%j"
)

REM Determine Windows version
if !windows_major! GEQ 10 (
    if !windows_build! GEQ 22000 (
        set "windows_version=11"
    ) else (
        set "windows_version=10"
    )
) else (
    for /f "tokens=4-5 delims=. " %%i in ('ver') do set "VERSION=%%i.%%j"
    if "!VERSION!" == "10.0" set "windows_version=10"
    if "!VERSION!" == "6.3" set "windows_version=8.1"
    if "!VERSION!" == "6.2" set "windows_version=8"
    if "!VERSION!" == "6.1" set "windows_version=7"
)

@REM Check architecture - exactly like original
reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL
if !errorlevel! equ 0 (
    set "architecture=32"
    set "bits32=true"
) else (
    set "architecture=64"
    set "bits32=false"
)

echo [%DATE% %TIME%] [INFO] Windows !windows_version! Build !windows_build! !architecture!-bit >> "%LogFile%"

if not "!windows_version!" == "7" if not "!windows_version!" == "8" if not "!windows_version!" == "8.1" if not "!windows_version!" == "10" if not "!windows_version!" == "11" (
    echo [-] Vajra EDR client does not support current Windows version.
    echo [-] Vajra EDR client currently supports Windows 7, Windows 8, Windows 8.1, Windows 10 and Windows 11.
    echo [-] Aborting the installation process.
    echo [%DATE% %TIME%] [ERROR] Unsupported Windows version >> "%LogFile%"
    if exist "%LockFile%" del "%LockFile%"
    pause
    exit /b 1
) else (
    echo [+] Vajra EDR client supports the current Windows version !windows_version! !architecture!-bit.
    echo [+] Continuing the installation process.
)

GOTO :CheckVajraService

@REM ================================================================================
@REM HELPER FUNCTIONS - Simplified like original
@REM ================================================================================

:removelock
    if exist "%LockFile%" del "%LockFile%"
    goto :eof

:cleanup
    echo [+] Cleaning up Vajra EDR client installation files
    sc stop %kServiceName% >nul 2>&1
    rmdir /s /q "%ProgramFiles%\osquery" >nul 2>&1
    rmdir /s /q "%ProgramFiles%\plgx_osquery\" >nul 2>&1
    sc delete %kServiceName% >nul 2>&1
    if exist "%LockFile%" del "%LockFile%"
    echo [+] Cleanup completed
    goto :eof

:LogError
    echo %* >> "%LogFile%"
    exit /b

@REM Stop with a clear message if the files that are not stored in this repository are missing
:MissingFile
    echo [-] ERROR: the certificate and enrollment secret are missing.
    echo [-] Put the Vajra server's CA certificate at common\cert.pem and its enrollment secret at common\enrollment_secret.txt,
    echo [-] or use the agent zip downloaded from the Vajra web console, which includes both.
    echo [%DATE% %TIME%] [ERROR] common\cert.pem or common\enrollment_secret.txt missing >> "%LogFile%"
    call :removelock
    pause
    exit /b 1

@REM Check if Vajra service is already running
:CheckVajraService
    echo [%DATE% %TIME%] [INFO] Checking if Vajra service already exists >> "%LogFile%"
    sc query %kServiceName% | findstr "RUNNING" >nul
    if !errorlevel! equ 0 (
        echo [-] ERROR: The Vajra EDR service is already running. Exiting...
        echo [%DATE% %TIME%] [ERROR] Service already RUNNING - cannot reinstall >> "%LogFile%"
        call :removelock
        pause
        exit /b 1
    ) else (
        echo [+] The Vajra EDR service is not running. Proceeding with the installation...
        echo [%DATE% %TIME%] [SUCCESS] Service not running - safe to proceed >> "%LogFile%"
    )


@REM ================================================================================
@REM PART 2: INSTALLING THE CLIENT - Using GOTO pattern to avoid batch bugs
@REM ================================================================================
:main
echo [%DATE% %TIME%] [INFO] Starting installation phase >> "%LogFile%"
if not exist "%~dp0common\cert.pem" goto :MissingFile
if not exist "%~dp0common\enrollment_secret.txt" goto :MissingFile

set OsquerydFilename=osqueryd.exe
set ExtnFilename=plgx_win_extension.ext.exe
set VajraExtnFilename=websocket_extension.ext.exe
set VajraWinExtnFilename=vajra_win_extension.ext.exe
set VajraExtnConfFilename=extension.conf
set OsqueryFlagsFilename=osquery.flags
set OsqueryExtnLoadFilename=extensions.load
set OsqueryCertFilename=cert.pem
set OsqueryEnrollmentSecretFilename=enrollment_secret.txt
set OsqueryManifestFilename=osquery.man

@REM If osquery is already on this machine (and Vajra is not), keep a copy of its files so
@REM vajra_uninstall.bat can put them back instead of deleting them.
set "VajraFlag=%ProgramFiles%\osquery\vajra_preexisting_osquery.flag"
set "VajraBackup=%ProgramFiles%\osquery\vajra_backup"
sc query %kServiceName% >nul 2>&1
if !errorlevel! neq 0 if exist "%ProgramFiles%\osquery\osqueryd\osqueryd.exe" if not exist "!VajraFlag!" (
    echo [+] osquery is already installed; its files are backed up and restored on uninstall
    mkdir "!VajraBackup!" >nul 2>&1
    copy /Y "%ProgramFiles%\osquery\osqueryd\osqueryd.exe" "!VajraBackup!\osqueryd.exe" >nul 2>&1
    for %%F in (osquery.flags extensions.load osquery.man enrollment_secret.txt cert.pem extension.conf) do (
        if exist "%ProgramFiles%\osquery\%%F" copy /Y "%ProgramFiles%\osquery\%%F" "!VajraBackup!\%%F" >nul 2>&1
    )
    type nul > "!VajraFlag!"
    echo [%DATE% %TIME%] [INFO] Existing osquery backed up to !VajraBackup! >> "%LogFile%"
)

echo [+] Creating installation directories
echo [%DATE% %TIME%] [INFO] Creating installation directories >> "%LogFile%"

@REM Create necessary directories
mkdir "%ProgramFiles%\osquery" >nul 2>&1
if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Created: %ProgramFiles%\osquery >> "%LogFile%"
mkdir "%ProgramFiles%\osquery\osqueryd" >nul 2>&1
if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Created: %ProgramFiles%\osquery\osqueryd >> "%LogFile%"
mkdir "%ProgramFiles%\osquery\packs" >nul 2>&1
if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Created: %ProgramFiles%\osquery\packs >> "%LogFile%"
mkdir "%ProgramFiles%\osquery\log" >nul 2>&1
if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Created: %ProgramFiles%\osquery\log >> "%LogFile%"
mkdir "%ProgramFiles%\osquery\certs" >nul 2>&1
if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Created: %ProgramFiles%\osquery\certs >> "%LogFile%"

@REM Copying executables and other files in the installation directory
echo [+] Copying executables and other files in the installation directory
echo [%DATE% %TIME%] [INFO] Starting file copy operations >> "%LogFile%"

set "SourceFolder=%~dp0"
set "ProgramFilesFolder=%ProgramFiles%\osquery"
set "CertFolderName=%ProgramFiles%\osquery\certs"
set "OsquerydFolderName=%ProgramFiles%\osquery\osqueryd"

echo [%DATE% %TIME%] [DEBUG] Source: !SourceFolder! >> "%LogFile%"
echo [%DATE% %TIME%] [DEBUG] Destination: !ProgramFilesFolder! >> "%LogFile%"

@REM Set architecture subfolder
if "!bits32!"=="false" (
    set "ArchSubfolder=x64"
    set "FilesToCopy=!OsqueryFlagsFilename! !ExtnFilename! !VajraExtnFilename! !VajraWinExtnFilename! !OsqueryManifestFilename! !OsqueryExtnLoadFilename!"
) else (
    set "ArchSubfolder=x86"
    set "FilesToCopy=!OsqueryFlagsFilename! !VajraWinExtnFilename! !OsqueryExtnLoadFilename!"
)
echo [%DATE% %TIME%] [DEBUG] Architecture: !architecture!-bit, using !ArchSubfolder! subfolder >> "%LogFile%"

@REM Copying architecture-specific files
for %%F in (!FilesToCopy!) do (
    echo [+] Copying file: %%F
    copy /Y "!SourceFolder!!ArchSubfolder!\%%F" "!ProgramFilesFolder!\%%F" >nul 2>&1
    if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Copied: %%F >> "%LogFile%"
    if !errorlevel! neq 0 echo [%DATE% %TIME%] [WARNING] Failed to copy: %%F >> "%LogFile%"
)

@REM Copying common files
echo [%DATE% %TIME%] [INFO] Copying common configuration files >> "%LogFile%"
for %%F in (!OsqueryEnrollmentSecretFilename! !OsqueryCertFilename! !VajraExtnConfFilename!) do (
    echo [+] Copying file: %%F
    copy /Y "!SourceFolder!common\%%F" "!ProgramFilesFolder!\%%F" >nul 2>&1
    if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Copied: %%F >> "%LogFile%"
    if !errorlevel! neq 0 echo [%DATE% %TIME%] [WARNING] Failed to copy: %%F >> "%LogFile%"
)

@REM Copying osqueryd executable file
echo [+] Copying osqueryd executable
copy /Y "!SourceFolder!!ArchSubfolder!\!OsquerydFilename!" "!OsquerydFolderName!\!OsquerydFilename!" >nul 2>&1
if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Copied: !OsquerydFilename! >> "%LogFile%"
if !errorlevel! neq 0 echo [%DATE% %TIME%] [WARNING] Failed to copy: !OsquerydFilename! >> "%LogFile%"

@REM Copying SSL certificate file to certs folder
echo [+] Copying SSL certificate to certs folder
copy /Y "!SourceFolder!common\!OsqueryCertFilename!" "!CertFolderName!\!OsqueryCertFilename!" >nul 2>&1
if !errorlevel! equ 0 echo [%DATE% %TIME%] [SUCCESS] Copied: !OsqueryCertFilename! to certs folder >> "%LogFile%"
if !errorlevel! neq 0 echo [%DATE% %TIME%] [WARNING] Failed to copy: !OsqueryCertFilename! to certs folder >> "%LogFile%"

echo [+] All files copied successfully!
echo [%DATE% %TIME%] [INFO] File copy operations completed >> "%LogFile%"

@REM Creating the service - using GOTO pattern to avoid batch if/else bugs
echo [+] Creating Vajra EDR client service
echo [%DATE% %TIME%] [INFO] Creating Windows service: %kServiceName% >> "%LogFile%"

sc create %kServiceName% binPath= "\"C:\Program Files\osquery\osqueryd\osqueryd.exe\" \"--flagfile\" \"C:\Program Files\osquery\osquery.flags\" \"--allow_unsafe\"" start= auto DisplayName= %kServiceDisplayName% >nul 2>&1
if !errorlevel! neq 0 goto :ServiceCreateFailed
echo [+] Vajra EDR client service created successfully!
echo [%DATE% %TIME%] [SUCCESS] Service created successfully >> "%LogFile%"
goto :StartService

:ServiceCreateFailed
echo [-] Failed to create Vajra EDR service!
echo [%DATE% %TIME%] [ERROR] Service creation failed >> "%LogFile%"
call :cleanup
pause
exit /b 1

:StartService
@REM Starting the service - using GOTO pattern
echo [+] Starting Vajra EDR client service
echo [%DATE% %TIME%] [INFO] Starting service: %kServiceName% >> "%LogFile%"

sc start %kServiceName% >nul 2>&1
set "startErrorLevel=!errorlevel!"
echo [%DATE% %TIME%] [DEBUG] sc start returned errorlevel=!startErrorLevel! >> "%LogFile%"
if !startErrorLevel! neq 0 goto :ServiceStartWarning
echo [+] Vajra EDR client service started successfully!
echo [%DATE% %TIME%] [SUCCESS] Service started successfully >> "%LogFile%"
goto :VerifyService

:ServiceStartWarning
echo [%DATE% %TIME%] [WARNING] Service start returned errorlevel=!startErrorLevel! >> "%LogFile%"

:VerifyService
@REM Verify final service status
echo [%DATE% %TIME%] [INFO] Verifying final service status >> "%LogFile%"
sc query %kServiceName% 2>&1 >> "%LogFile%"

sc query %kServiceName% | findstr "RUNNING" >nul 2>&1
if !errorlevel! neq 0 goto :ServiceNotRunning
echo [+] Vajra EDR client installation successful!
echo [%DATE% %TIME%] [SUCCESS] Installation completed - Service is RUNNING >> "%LogFile%"
goto :InstallComplete

:ServiceNotRunning
echo [-] WARNING: Installation completed but service may not be running
echo [%DATE% %TIME%] [WARNING] Installation completed but service is NOT in RUNNING state >> "%LogFile%"

:InstallComplete
echo [%DATE% %TIME%] [INFO] Installation script completed >> "%LogFile%"

@REM Removing the Lock file
del "%LockFile%" >nul 2>&1
pause
