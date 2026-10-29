@echo off

REM Vajra EDR client installer script

set scriptVersion=1.0.0.1
set "bits32=false"
set "LogFile=vajra_uninstall_log.txt"
set "LockFile=install.lock"
set kServiceName=vajra
set kServiceDescription=Vajra EDR client service
set kServiceDisplayName=vajra

GOTO :check_Permissions


@REM Log error messages function
:LogError
    echo %* >> "%LogFile%"
    exit /b

@REM 
:removelock
    if exist "%LockFile%" (
        del "%LockFile%"
    ) else (
        echo [-] Lock File does not exist.
    )
    goto :eof


@REM Check Admin privileges
echo [+] Verifying that script is running with Admin privileges.

:check_Permissions    
    net session >nul 2>&1 
    if %errorLevel% == 0 (
        echo [+] SUCCESS: Script running with Admin privileges! Proceeding with the uninstallation.
        call :LogError SUCCESS: Script running with Admin privileges!
    ) else (
        echo [-] ERROR: Please run this script with Admin privileges! Right click on Filename and Run as Administrator.
        call :LogError ERROR: Script running without Admin privileges!
        pause
        exit /b 1
    )

if exist "%LogFile%" del "%LogFile%"
if exist "%LockFile%" del "%LockFile%"

echo [+] Cleaning up Vajra EDR client installation files

echo [+] Checking if Vajra EDR client is installed

if exist "%LockFile%" (
    echo [-] Uninstall process is already in progress. Please wait... %LockFile%
    pause
    exit /b
)

REM Create the lock file
type nul > "%LockFile%"

sc query %kServiceName% | findstr /C:"SERVICE_NAME: %kServiceName%" >nul
if %errorlevel% neq 0 (
    echo [-] The Vajra EDR service does not exist
    echo [-] The Vajra EDR service does not exist
    echo [-] Exiting
    pause
    exit /b 1
)

echo [+] The Vajra EDR service exists. Proceeding to uninstall

echo [+] Stopping the Vajra EDR service

sc stop %kServiceName% >nul 2>> "%LogFile%"

if exist "%ProgramFiles%\osquery\vajra_preexisting_osquery.flag" goto :RestoreOsquery

echo [+] Removing "%ProgramFiles%\osquery" files

rmdir /s /q "%ProgramFiles%\osquery" >nul 2>> "%LogFile%"
if %errorlevel% equ 0 (
    echo [+] Cleared all the installation directories
) else (
    echo [-] Failed to clear all the installation directories
)
goto :AfterOsqueryRemoval

:RestoreOsquery
@REM osquery was installed before Vajra: remove only Vajra's files and put the originals back.
echo [+] osquery was already installed before Vajra; restoring it
for %%F in (osquery.flags extensions.load osquery.man enrollment_secret.txt cert.pem extension.conf plgx_win_extension.ext.exe websocket_extension.ext.exe vajra_win_extension.ext.exe) do (
    del /f /q "%ProgramFiles%\osquery\%%F" >nul 2>> "%LogFile%"
)
del /f /q "%ProgramFiles%\osquery\certs\cert.pem" >nul 2>> "%LogFile%"
if exist "%ProgramFiles%\osquery\vajra_backup\osqueryd.exe" copy /Y "%ProgramFiles%\osquery\vajra_backup\osqueryd.exe" "%ProgramFiles%\osquery\osqueryd\osqueryd.exe" >nul 2>> "%LogFile%"
for %%F in (osquery.flags extensions.load osquery.man enrollment_secret.txt cert.pem extension.conf) do (
    if exist "%ProgramFiles%\osquery\vajra_backup\%%F" copy /Y "%ProgramFiles%\osquery\vajra_backup\%%F" "%ProgramFiles%\osquery\%%F" >nul 2>> "%LogFile%"
)
rmdir /s /q "%ProgramFiles%\osquery\vajra_backup" >nul 2>&1
del /f /q "%ProgramFiles%\osquery\vajra_preexisting_osquery.flag" >nul 2>&1

:AfterOsqueryRemoval
echo [+] Removing "%ProgramFiles%\plgx_osquery\" files

rmdir /s /q "%ProgramFiles%\plgx_osquery\" >nul 2>> "%LogFile%"

@REM Remove service
echo [+] Removing Vajra EDR client service

sc delete %kServiceName% >nul 2>> "%LogFile%"

@REM Removing lock file
if exist "%LockFile%" (
    del "%LockFile%"
) else (
    echo [-] File does not exist.
)
echo [+] Cleanup completed

echo [+] Vajra EDR is successfully removed
pause 