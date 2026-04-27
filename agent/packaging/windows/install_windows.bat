@echo off
:: AIPET X Agent — Windows installer
:: Designed for non-technical IT staff. Asks 3 questions max.
:: Self-tests the install. Plain-English errors only.
::
:: Usage:
::   1. Right-click  -> Run as administrator
::   2. Or from an elevated cmd: install_windows.bat
::
:: Optional environment overrides (advanced):
::   AIPET_API_URL    default https://api.aipet.io  (use http://... for dev)
::   AIPET_DEV_MODE   set to 1 to skip the SSL cert check banner
setlocal enabledelayedexpansion

set "VERSION=1.0.0"
set "SCRIPT_DIR=%~dp0"
set "INSTALL_DIR=%ProgramFiles%\AIPET"
set "DATA_DIR=%ProgramData%\AIPET"
set "DEFAULT_API=%AIPET_API_URL%"
if "%DEFAULT_API%"=="" set "DEFAULT_API=https://api.aipet.io"

:: ── 1. Administrator check ───────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [X] This installer needs Administrator privileges.
    echo      Right-click install_windows.bat and choose "Run as administrator".
    echo.
    pause
    exit /b 1
)

cls
echo.
echo  ====================================================
echo    AIPET X Agent - Installation (Windows v%VERSION%)
echo  ====================================================
echo.
echo  This will install the AIPET X security agent as a
echo  Windows Service. It scans your local network for IoT
echo  devices and reports findings to your AIPET dashboard.
echo.
echo    Required:  Administrator, Python 3.8+, nmap
echo    Time:      ~3 minutes
echo.

:: ── 2. Python check ──────────────────────────────────────
echo  [..] Checking for Python 3.8+...
set "PYTHON_EXE="
for %%P in (python.exe python3.exe py.exe) do (
    where %%P >nul 2>&1
    if !errorlevel! equ 0 (
        for /f "tokens=2" %%V in ('%%P --version 2^>^&1') do (
            set "PYVER=%%V"
            for /f "tokens=1,2 delims=." %%A in ("!PYVER!") do (
                if %%A geq 3 if %%B geq 8 (
                    for /f "delims=" %%X in ('where %%P') do set "PYTHON_EXE=%%X"
                    goto :python_found
                )
            )
        )
    )
)
echo  [X] Python 3.8 or newer not found.
echo      Download from https://www.python.org/downloads/ and tick
echo      "Add Python to PATH" during install. Then re-run this script.
pause
exit /b 1

:python_found
echo  [OK] Python found: !PYTHON_EXE! ^(version !PYVER!^)

:: ── 3. nmap check ────────────────────────────────────────
echo  [..] Checking for nmap...
where nmap >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] nmap not found in PATH.
    echo      Download from https://nmap.org/dist/nmap-7.95-setup.exe
    echo      and re-run this installer. Continuing without nmap means
    echo      scans will fail until it is installed.
    echo.
    set /p CONTINUE_NO_NMAP="     Continue anyway? [y/N]: "
    if /i not "!CONTINUE_NO_NMAP!"=="y" exit /b 1
) else (
    echo  [OK] nmap found
)

:: ── 4. Three questions ───────────────────────────────────
echo.
echo  ---- Configuration ---------------------------------
echo.
echo  1. Your AIPET X agent API key
echo     ^(Get one at https://app.aipet.io/settings/agents^)
echo     Format: aipet_^<random^>
echo.
:ask_key
set "AGENT_KEY="
set /p AGENT_KEY="     Key: "
if "!AGENT_KEY!"=="" (
    echo  [!] Key cannot be empty.
    goto :ask_key
)
echo !AGENT_KEY! | findstr /R "^aipet_[A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-][A-Za-z0-9_-]" >nul
if !errorlevel! neq 0 (
    echo  [!] That doesn't look like a valid AIPET key. It must start with
    echo      "aipet_" and be at least 26 characters long.
    goto :ask_key
)

echo.
echo  2. Label for this agent ^(default: %COMPUTERNAME%^)
set "AGENT_LABEL="
set /p AGENT_LABEL="     Label: "
if "!AGENT_LABEL!"=="" set "AGENT_LABEL=%COMPUTERNAME%"

echo.
echo  3. Network to scan ^(CIDR like 192.168.1.0/24, or "auto"^)
set "SCAN_TARGET="
set /p SCAN_TARGET="     Network: "
if "!SCAN_TARGET!"=="" set "SCAN_TARGET=auto"

echo.

:: ── 5. Create directories ────────────────────────────────
echo  [..] Creating install directories
if not exist "%INSTALL_DIR%"      mkdir "%INSTALL_DIR%"
if not exist "%DATA_DIR%"         mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\logs"    mkdir "%DATA_DIR%\logs"
if not exist "%DATA_DIR%\state"   mkdir "%DATA_DIR%\state"
echo  [OK] Directories ready

:: ── 6. Copy files ────────────────────────────────────────
echo  [..] Copying agent files
copy /Y "%SCRIPT_DIR%aipet_agent.py" "%INSTALL_DIR%\aipet_agent.py" >nul
copy /Y "%SCRIPT_DIR%watchdog.py"    "%INSTALL_DIR%\watchdog.py"    >nul
copy /Y "%SCRIPT_DIR%nssm.exe"       "%INSTALL_DIR%\nssm.exe"       >nul
copy /Y "%SCRIPT_DIR%aipet-agent-service-install.bat"   "%INSTALL_DIR%\aipet-agent-service-install.bat"   >nul
copy /Y "%SCRIPT_DIR%aipet-agent-service-uninstall.bat" "%INSTALL_DIR%\aipet-agent-service-uninstall.bat" >nul
copy /Y "%SCRIPT_DIR%uninstall_windows.bat"             "%INSTALL_DIR%\uninstall_windows.bat"             >nul
copy /Y "%SCRIPT_DIR%README-Windows.md"                 "%INSTALL_DIR%\README-Windows.md"                 >nul
echo  [OK] Files installed under %INSTALL_DIR%

:: ── 7. Install Python deps into a per-service site-dir ──
echo  [..] Installing Python dependencies (psutil, requests, defusedxml)
"!PYTHON_EXE!" -m pip install --quiet --upgrade pip >nul 2>&1
"!PYTHON_EXE!" -m pip install --quiet psutil requests defusedxml
if !errorlevel! neq 0 (
    echo  [X] pip install failed. Try running:
    echo        "!PYTHON_EXE!" -m pip install psutil requests defusedxml
    pause
    exit /b 1
)
echo  [OK] Dependencies installed

:: ── 8. Write config ──────────────────────────────────────
echo  [..] Writing %DATA_DIR%\agent.conf
^> "%DATA_DIR%\agent.conf" echo # AIPET X Agent Configuration ^(generated %DATE% %TIME%^)
^>^> "%DATA_DIR%\agent.conf" echo # This file documents the values used to install the service.
^>^> "%DATA_DIR%\agent.conf" echo # The service itself reads these values from environment variables
^>^> "%DATA_DIR%\agent.conf" echo # set by NSSM. To change config: re-run install_windows.bat.
^>^> "%DATA_DIR%\agent.conf" echo AIPET_API=%DEFAULT_API%
^>^> "%DATA_DIR%\agent.conf" echo AIPET_AGENT_KEY=^(redacted^)
^>^> "%DATA_DIR%\agent.conf" echo AIPET_AGENT_LABEL=!AGENT_LABEL!
^>^> "%DATA_DIR%\agent.conf" echo AIPET_SCAN_TARGET=!SCAN_TARGET!
^>^> "%DATA_DIR%\agent.conf" echo AIPET_SCAN_INTERVAL_HOURS=24
^>^> "%DATA_DIR%\agent.conf" echo AIPET_INTERVAL=60
^>^> "%DATA_DIR%\agent.conf" echo AIPET_WATCHDOG_INTERVAL=300
^>^> "%DATA_DIR%\agent.conf" echo AIPET_LOG_LEVEL=INFO
:: ACL: only Administrators + SYSTEM can read the conf
icacls "%DATA_DIR%\agent.conf" /inheritance:r /grant:r SYSTEM:F Administrators:F >nul 2>&1
echo  [OK] Configuration saved (key value held in service env, NOT written to disk)

:: ── 9. Install service ──────────────────────────────────
:: Export env vars for the service-install script
set "AIPET_API=%DEFAULT_API%"
set "AIPET_AGENT_KEY=!AGENT_KEY!"
set "AIPET_AGENT_LABEL=!AGENT_LABEL!"
set "AIPET_SCAN_TARGET=!SCAN_TARGET!"
set "AIPET_SCAN_INTERVAL_HOURS=24"
set "AIPET_INTERVAL=60"
set "AIPET_WATCHDOG_INTERVAL=300"
set "AIPET_LOG_LEVEL=INFO"

call "%INSTALL_DIR%\aipet-agent-service-install.bat"
if !errorlevel! neq 0 (
    echo  [X] Service installation failed.
    pause
    exit /b 1
)

echo  [..] Starting service
sc start AipetAgent >nul 2>&1
timeout /t 4 /nobreak >nul

:: ── 10. Add/Remove Programs registry entry ──────────────
echo  [..] Registering with Add/Remove Programs
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent" /v "DisplayName"     /t REG_SZ /d "AIPET X Agent"                     /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent" /v "DisplayVersion"  /t REG_SZ /d "%VERSION%"                          /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent" /v "Publisher"       /t REG_SZ /d "AIPET X"                            /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent" /v "InstallLocation" /t REG_SZ /d "%INSTALL_DIR%"                      /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent" /v "UninstallString" /t REG_SZ /d "\"%INSTALL_DIR%\uninstall_windows.bat\"" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent" /v "NoModify"        /t REG_DWORD /d 1                                  /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent" /v "NoRepair"        /t REG_DWORD /d 1                                  /f >nul
echo  [OK] Registered

:: ── 11. Self-test ───────────────────────────────────────
echo.
echo  ---- Self-test -----------------------------------
echo.

echo  [..] Verifying service is running
sc query AipetAgent | findstr /C:"RUNNING" >nul
if !errorlevel! neq 0 (
    echo  [X] Service is not running. Recent log lines:
    if exist "%DATA_DIR%\logs\agent-error.log" (
        type "%DATA_DIR%\logs\agent-error.log" 2>nul
    )
    pause
    exit /b 1
)
echo  [OK] Service is RUNNING

echo  [..] Verifying connection to %DEFAULT_API%
:: Use Python's urllib to avoid depending on curl on the box
"!PYTHON_EXE!" -c "import urllib.request, ssl, sys; req=urllib.request.Request('%DEFAULT_API%/api/agent/keys/me', headers={'X-Agent-Key':'!AGENT_KEY!'}); ctx=ssl._create_unverified_context() if '%DEFAULT_API%'.startswith('https') and '%AIPET_DEV_MODE%'=='1' else None; r=urllib.request.urlopen(req, timeout=10, context=ctx); sys.exit(0 if r.status==200 else 1)" 2>nul
if !errorlevel! neq 0 (
    echo  [X] Cloud rejected the agent key. Generate a new one and re-run.
    pause
    exit /b 1
)
echo  [OK] Cloud accepted agent key

echo  [..] Waiting 10 seconds for first telemetry round-trip...
timeout /t 10 /nobreak >nul
if exist "%DATA_DIR%\logs\agent.log" (
    findstr /C:"Telemetry sent" "%DATA_DIR%\logs\agent.log" >nul
    if !errorlevel! equ 0 (
        echo  [OK] Telemetry flowing
    ) else (
        echo  [!] No telemetry yet. Check %DATA_DIR%\logs\agent.log in a minute.
    )
) else (
    echo  [!] Log file not yet created. Will appear at %DATA_DIR%\logs\agent.log
)

:: ── 12. Final ──────────────────────────────────────────
echo.
echo  ====================================================
echo    AIPET X Agent installed successfully.
echo  ====================================================
echo.
echo    Service:     AipetAgent ^(auto-start on boot^)
echo    Install dir: %INSTALL_DIR%
echo    Logs:        %DATA_DIR%\logs\agent.log
echo    Scan target: !SCAN_TARGET!
echo    Frequency:   every 24 hours
echo.
echo    Useful commands:
echo      sc query AipetAgent       (check status)
echo      sc stop  AipetAgent       (stop)
echo      sc start AipetAgent       (start)
echo      uninstall_windows.bat     (remove)
echo.
echo    Documentation: %INSTALL_DIR%\README-Windows.md
echo.
endlocal
pause
exit /b 0
