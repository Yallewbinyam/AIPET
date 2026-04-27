@echo off
:: AIPET X Agent — NSSM service installer
:: Called by install_windows.bat after files are in place. Not intended for
:: direct use. Expects these env vars to be set in the calling shell:
::   AIPET_API, AIPET_AGENT_KEY, AIPET_AGENT_LABEL, AIPET_SCAN_TARGET,
::   AIPET_SCAN_INTERVAL_HOURS, AIPET_INTERVAL, AIPET_WATCHDOG_INTERVAL,
::   AIPET_LOG_LEVEL
:: Critical security setting: AppExit 1 Stop — when the watchdog detects a
:: revoked key and exits with code 1, NSSM does NOT restart the service.

setlocal

set "INSTALL_DIR=%ProgramFiles%\AIPET"
set "DATA_DIR=%ProgramData%\AIPET"
set "NSSM=%INSTALL_DIR%\nssm.exe"
set "SERVICE_NAME=AipetAgent"

if not exist "%NSSM%" (
    echo [X] nssm.exe not found at %NSSM%
    exit /b 1
)

if not exist "%DATA_DIR%\logs" mkdir "%DATA_DIR%\logs"

:: Resolve Python — prefer the bundled venv if present, else system Python
set "PYTHON_EXE=%INSTALL_DIR%\python\python.exe"
if not exist "%PYTHON_EXE%" (
    where python >nul 2>&1 && (for /f "delims=" %%i in ('where python') do set "PYTHON_EXE=%%i" & goto :py_resolved)
    where python3 >nul 2>&1 && (for /f "delims=" %%i in ('where python3') do set "PYTHON_EXE=%%i" & goto :py_resolved)
    echo [X] Could not locate python.exe. Install Python 3.8+ from python.org and re-run.
    exit /b 1
)
:py_resolved

echo [..] Installing service "%SERVICE_NAME%"
"%NSSM%" install %SERVICE_NAME% "%PYTHON_EXE%" "%INSTALL_DIR%\aipet_agent.py" >nul

:: Where the service runs from (so relative imports of watchdog.py work)
"%NSSM%" set %SERVICE_NAME% AppDirectory "%INSTALL_DIR%" >nul

:: Service identity
"%NSSM%" set %SERVICE_NAME% Description "AIPET X Security Agent" >nul
"%NSSM%" set %SERVICE_NAME% DisplayName "AIPET X Agent" >nul
"%NSSM%" set %SERVICE_NAME% Start SERVICE_AUTO_START >nul
"%NSSM%" set %SERVICE_NAME% ObjectName LocalSystem >nul

:: Logging — NSSM redirects stdout/stderr to files (with rotation)
"%NSSM%" set %SERVICE_NAME% AppStdout "%DATA_DIR%\logs\agent.log" >nul
"%NSSM%" set %SERVICE_NAME% AppStderr "%DATA_DIR%\logs\agent-error.log" >nul
"%NSSM%" set %SERVICE_NAME% AppRotateFiles 1 >nul
"%NSSM%" set %SERVICE_NAME% AppRotateBytes 10485760 >nul

:: SECURITY-CRITICAL — exit code 1 from the watchdog (revoked key) must
:: NOT be auto-restarted. Other exit codes (0 = clean shutdown, anything
:: else = crash) follow Default policy = Restart.
"%NSSM%" set %SERVICE_NAME% AppExit 1 Stop >nul
"%NSSM%" set %SERVICE_NAME% AppExit Default Restart >nul
"%NSSM%" set %SERVICE_NAME% AppRestartDelay 30000 >nul

:: Environment variables (NSSM AppEnvironmentExtra) — single string,
:: each KEY=VALUE separated by ASCII NUL is the official approach but
:: NSSM 2.x accepts space-separated KEY=VALUE on Windows.
"%NSSM%" set %SERVICE_NAME% AppEnvironmentExtra ^
    "AIPET_API=%AIPET_API%" ^
    "AIPET_AGENT_KEY=%AIPET_AGENT_KEY%" ^
    "AIPET_AGENT_LABEL=%AIPET_AGENT_LABEL%" ^
    "AIPET_SCAN_TARGET=%AIPET_SCAN_TARGET%" ^
    "AIPET_SCAN_INTERVAL_HOURS=%AIPET_SCAN_INTERVAL_HOURS%" ^
    "AIPET_INTERVAL=%AIPET_INTERVAL%" ^
    "AIPET_WATCHDOG_INTERVAL=%AIPET_WATCHDOG_INTERVAL%" ^
    "AIPET_LOG_LEVEL=%AIPET_LOG_LEVEL%" >nul

echo [OK] Service "%SERVICE_NAME%" installed (auto-start, restart-on-crash, stop-on-revoke)
endlocal
exit /b 0
