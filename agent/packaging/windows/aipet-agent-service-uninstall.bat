@echo off
:: AIPET X Agent -- NSSM service uninstaller
:: Stops and removes the AipetAgent service. Files are removed by the
:: top-level uninstall_windows.bat.
setlocal

set "INSTALL_DIR=%ProgramFiles%\AIPET"
set "NSSM=%INSTALL_DIR%\nssm.exe"
set "SERVICE_NAME=AipetAgent"

if not exist "%NSSM%" (
    :: Service-level uninstall is best-effort if NSSM is missing -- fall back to sc
    sc stop %SERVICE_NAME% >nul 2>&1
    sc delete %SERVICE_NAME% >nul 2>&1
    exit /b 0
)

echo [..] Stopping service "%SERVICE_NAME%"
"%NSSM%" stop %SERVICE_NAME% >nul 2>&1

echo [..] Removing service "%SERVICE_NAME%"
"%NSSM%" remove %SERVICE_NAME% confirm >nul 2>&1

echo [OK] Service removed
endlocal
exit /b 0
