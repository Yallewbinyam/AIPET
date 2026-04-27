@echo off
:: AIPET X Agent — Windows uninstaller
:: Removes the AipetAgent service, install directory, ProgramData state,
:: and the Add/Remove Programs registry entry.
::
:: Triggered by:
::   * User runs uninstall_windows.bat directly
::   * Add/Remove Programs (uses UninstallString from registry)
setlocal

set "INSTALL_DIR=%ProgramFiles%\AIPET"
set "DATA_DIR=%ProgramData%\AIPET"

:: ── Administrator check ────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [X] This uninstaller needs Administrator privileges.
    echo      Right-click and choose "Run as administrator".
    pause
    exit /b 1
)

echo.
echo  ====================================================
echo    AIPET X Agent - Uninstall
echo  ====================================================
echo.
echo  This will remove the AIPET X Agent service, all installed
echo  files, configuration, logs, and the Add/Remove Programs
echo  entry. This cannot be undone.
echo.
set /p CONFIRM="  Type 'YES' to continue: "
if /i not "%CONFIRM%"=="YES" (
    echo.
    echo  Aborted. Nothing was removed.
    pause
    exit /b 0
)

echo.
echo  [..] Stopping and removing AipetAgent service
if exist "%INSTALL_DIR%\aipet-agent-service-uninstall.bat" (
    call "%INSTALL_DIR%\aipet-agent-service-uninstall.bat"
) else (
    sc stop AipetAgent >nul 2>&1
    sc delete AipetAgent >nul 2>&1
)
echo  [OK] Service removed

echo  [..] Removing installation directory %INSTALL_DIR%
if exist "%INSTALL_DIR%" (
    rmdir /S /Q "%INSTALL_DIR%"
)
echo  [OK] Install directory removed

echo  [..] Removing ProgramData directory %DATA_DIR%
if exist "%DATA_DIR%" (
    rmdir /S /Q "%DATA_DIR%"
)
echo  [OK] ProgramData removed (config, logs, state all gone)

echo  [..] Removing Add/Remove Programs entry
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AipetAgent" /f >nul 2>&1
echo  [OK] Registry entry removed

echo.
echo  ====================================================
echo    AIPET X Agent uninstalled.
echo  ====================================================
echo.
endlocal
pause
exit /b 0
