@echo off
:: AIPET X Agent -- Windows uninstaller
:: Removes the AipetAgent service, install directory, ProgramData state,
:: and the Add/Remove Programs registry entry.
::
:: Triggered by:
::   * User runs uninstall_windows.bat directly
::   * Add/Remove Programs (uses UninstallString from registry)

setlocal

set "INSTALL_DIR=%ProgramFiles%\AIPET"
set "DATA_DIR=%ProgramData%\AIPET"

:: Self-relocate: if we're being run from %INSTALL_DIR% (the most common
:: case -- user double-clicks uninstall_windows.bat or AppWiz invokes
:: it via the registry's UninstallString), we cannot delete that
:: directory while running OUT of a file inside it. Copy ourselves to
:: %TEMP% and re-execute. PLB-9 found this: in-place execution leaves
:: cmd.exe with its bat in a deleted dir; subsequent commands fail with
:: "The system cannot find the path specified" and ProgramData +
:: registry are left orphaned.
if /i "%~dp0"=="%INSTALL_DIR%\" (
    copy /Y "%~f0" "%TEMP%\aipet-uninstall.bat" >nul
    cd /d "%TEMP%"
    cmd /c ""%TEMP%\aipet-uninstall.bat" --relocated"
    exit /b %ERRORLEVEL%
)

:: -- Administrator check --------------------------------
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

:: CRITICAL: step out of the install dir before we touch anything inside it.
:: If the user double-clicked uninstall_windows.bat from %INSTALL_DIR%, our
:: working directory IS the directory we're about to delete. rmdir /S /Q
:: succeeds against an in-use working directory but leaves the bat itself
:: locked, and the script's subsequent steps run with a stale cwd that
:: causes "The system cannot find the path specified" errors that abort
:: the rest of cleanup. Move to %TEMP% before any destructive op.
cd /d "%TEMP%"

echo  [..] Stopping and removing AipetAgent service
if exist "%INSTALL_DIR%\aipet-agent-service-uninstall.bat" (
    call "%INSTALL_DIR%\aipet-agent-service-uninstall.bat"
) else (
    sc stop AipetAgent >nul 2>&1
    sc delete AipetAgent >nul 2>&1
)
echo  [OK] Service removed

echo  [..] Removing installation directory %INSTALL_DIR%
if exist "%INSTALL_DIR%" rmdir /S /Q "%INSTALL_DIR%" 2>nul
if exist "%INSTALL_DIR%" (
    :: Some files may be locked briefly by SCM after service removal --
    :: wait 2s and retry once.
    timeout /t 2 /nobreak >nul
    rmdir /S /Q "%INSTALL_DIR%" 2>nul
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
