@echo off
setlocal EnableDelayedExpansion

:: ---------------------------------------------------------------
:: R-SecOpsX SAST - Windows launcher
:: Works correctly even when the tool folder has spaces in its name.
::
:: Usage:
::   run.bat                           <- scans sample_app folder
::   run.bat "C:\My Code\my-project"  <- scans that folder
::   run.bat "C:\My Code\project" "C:\Reports\output"
:: ---------------------------------------------------------------

:: %~dp0 = full path to the folder containing this .bat, always quoted-safe
set "TOOL_DIR=%~dp0"

:: Remove trailing backslash from TOOL_DIR if present
if "%TOOL_DIR:~-1%"=="\" set "TOOL_DIR=%TOOL_DIR:~0,-1%"

:: Target: use first argument if given, else sample_app inside tool folder
if "%~1"=="" (
    set "TARGET=%TOOL_DIR%\sample_app"
) else (
    set "TARGET=%~1"
)

:: Output: use second argument if given, else reports inside tool folder
if "%~2"=="" (
    set "OUTPUT=%TOOL_DIR%\reports"
) else (
    set "OUTPUT=%~2"
)

echo.
echo  EnterpriseGuard SAST - Windows Launcher
echo  Tool    : %TOOL_DIR%
echo  Target  : %TARGET%
echo  Output  : %OUTPUT%
echo.

:: cd into the tool directory first so Python can find scanner/, core/, reporting/
cd /d "%TOOL_DIR%"

:: Run main.py with fully quoted paths
python "%TOOL_DIR%\main.py" "%TARGET%" --output-dir "%OUTPUT%" --workers 2

echo.
echo  Reports saved to: %OUTPUT%
echo.
pause
