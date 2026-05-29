@echo off
REM -------------------------------------------------------------------------
REM run_headless_export.bat
REM
REM Runs ExportFunctions.java in Ghidra headless mode.
REM
REM Usage:
REM   run_headless_export.bat <binary_path> <output_jsonl_path>
REM
REM Example:
REM   run_headless_export.bat "C:\samples\malware.exe" "data\input\malware.jsonl"
REM
REM Requirements:
REM   - GHIDRA_HOME environment variable must point to your Ghidra installation,
REM     e.g. C:\Tools\ghidra_11.0
REM   - A Ghidra project directory will be created at %TEMP%\ghidra_headless_project
REM -------------------------------------------------------------------------

setlocal

if "%~1"=="" (
    echo Usage: %~nx0 ^<binary_path^> ^<output_jsonl_path^>
    exit /b 1
)
if "%~2"=="" (
    echo Usage: %~nx0 ^<binary_path^> ^<output_jsonl_path^>
    exit /b 1
)

set "BINARY=%~f1"
set "OUTPUT=%~f2"
set "PROJECT_DIR=%TEMP%\ghidra_headless_project"
REM %~dp0 includes trailing backslash; strip it so quoted -scriptPath does not escape the closing quote
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

for %%I in ("%OUTPUT%") do mkdir "%%~dpI" 2>nul

if not defined GHIDRA_HOME (
    echo ERROR: GHIDRA_HOME is not set.
    echo.
    echo In Command Prompt ^(cmd^):
    echo   set GHIDRA_HOME=C:\Tools\ghidra_12.1_PUBLIC
    echo.
    echo In PowerShell ^(set does NOT work — use $env:^):
    echo   $env:GHIDRA_HOME = "C:\Tools\ghidra_12.1_PUBLIC"
    echo.
    echo Or use: ghidra_scripts\run_headless_export.ps1 -GhidraHome "C:\path\to\ghidra"
    exit /b 1
)

if not exist "%GHIDRA_HOME%\support\analyzeHeadless.bat" (
    echo ERROR: analyzeHeadless.bat not found at:
    echo   %GHIDRA_HOME%\support\analyzeHeadless.bat
    echo Check that GHIDRA_HOME is correct.
    exit /b 1
)

mkdir "%PROJECT_DIR%" 2>nul

echo.
echo Ghidra Headless Export
echo   Binary  : %BINARY%
echo   Output  : %OUTPUT%
echo   Project : %PROJECT_DIR%
echo   Script  : %SCRIPT_DIR%\ExportFunctions.java
echo.

"%GHIDRA_HOME%\support\analyzeHeadless.bat" ^
    "%PROJECT_DIR%" HeadlessExport ^
    -import "%BINARY%" ^
    -scriptPath "%SCRIPT_DIR%" ^
    -postScript ExportFunctions.java "%OUTPUT%" ^
    -deleteProject ^
    -overwrite

if errorlevel 1 (
    echo.
    echo ERROR: Ghidra headless analysis failed.
    exit /b 1
)

if not exist "%OUTPUT%" (
    echo.
    echo ERROR: Output file was not created: %OUTPUT%
    echo Check the log above for script compile errors ^(e.g. ExportFunctions.java^).
    exit /b 1
)

echo.
echo Done. Output written to: %OUTPUT%
endlocal
