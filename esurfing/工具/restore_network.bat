@echo off
rem ============================================================
rem  Restore connectivity by running the Python dialer.
rem
rem  Called automatically by run_full_test.bat when the C client
rem  fails to authenticate. Can also be run by hand.
rem
rem  IMPORTANT: pure ASCII on purpose. cmd.exe parses .bat files
rem  byte-by-byte using the active code page, so Chinese literals
rem  would be mis-parsed. The Chinese path is avoided by using %~dp0
rem  (this file lives in the tools subfolder; run.py is one level up,
rem  hence %~dp0.. -- still no Chinese literal in this file).
rem ============================================================
setlocal EnableExtensions
cd /d "%~dp0.."

set "PY="
for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
if not defined PY (
    for /f "delims=" %%i in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
)

if not defined PY (
    echo.
    echo  Python not found. Please double-click the dialer .bat manually.
    echo.
    pause
    exit /b 1
)

echo.
echo  Restoring connectivity with the Python dialer ...
echo  (this window stays open and keeps the session alive)
echo.

"%PY%" -X utf8 run.py

echo.
echo  The Python dialer has exited.
pause
exit /b 0
