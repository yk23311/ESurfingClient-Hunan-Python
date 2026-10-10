@echo off
rem ============================================================
rem  Test the MAIN C client (ESurfingClient.exe) on the Hunan path.
rem
rem  Unlike the earlier hunan_live tests, this runs the real program:
rem  network check -> province routing -> session init -> ticket ->
rem  login -> keepalive, plus supervisor / watchdog / web UI.
rem
rem  BEFORE RUNNING: stop the Python dialer (Ctrl+C in its window).
rem  This script checks keepalive.lock and refuses to start if the
rem  Python keepalive is still alive - two clients would fight over
rem  the same session and the result would be meaningless.
rem
rem  If the main client fails to get online, the Python dialer is
rem  started automatically to restore connectivity.
rem
rem  Pure ASCII on purpose (see restore_network.bat).
rem ============================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "PY="
for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
if not defined PY (
    for /f "delims=" %%i in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
)
if not defined PY (
    echo.
    echo  Python not found.
    echo.
    pause
    exit /b 1
)

echo.
echo  ============================================================
echo   Main C client - Hunan live test
echo  ============================================================
echo.
echo   This will briefly drop the network on purpose, then let the
echo   C client bring it back. If it fails, the Python dialer is
echo   started automatically.
echo.
echo   Log: main-client-test.log
echo.
echo   Press Ctrl+C to stop watching.
echo.

"%PY%" -X utf8 test_main_client.py %*

echo.
echo  Test finished.
pause
exit /b 0
