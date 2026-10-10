@echo off
rem ============================================================
rem  Watch the current session until the server reclaims it, then
rem  bring the network back up with the C client.
rem
rem  Use this if the background watcher is not running (check for
rem  session-watch.lock and session-watch.log in this folder).
rem
rem  It logs everything to session-watch.log, so the result survives
rem  even if your remote session (the AI assistant) goes offline.
rem
rem  Only ONE watcher may run at a time - the script refuses to start
rem  a second one, because two watchers would each authenticate and
rem  fight over the session.
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
echo   Wait for the drop, then dial back up with the C client
echo  ============================================================
echo.
echo   Probe: TCP to public DNS, bound to your campus source IP.
echo          It never touches the portal, so it cannot keep the
echo          session alive by accident.
echo.
echo   On drop: re-authenticates with the C client and verifies.
echo            If that fails, the Python dialer is started instead.
echo.
echo   Log: session-watch.log
echo.
echo   Press Ctrl+C to stop watching (this does NOT affect the network).
echo.

"%PY%" -X utf8 watch_session.py

echo.
echo  Watcher exited.
pause
exit /b 0
