@echo off
rem ============================================================
rem  Route B - FULL live test of the C client against the real
rem  Hunan portal, with automatic recovery.
rem
rem  Steps:
rem    1. term.cgi  -> log out      (THIS DROPS YOUR NETWORK)
rem    2. auth.cgi  -> log back in  (using the C implementation)
rem    3. read      -> verify ticket/state/keep
rem
rem  If step 2 fails you are left OFFLINE, so this script then
rem  launches restore_network.bat in a new window, which reconnects
rem  using the Python dialer. Worst case you are back where you
rem  started - just double-click the normal dialer .bat.
rem
rem  NOTE: run this AFTER saving any work that needs the network.
rem  Pure ASCII on purpose (see restore_network.bat).
rem ============================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "TOOL=C:\temp\esurfing_build\hunan_live.exe"
rem config.json lives one level up (this script sits in the tools subfolder).
rem %~dp0.. expands at run time, so no Chinese literal appears in this file.
set "CFG=%~dp0..\config.json"
set "LOG=%~dp0routeB-test.log"

if not exist "%TOOL%" (
    echo.
    echo  ERROR: test tool not found:
    echo    %TOOL%
    echo  Build it first with C:\temp\esurfing_build\build_live.bat
    echo.
    pause
    exit /b 2
)

set "PY="
for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
if not defined PY (
    for /f "delims=" %%i in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
)

echo.
echo  ============================================================
echo   Route B - full live test
echo  ============================================================
echo.
echo   Step 1 logs out. YOUR NETWORK AND ANY REMOTE SESSION
echo   (including the AI assistant) WILL DROP.
echo.
echo   Step 2 brings it back with the C client.
echo   If step 2 fails, the Python dialer is started automatically.
echo.
echo   Log file: %LOG%
echo.
choice /c YN /n /m "  Continue? [Y]es / [N]o : "
if errorlevel 2 (
    echo.
    echo  Aborted. Nothing was changed.
    echo.
    pause
    exit /b 0
)
echo.

echo ============================================================ >  "%LOG%"
echo  Route B full test   %DATE% %TIME%                          >> "%LOG%"
echo ============================================================ >> "%LOG%"

rem ---- refresh identity while we still have a connection ----------
rem NOTE: this lives in refresh_identity.py, NOT as an inline Python
rem command. cmd.exe expands percent-delimited tokens inside .bat files,
rem so a printf-style format string in an inline snippet gets partially
rem eaten and Python dies with SyntaxError while the script carries on
rem regardless. Keeping it in a .py file avoids the whole class of problem.
if defined PY (
    echo  Refreshing adapter identity ...
    "%PY%" -X utf8 "%~dp0refresh_identity.py" >> "%LOG%" 2>&1
    if errorlevel 1 (
        echo  WARNING: identity refresh failed - continuing with the values
        echo           already in config.json.
    )
    echo.
) else (
    echo  WARNING: Python not found, skipping identity refresh.
    echo.
)

rem ---- step 1: logout -------------------------------------------
echo  [1/3] term.cgi  (logging out ...)
"%TOOL%" term "%CFG%" >> "%LOG%" 2>&1
set "RC1=%ERRORLEVEL%"
if not "%RC1%"=="0" (
    echo.
    echo  [1/3] FAILED - logout did not succeed.
    echo        You should still be ONLINE. Aborting before anything else.
    echo        See %LOG%
    echo.
    type "%LOG%"
    echo.
    pause
    exit /b 1
)
echo        OK - logged out.

rem ---- step 2: authenticate with the C client ------------------
echo.
echo  [2/3] auth.cgi  (logging back in with the C client ...)
"%TOOL%" auth "%CFG%" >> "%LOG%" 2>&1
set "RC2=%ERRORLEVEL%"
if not "%RC2%"=="0" (
    echo.
    echo  [2/3] FAILED - the C client could not authenticate.
    echo        You are currently OFFLINE. Starting the Python dialer
    echo        in a new window to restore connectivity ...
    echo.
    start "esurfing restore" "%~dp0restore_network.bat"
    echo        A new window should be opening. If the network does not
    echo        come back, double-click the normal dialer .bat yourself.
    echo.
    echo  ---- log so far ----
    type "%LOG%"
    echo.
    pause
    exit /b 1
)
echo        OK - authenticated.

rem ---- step 3: verify -------------------------------------------
echo.
echo  [3/3] verifying ticket / state / keep ...
"%TOOL%" read "%CFG%" >> "%LOG%" 2>&1
set "RC3=%ERRORLEVEL%"

echo.
echo  ============================================================
if "%RC3%"=="0" (
    echo   RESULT: ALL PASSED
    echo   The C implementation completed the full flow against the
    echo   real portal: term -^> auth -^> state -^> keep
) else (
    echo   RESULT: steps 1-2 passed, step 3 verification had problems
    echo   You are ONLINE, but check the log.
)
echo  ============================================================
echo.
echo  ---- full log ----
type "%LOG%"
echo.
pause
exit /b %RC3%
