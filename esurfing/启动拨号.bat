@echo off
rem ============================================================
rem  ESurfing dialer - launcher
rem
rem  IMPORTANT: this file is intentionally pure ASCII.
rem  cmd.exe parses batch files byte-by-byte using the active code
rem  page; a .bat containing Chinese can be mis-parsed (characters
rem  treated as command separators) and the window closes at once.
rem  All Chinese UI lives in run.py instead.
rem
rem  Double-click this file to dial. No menu, no extra steps.
rem ============================================================
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

set "PY="
set "PYARGS=-X utf8"

rem ---------- locate Python ----------
for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
if not defined PY (
    for /f "delims=" %%i in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
)
if not defined PY (
    for %%p in (
        "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python39\python.exe"
        "C:\Python313\python.exe"
        "C:\Python312\python.exe"
        "C:\Python311\python.exe"
    ) do (
        if not defined PY if exist %%p set "PY=%%~p"
    )
)

if not defined PY goto no_python

rem ---------- dependency check ----------
"%PY%" -c "import Crypto" >nul 2>&1
if errorlevel 1 (
    echo.
    echo  Installing dependency pycryptodome ...
    echo.
    "%PY%" -m pip install pycryptodome
    if errorlevel 1 goto dep_fail
    echo.
    echo  Dependency installed.
    echo.
)

rem ---------- hand over to the dialer ----------
"%PY%" %PYARGS% run.py

if errorlevel 1 (
    echo.
    echo  The dialer exited with an error. Output above may explain why.
    echo.
    pause
)
exit /b 0

:no_python
echo.
echo  ============================================================
echo    Python not found
echo  ============================================================
echo.
echo  Please install Python 3.8 or newer:
echo    https://www.python.org/downloads/
echo.
echo  During installation, tick "Add Python to PATH".
echo.
pause
exit /b 1

:dep_fail
echo.
echo  Failed to install pycryptodome. Run manually:
echo    "%PY%" -m pip install pycryptodome
echo.
pause
exit /b 1
