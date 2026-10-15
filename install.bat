@echo off
rem ============================================================
rem  HuntGuard - one-click installer (double-click this file)
rem
rem  Fully automatic. No questions asked:
rem    1. locate Python (exhaustive search, works without PATH)
rem    2. detect curl / Git Bash / PowerShell paths and cache them
rem    3. install all interception hooks
rem    4. self-check
rem
rem  NOTE: ASCII-only on purpose. cmd.exe reads .cmd files using
rem  the system codepage; non-ASCII bytes corrupt parsing.
rem ============================================================
setlocal
set "WAF_ROOT=%~dp0"
cd /d "%WAF_ROOT%"

echo.
echo   ============================================================
echo    HuntGuard installer
echo   ============================================================
echo.

rem ---- 1. locate Python ----
echo   [1/3] Locating Python...
call "%WAF_ROOT%\bin\_find-python.cmd" >nul 2>nul
if not defined WAF_PY (
  echo.
  echo   [ERROR] Python not found on this machine.
  echo.
  echo   Install Python 3.7+ from https://www.python.org/downloads/
  echo   During setup, tick "Add python.exe to PATH", then re-run
  echo   this installer.
  echo.
  pause
  exit /b 1
)
echo         found: %WAF_PY%

rem ---- 2. detect tool paths and cache them ----
echo   [2/3] Detecting curl / Git Bash / PowerShell...
"%WAF_PY%" "%WAF_ROOT%\waf\cli.py" detect --quiet
if errorlevel 1 (
  echo         [WARN] detection reported problems; continuing anyway
)

rem ---- 3. install hooks (cmd AutoRun / BASH_ENV / PowerShell / Python) ----
echo   [3/3] Installing interception hooks...
"%WAF_PY%" "%WAF_ROOT%\waf\cli.py" install-path
if errorlevel 1 (
  echo         [WARN] some hooks failed to install; see messages above
)


echo.
echo   ============================================================
echo    Done
echo   ============================================================
echo.
echo   Daily use:
echo     1. Double-click start.bat   (browser opens automatically)
echo     2. Double-click stop.bat    (when you are done)
echo.
echo   Reopen your terminal once so the hooks take effect.
echo.
echo   Tools are picked up automatically:
echo     * curl        via hook installed above
echo     * Burp Suite  load extension  burp\burp_waf.py
echo     * AI scripts  waf-run python exp.py
echo     * Browser     start-proxy.bat, then proxy 127.0.0.1:8899
echo.
pause
