@echo off
rem ============================================================
rem  HuntGuard - one-click start (double-click this file)
rem
rem  On first run it also performs setup automatically (locate
rem  Python, detect tool paths, install hooks) so this is the
rem  only file you ever need to click.
rem
rem  NOTE: ASCII-only on purpose. cmd.exe reads .cmd files using
rem  the system codepage; non-ASCII bytes corrupt parsing.
rem ============================================================
setlocal
set "WAF_ROOT=%~dp0"
cd /d "%WAF_ROOT%"

rem ---- locate Python (exhaustive search) ----
call "%WAF_ROOT%\bin\_find-python.cmd" >nul 2>nul
if not defined WAF_PY (
  echo.
  echo   [ERROR] Python not found on this machine.
  echo.
  echo   Install Python 3.7+ from https://www.python.org/downloads/
  echo   During setup, tick "Add python.exe to PATH", then run this again.
  echo.
  pause
  exit /b 1
)

rem ---- first run? do the automatic setup ----
if not exist "%WAF_ROOT%\data\detected.json" (
  echo.
  echo   First run detected - performing automatic setup...
  echo.
  "%WAF_PY%" "%WAF_ROOT%\waf\cli.py" detect --quiet
  "%WAF_PY%" "%WAF_ROOT%\waf\cli.py" install-path
  echo.
)

rem ---- start the console ----
"%WAF_PY%" "%WAF_ROOT%\waf\cli.py" start %*

echo.
echo   HuntGuard stopped.
pause
