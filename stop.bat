@echo off
rem ============================================================
rem  HuntGuard - one-click stop (double-click this file)
rem
rem  NOTE: ASCII-only on purpose; see start.bat for why.
rem ============================================================
setlocal
set "WAF_ROOT=%~dp0"
cd /d "%WAF_ROOT%"

call "%WAF_ROOT%\bin\_find-python.cmd" >nul 2>nul
if not defined WAF_PY (
  echo.
  echo   [ERROR] Python not found.
  echo.
  pause
  exit /b 1
)

"%WAF_PY%" "%WAF_ROOT%\waf\cli.py" stop

echo.
echo   Done. Closing in 3 seconds.
timeout /t 3 >nul
