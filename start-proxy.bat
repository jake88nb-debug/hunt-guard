@echo off
rem ============================================================
rem  HuntGuard - start with the local intercept proxy
rem  Console + proxy on 127.0.0.1:8899
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

echo.
echo   ============================================
echo    HuntGuard console + intercept proxy
echo   ============================================
echo.
echo   Proxy listens on 127.0.0.1:8899  (full HTTP inspection)
echo   For HTTPS, enable MITM in the console ("Proxy / System" tab).
echo.
echo   Point Burp's Upstream Proxy, or your browser proxy, at that address.
echo.

"%WAF_PY%" "%WAF_ROOT%\waf\cli.py" start --proxy %*

echo.
echo   HuntGuard stopped.
pause
