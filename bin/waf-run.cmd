@echo off
rem ============================================================
rem  HuntGuard: run any command with the guard active.
rem
rem  Usage:
rem    waf-run python exp.py
rem    waf-run --no-shim python exp.py
rem    waf-run --shell "curl http://x/?delete=1"
rem
rem  Locates Python automatically so it works right after
rem  unzipping, with no configuration.
rem
rem  NOTE: ASCII-only on purpose. cmd.exe reads .cmd files using
rem  the system codepage; non-ASCII bytes corrupt parsing.
rem  NOTE: variables set by a "call"ed file must be read OUTSIDE
rem  any parenthesised block (%VAR% expands at parse time).
rem ============================================================
setlocal
set "WAF_ROOT=%~dp0.."
set "WAF_PY="

rem --- fast path: reuse the Python detected at install time ---
call "%WAF_ROOT%\data\env.cmd" >nul 2>nul
if defined WAF_PYTHON set "WAF_PY=%WAF_PYTHON%"
if defined WAF_PY if not exist "%WAF_PY%" set "WAF_PY="

rem --- cache missing or stale: run the exhaustive search ---
if not defined WAF_PY call "%~dp0_find-python.cmd" >nul 2>nul
if defined WAF_PY set "WAF_PY=%WAF_PYTHON%"

if defined WAF_PY goto :run

echo [agent-waf] Python not found. Install Python 3.7+ then retry. 1>&2
exit /b 127

:run
"%WAF_PY%" "%WAF_ROOT%\waf\runner.py" %*
exit /b %ERRORLEVEL%
