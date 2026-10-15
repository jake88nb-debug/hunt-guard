@echo off
rem ============================================================
rem  HuntGuard curl interceptor (Windows cmd)
rem
rem  Installed to the front of PATH so typing "curl" goes
rem  through the WAF. Can also be called directly:
rem      curl.cmd <normal curl arguments>
rem
rem  Python is located automatically (works right after unzip,
rem  even when python.exe is not on PATH).
rem
rem  NOTE: ASCII-only on purpose. cmd.exe reads .cmd files using
rem  the system codepage; non-ASCII bytes corrupt parsing.
rem
rem  NOTE: variables from a "call"ed file must be read OUTSIDE
rem  any parenthesised block -- %VAR% is expanded when the block
rem  is parsed, i.e. before the call runs. That mismatch silently
rem  produced an empty Python path. Hence the flat structure below.
rem ============================================================
setlocal
set "WAF_ROOT=%~dp0.."
set "WAF_PY="

rem --- load install-time cache (also gives WAF_CURL for passthrough) ---
call "%WAF_ROOT%\data\env.cmd" >nul 2>nul
if defined WAF_PYTHON set "WAF_PY=%WAF_PYTHON%"
if defined WAF_PY if not exist "%WAF_PY%" set "WAF_PY="

rem --- fast path: WAF provably NOT active -> skip Python entirely ---
rem
rem  Why this exists (third-party review): without it every single curl
rem  paid a Python interpreter startup (~150-300ms) even when the WAF
rem  was switched off. cmd is the AutoRun main channel, so an AI doing
rem  a batch of curls felt that on every call. The bash shim already
rem  had this check (_waf_active); cmd did not.
rem
rem  Order matters -- do NOT move these lines:
rem    1. WAF_ALWAYS_ON must run the shim first. Tests and "force on"
rem       rely on it; checking the heartbeat first would silently
rem       downgrade forced-on to pass-through.
rem    2. WAF_DISABLE is the documented single-command escape hatch.
rem    3. Only when both are unset, an absent heartbeat file proves the
rem       console is not running (wafctl off / stop deletes the file,
rem       see state.deactivate), so there is nothing to intercept.
rem
rem  A stale-but-present heartbeat (console crashed) still goes through
rem  Python -- curlshim.py re-checks freshness and passes through.
rem  That costs one startup in an abnormal state, which is acceptable;
rem  guessing freshness in batch would need another process anyway.
if "%WAF_ALWAYS_ON%"=="1" goto :need_python
if "%WAF_DISABLE%"=="1" goto :passthrough
if not exist "%WAF_ROOT%\data\run\active.json" goto :passthrough

:need_python
rem --- cache missing or stale: run the exhaustive search ---
if not defined WAF_PY call "%~dp0_find-python.cmd" >nul 2>nul

if defined WAF_PY goto :run

echo [agent-waf] Python not found. Install Python 3.7+ then re-run install.bat 1>&2
echo [agent-waf] Falling back to the real curl so your command still works. 1>&2
goto :passthrough

:passthrough
rem WAF not intercepting: hand over to the real curl, zero WAF overhead.
if defined WAF_CURL "%WAF_CURL%" %*
if defined WAF_CURL exit /b %ERRORLEVEL%
echo [agent-waf] real curl path unknown; re-run install.bat to record it 1>&2
exit /b 127

:run
"%WAF_PY%" "%WAF_ROOT%\waf\curlshim.py" %*
exit /b %ERRORLEVEL%
