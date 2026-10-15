@echo off
rem HuntGuard command-line entry (wrapper for wafctl)
rem Finds Python automatically so it works right after unzipping.
rem ASCII-only on purpose; see bin\_find-python.cmd for why.
setlocal
set "WAF_ROOT=%~dp0"

set "WAF_PY="
if exist "%WAF_ROOT%\data\env.cmd" (
  call "%WAF_ROOT%\data\env.cmd" >nul 2>nul
  if defined WAF_PYTHON if exist "%WAF_PYTHON%" set "WAF_PY=%WAF_PYTHON%"
)
if not defined WAF_PY (
  for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined WAF_PY set "WAF_PY=%%i"
  )
)
if not defined WAF_PY (
  for /f "delims=" %%i in ('where py 2^>nul') do (
    if not defined WAF_PY set "WAF_PY=%%i -3"
  )
)
if not defined WAF_PY (
  echo [agent-waf] Python not found. Install Python 3.7+ first. 1>&2
  exit /b 127
)

"%WAF_PY%" "%WAF_ROOT%\waf\cli.py" %*
exit /b %ERRORLEVEL%
