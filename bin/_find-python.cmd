@echo off
rem ============================================================
rem  HuntGuard - locate Python (shared by shims and launchers)
rem
rem  Why this exists: on other people's machines python.exe is
rem  often not on PATH (Store version, only the "py" launcher,
rem  installed deep on another drive...). Without Python the
rem  whole tool cannot start, so we search exhaustively.
rem
rem  Output: sets WAF_PY to a usable Python command.
rem  Usage:  call "%~dp0_find-python.cmd"
rem          then invoke with "%WAF_PY%"
rem
rem  NOTE: ASCII-only on purpose. cmd.exe reads .cmd files using
rem  the system codepage; non-ASCII bytes corrupt parsing.
rem ============================================================
setlocal enabledelayedexpansion

set "WAF_PY="
set "_WAF_ROOT=%~dp0.."

rem --- 1) reuse a previous detection result (fastest, most accurate).
rem     env.cmd is just a list of SET statements, so calling it is
rem     the simplest way to import the detected paths.
if exist "%_WAF_ROOT%\data\env.cmd" (
  if not defined WAF_PY (
    call "%_WAF_ROOT%\data\env.cmd" >nul 2>nul
    if defined WAF_PYTHON if exist "%WAF_PYTHON%" set "WAF_PY=%WAF_PYTHON%"
  )
)

rem --- 2) python on PATH
if not defined WAF_PY (
  for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined WAF_PY set "WAF_PY=%%i"
  )
)

rem --- 3) the "py" launcher
if not defined WAF_PY (
  for /f "delims=" %%i in ('where py 2^>nul') do (
    if not defined WAF_PY set "WAF_PY=%%i -3"
  )
)

rem --- 4) per-user installs (the common case when PATH is unset)
if not defined WAF_PY (
  for %%v in (314 313 312 311 310 39 38 37) do (
    if not defined WAF_PY (
      if exist "%LOCALAPPDATA%\Programs\Python\Python%%v\python.exe" (
        set "WAF_PY=%LOCALAPPDATA%\Programs\Python\Python%%v\python.exe"
      )
    )
  )
)

rem --- 5) system-wide install locations
if not defined WAF_PY (
  for %%d in ("C:\Python314" "C:\Python313" "C:\Python312" "C:\Python311" "C:\Python310" "C:\Python39" "C:\Python38" "C:\Python37" "C:\Program Files\Python314" "C:\Program Files\Python313" "C:\Program Files\Python312" "C:\Program Files\Python311" "C:\Program Files\Python310" "C:\Program Files\Python39" "C:\Program Files\Python38" "D:\Python" "D:\python" "D:\python37" "E:\Python") do (
    if not defined WAF_PY if exist "%%~d\python.exe" set "WAF_PY=%%~d\python.exe"
  )
)

endlocal & set "WAF_PY=%WAF_PY%"
if not defined WAF_PY exit /b 1
exit /b 0
