@echo off
rem ============================================================
rem  HuntGuard - one-click uninstaller (double-click this file)
rem
rem  Removes every hook the installer put outside this folder:
rem    * cmd AutoRun (registry value)
rem    * BASH_ENV (registry value + ~/.bashrc pointer)
rem    * PowerShell profile (one pointer line)
rem    * PYTHONPATH / HUNTGUARD_HOME / AGENTWAF_HOME (user env)
rem    * PATH entries pointing here (user + machine)
rem  Then it re-checks the final state and tells you if anything
rem  is left (a machine-level PATH needs an admin shell).
rem
rem  It never touches your files, your targets or your browser.
rem  Everything of ours lives in this folder, so "uninstall" means
rem  removing pointers to it - after that this folder is inert and
rem  you can delete it (this script offers to).
rem
rem  Order matters and is deliberate: ALL questions are asked BEFORE
rem  Python is located. Reason: "call"ing a batch file from a batch
rem  file consumes the inherited stdin (measured), so any "set /p"
rem  after that call reads nothing when the script is driven by
rem  redirected input (automation, tests). Asking first also means a
rem  user who answers Y and only then learns Python is missing has
rem  changed nothing yet.
rem
rem  Non-interactive use (automation / an AI, no keyboard needed):
rem    set WAF_UNINSTALL=yes     uninstall, keep data and folder
rem    set WAF_UNINSTALL=purge   uninstall + delete the data folder
rem    set WAF_UNINSTALL=all     uninstall + delete data + delete folder
rem  (Interactive prompts cannot be driven by a pipe: cmd's "set /p"
rem   swallows the whole redirected buffer on its first call. That is
rem   why the env var exists instead of relying on "echo Y |".)
rem
rem  NOTE: ASCII-only on purpose. cmd.exe reads .cmd files using
rem  the system codepage; non-ASCII bytes corrupt parsing.
rem ============================================================
setlocal
set "WAF_ROOT=%~dp0"
cd /d "%WAF_ROOT%"

rem ---- non-interactive answers (optional) ----
set "_ANS="
set "_DELDATA="
set "_DELDIR="
if /i "%WAF_UNINSTALL%"=="yes"   set "_ANS=Y"
if /i "%WAF_UNINSTALL%"=="purge" set "_ANS=Y" & set "_DELDATA=Y"
if /i "%WAF_UNINSTALL%"=="all"   set "_ANS=Y" & set "_DELDATA=Y" & set "_DELDIR=Y"

echo.
echo   ============================================================
echo    HuntGuard uninstaller
echo   ============================================================
echo.
echo   This removes the interception hooks from your system:
echo.
echo     - cmd AutoRun / PowerShell profile / BASH_ENV
echo     - PYTHONPATH Python hook
echo     - HUNTGUARD_HOME / AGENTWAF_HOME environment variables
echo     - PATH entries that point at this folder
echo.
echo   Your own files and your test targets are not touched.
echo.
if defined _ANS goto :answered
set /p "_ANS=  Type Y to uninstall, anything else to quit: "
if /i not "%_ANS%"=="Y" goto :cancelled

:answered
rem ---- ask about the data folder BEFORE doing anything ----
rem  Data holds the interception log (URLs + payloads), your rules
rem  and the optional MITM CA key. Default is to KEEP it: deletion
rem  is irreversible and has nothing to do with "stop intercepting".
if defined _DELDATA goto :decided_data
if exist "%WAF_ROOT%data" (
  echo.
  echo   The data folder is kept unless you say otherwise:
  echo     %WAF_ROOT%data
  echo     ^(interception log, rules, settings, CA key^)
  echo.
  set /p "_DELDATA=  Delete it as well? Type Y to delete, Enter to keep: "
)

:decided_data
rem ---- ask about this folder itself ----
rem  The answer is recorded now and acted on at the very end (after the
rem  hooks are gone). Guarded deliberately: only when this really is the
rem  install folder (waf\cli.py + README.md + this script present) and it
rem  is not a drive root. A wrong rd /s /q is exactly the kind of
rem  irreversible accident this tool exists to prevent.
if not defined _DELDIR (
  echo.
  set /p "_DELDIR=  Delete this folder too? Type Y to delete, Enter to keep: "
)

rem ---- locate Python (same exhaustive search the installer uses) ----
call "%WAF_ROOT%\bin\_find-python.cmd" >nul 2>nul
if not defined WAF_PY (
  echo.
  echo   [ERROR] Python not found, so the hooks cannot be removed
  echo           automatically. Nothing was changed.
  echo.
  echo   Manual cleanup, in this order:
  echo     1. reg delete "HKCU\Software\Microsoft\Command Processor" /v AutoRun
  echo     2. reg delete "HKCU\Environment" /v BASH_ENV
  echo     3. reg delete "HKCU\Environment" /v HUNTGUARD_HOME
  echo     4. reg delete "HKCU\Environment" /v AGENTWAF_HOME
  echo     5. remove the HuntGuard line from your PowerShell profile
  echo.
  pause
  exit /b 1
)

rem ---- stop the console first (best effort; ignore errors) ----
"%WAF_PY%" "%WAF_ROOT%\waf\cli.py" stop >nul 2>nul

rem ---- remove the hooks ----
if /i "%_DELDATA%"=="Y" (
  echo.
  echo   Removing hooks and data...
  "%WAF_PY%" "%WAF_ROOT%\waf\cli.py" uninstall-path --purge-data
) else (
  echo.
  echo   Removing hooks ^(keeping data^)...
  "%WAF_PY%" "%WAF_ROOT%\waf\cli.py" uninstall-path
)

rem ---- delete this folder if that is what was asked for ----
if /i not "%_DELDIR%"=="Y" goto :done
set "_DIR=%WAF_ROOT:~0,-1%"
if not defined _DIR goto :unsafe
if "%_DIR:~1%"==":" goto :unsafe
if not exist "%_DIR%\waf\cli.py" goto :unsafe
if not exist "%_DIR%\README.md" goto :unsafe
if not exist "%_DIR%\uninstall.bat" goto :unsafe

echo.
echo   Deleting %_DIR% ...
rem  A running cmd cannot delete its own folder: spawn a detached
rem  helper from %TEMP% that waits for us to exit, then removes the
rem  tree and itself.
set "_HELPER=%TEMP%\_huntguard_selfdelete.cmd"
> "%_HELPER%" (
  echo @echo off
  echo cd /d "%%TEMP%%"
  echo ping -n 3 127.0.0.1 ^>nul
  echo rd /s /q "%_DIR%"
  echo if exist "%_DIR%" ^(echo. ^& echo   [WARN] some files are still there - remove the folder by hand. ^& pause^)
  echo del "%%~f0"
)
start "" /min cmd /c "%_HELPER%"
echo   The folder disappears in a couple of seconds.
goto :eof

:unsafe
echo.
echo   [SKIP] This folder does not look like a HuntGuard install folder
echo          (or it sits at a drive root). Delete it by hand.
goto :done

:done
echo.
echo   ============================================================
echo    Uninstalled
echo   ============================================================
echo.
echo   Open a NEW terminal (cmd / Git Bash / PowerShell) so the old
echo   environment variables are gone. In the current window curl
echo   keeps using the interceptor until you do.
echo.
echo   Re-install any time by double-clicking install.bat.
echo.
pause
exit /b 0

:cancelled
echo.
echo   Cancelled, nothing was changed.
echo.
ping -n 4 127.0.0.1 >nul
exit /b 0
