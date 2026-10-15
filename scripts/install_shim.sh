#!/usr/bin/env bash
# HuntGuard: let curl go through the WAF (Git Bash / WSL / Linux / macOS).
#
# Usage:
#   source scripts/install_shim.sh      # current session (recommended)
#   bash scripts/install_shim.sh -p     # persist for future sessions
#
# What "persist" does (all of it is needed, this is the whole point):
#   * ~/.bashrc  -> interactive shells (when you open a terminal yourself)
#   * BASH_ENV   -> **non-interactive** shells, i.e. `bash -c "..."`
#                   This is how AI tools (ZCode / Claude Code / Codex)
#                   run commands. They never read ~/.bashrc, so without
#                   BASH_ENV the interception simply does not happen there.
#
# Note: this only puts our bin/ in front of PATH. Whether a request is
# actually inspected is decided at run time by the heartbeat file, so
# installing this has no effect while the console is closed.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin"
HOOK="$BIN/waf-bash-env.sh"
MARK="# agent-waf curl shim"

if [ ! -f "$HOOK" ]; then
  echo "[agent-waf] ERROR: missing $HOOK" >&2
  return 1 2>/dev/null || exit 1
fi

# The shim must be executable. Git does not store the exec bit on Windows
# checkouts, so a fresh clone/unzip can arrive without it.
chmod +x "$BIN/curl" "$HOOK" "$ROOT/wafctl" 2>/dev/null || true

# ---- current session -------------------------------------------------
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) export PATH="$BIN:$PATH" ;;
esac

if [ "${1:-}" = "-p" ] || [ "${1:-}" = "--persist" ]; then

  # ---- 1) ~/.bashrc : interactive shells -----------------------------
  if [ -f "$HOME/.bashrc" ] && grep -qF "$MARK" "$HOME/.bashrc"; then
    echo "[agent-waf] ~/.bashrc already configured"
  else
    printf '\n%s\n' "export PATH=\"$BIN:\$PATH\"  $MARK" >> "$HOME/.bashrc"
    echo "[agent-waf] ~/.bashrc written (interactive shells)"
  fi

  # ---- 2) BASH_ENV : non-interactive shells (AI tools) --------------
  # Appending to the profile is not enough here: BASH_ENV is a variable,
  # so it has to be exported by the login environment. We write the
  # export into ~/.bashrc AND ~/.profile, and also export it right now
  # so the current session behaves the same.
  export BASH_ENV="$HOOK"
  for rc in "$HOME/.bashrc" "$HOME/.profile"; do
    [ -e "$rc" ] || continue
    if grep -qF "BASH_ENV" "$rc"; then
      echo "[agent-waf] $rc already exports BASH_ENV"
    else
      printf '\n%s\n' "export BASH_ENV=\"$HOOK\"" >> "$rc"
      echo "[agent-waf] $rc written (non-interactive shells)"
    fi
  done
  # ~/.profile may not exist on minimal systems; create it so the
  # non-interactive channel survives a reboot.
  if [ ! -e "$HOME/.profile" ]; then
    printf '%s\n' "export BASH_ENV=\"$HOOK\"" > "$HOME/.profile"
    echo "[agent-waf] ~/.profile created (non-interactive shells)"
  fi

  echo "[agent-waf] New terminals (and AI tool sessions) will pick it up."
else
  echo "[agent-waf] Current session active: PATH first entry = $BIN"
  echo "[agent-waf] To persist: bash scripts/install_shim.sh --persist"
fi

echo ""
echo "Verify (this must print the path inside $BIN):"
echo "  which curl"
echo "  bash -c 'which curl'        # non-interactive = AI tool path"
echo ""
echo "Then the interception itself:"
echo "  curl -s 'http://127.0.0.1/1.php?delete=test.txt'"
