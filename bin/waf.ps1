# ============================================================
#  HuntGuard PowerShell hook
#
#  Called from profile.ps1 by a one-line pointer:
#      . "$env:HUNTGUARD_HOME\bin\waf.ps1"
#  (the profile also falls back to AGENTWAF_HOME and then to an
#   absolute path, so an upgrade never breaks an existing install)
#
#  All logic lives inside the install folder so that removing the
#  folder removes everything. The external profile keeps just one
#  line pointing here.
#
#  What it does:
#    1. Drop the built-in alias curl -> Invoke-WebRequest.
#       Without this, "curl" never goes through PATH and the
#       interceptor can never match.
#    2. Prepend <root>\bin to PATH.
#
#  NOTE: ASCII-only on purpose. Windows PowerShell 5.1 reads files
#  without a BOM using the system codepage; non-ASCII bytes corrupt
#  parsing and the profile then fails to load silently.
# ============================================================

$wafRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$wafBin = Join-Path $wafRoot "bin"

# 1) Drop the built-in alias curl -> Invoke-WebRequest, otherwise "curl"
#    never resolves through PATH and the interceptor can never match.
#
#    Only remove it when it really is the built-in default. The previous
#    version deleted any alias named curl/wget, which would silently wipe
#    an alias the user defined themselves (e.g. pointing at their own
#    wrapper). Check the definition first.
foreach ($name in @("curl", "wget")) {
    $alias = Get-Alias -Name $name -ErrorAction SilentlyContinue
    if ($alias -and $alias.Definition -eq "Invoke-WebRequest") {
        Remove-Item "Alias:$name" -Force -ErrorAction SilentlyContinue
    }
}

# 2) put the interceptor directory first on PATH
if ($env:PATH -notlike "*$wafBin*") {
    $env:PATH = "$wafBin;" + $env:PATH
}

# 3) If the user has their own curl/wget alias, the interceptor cannot see
#    those calls (an alias wins over PATH). Say so once instead of silently
#    leaving a hole in the protection.
foreach ($name in @("curl", "wget")) {
    $alias = Get-Alias -Name $name -ErrorAction SilentlyContinue
    if ($alias) {
        Write-Warning ("HuntGuard: your '$name' alias points to '" +
            $alias.Definition + "', so calls to '$name' bypass the " +
            "interceptor. Remove it (Remove-Item Alias:$name) or call " +
            "$name.exe directly to be protected.")
    }
}
