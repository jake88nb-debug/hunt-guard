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
#    3. Wrap Invoke-WebRequest / Invoke-RestMethod so they ask the
#       checker (waf/pshook.py) before sending anything.
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

# ============================================================
#  4) Invoke-WebRequest / Invoke-RestMethod interception
# ============================================================
#  Why this exists (measured gap): steps 1-2 only cover "curl". The
#  PowerShell cmdlets are their own HTTP client -- they never touch
#  curl, never touch PATH -- so
#      Invoke-RestMethod -Method Delete -Uri http://t/api/users/1
#  went out completely unchecked. An AI writing PS one-liners is a
#  normal workflow, so that was a real hole.
#
#  How: PowerShell resolves functions before cmdlets, so defining a
#  function named Invoke-RestMethod shadows the built-in cmdlet (and
#  the "irm" alias, which resolves by name to the same function).
#  The function body is generated from the installed cmdlet itself
#  (ProxyCommand.Create), so every parameter keeps working -- no
#  hardcoded parameter list that would break on a different PS version.
#  We only prepend one check call.

$global:HuntGuardPython = $null
$global:HuntGuardHook = Join-Path $wafRoot "waf\pshook.py"
$global:HuntGuardHeartbeat = Join-Path $wafRoot "data\run\active.json"

# Locate the interpreter without assuming python.exe is on PATH:
#   1. env var (set by install.bat / wafctl)
#   2. data\env.cmd cache (written at install time, same file the
#      cmd shim reads)
#   3. whatever PATH has
if ($env:WAF_PYTHON -and (Test-Path -LiteralPath $env:WAF_PYTHON)) {
    $global:HuntGuardPython = $env:WAF_PYTHON
}
if (-not $global:HuntGuardPython) {
    $envCmd = Join-Path $wafRoot "data\env.cmd"
    if (Test-Path -LiteralPath $envCmd) {
        $hit = Select-String -Path $envCmd -Pattern 'set "WAF_PYTHON=(.+)"' -ErrorAction SilentlyContinue
        if ($hit -and $hit.Matches.Count -gt 0) {
            $cand = $hit.Matches[0].Groups[1].Value
            if ($cand -and (Test-Path -LiteralPath $cand)) {
                $global:HuntGuardPython = $cand
            }
        }
    }
}
if (-not $global:HuntGuardPython) {
    foreach ($cand in @("python.exe", "py.exe")) {
        $found = Get-Command $cand -ErrorAction SilentlyContinue
        if ($found) { $global:HuntGuardPython = $found.Source; break }
    }
}

function __HuntGuardBodyText($Body) {
    if ($null -eq $Body) { return "" }
    if ($Body -is [string]) { return $Body }
    if ($Body -is [byte[]]) {
        try { return [System.Text.Encoding]::UTF8.GetString($Body) }
        catch { return "" }
    }
    if ($Body -is [System.Collections.IDictionary]) {
        # form body: build k=v&k2=v2 -- closer to the wire format than
        # Out-String's table, and the scanner sees keys and values.
        $parts = @()
        foreach ($key in $Body.Keys) {
            $parts += ("{0}={1}" -f [string]$key, [string]$Body[$key])
        }
        return ($parts -join "&")
    }
    try { return ($Body | Out-String) } catch { return "" }
}

function __HuntGuardHeaderTable($Headers) {
    $out = @{}
    if ($null -eq $Headers) { return $out }
    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($key in $Headers.Keys) {
            $out[[string]$key] = [string]$Headers[$key]
        }
        return $out
    }
    foreach ($item in @($Headers)) {
        $line = [string]$item
        if ($line -match "^([^:]+):\s*(.*)$") {
            $out[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    return $out
}

function __HuntGuardCheck($Method, $Uri, $Body, $Headers) {
    if (-not $Uri) { return }

    # Fast path, same order as bin\curl.cmd: an explicitly forced-on
    # install (tests) must be checked first, WAF_DISABLE is the
    # documented escape hatch, and only when neither is set does an
    # absent heartbeat file prove the console is not running.
    if ($env:WAF_ALWAYS_ON -ne "1") {
        if ($env:WAF_DISABLE -eq "1") { return }
        if (-not (Test-Path -LiteralPath $global:HuntGuardHeartbeat)) { return }
    }
    if ($env:WAF_DISABLE -eq "1") { return }

    if (-not $global:HuntGuardPython) {
        Write-Warning ("HuntGuard: no Python interpreter found, so " +
            "Invoke-RestMethod / Invoke-WebRequest are NOT being checked.")
        return
    }

    $payload = @{
        method  = [string]$Method
        uri     = [string]$Uri
        body    = __HuntGuardBodyText $Body
        headers = __HuntGuardHeaderTable $Headers
    }
    try {
        $json = $payload | ConvertTo-Json -Compress -Depth 4
    } catch {
        Write-Warning "HuntGuard: could not serialise the request; not checked."
        return
    }

    $json | & $global:HuntGuardPython $global:HuntGuardHook
    $code = $LASTEXITCODE

    if ($code -eq 126) {
        # NOTE: single quotes on purpose -- "$env:WAF_DISABLE" would expand
        # the *current* value (usually empty) into the message, which is
        # how the first version ended up telling users to run "='1'".
        throw ("HuntGuard: request blocked by the interceptor " +
            "(the JSON above says why). To send it anyway, set " +
            'WAF_DISABLE=1 in this session.')
    }
    elseif ($code -ne 0) {
        # A broken checker must not break the user's script -- warn and
        # let the request through (same policy as bin\curl.cmd when
        # Python is missing).
        Write-Warning ("HuntGuard: the checker failed (exit $code); " +
            "this request was allowed without inspection.")
    }
}

function __HuntGuardWrapCmdlet($Name) {
    # Always generate from the **module-qualified** cmdlet:
    #   1. re-loading the profile must not wrap our own wrapper
    #      (Get-Command by bare name would return it)
    #   2. the generated body forwards to
    #      Microsoft.PowerShell.Utility\<name>, i.e. the real cmdlet,
    #      so there is no recursion even after we shadow the name
    $qualified = "Microsoft.PowerShell.Utility\$Name"

    $existing = Get-Command $Name -ErrorAction SilentlyContinue
    if ($existing -and $existing.CommandType -eq "Function") {
        $definition = [string]$existing.Definition
        if ($definition -notmatch "__HuntGuardCheck") {
            Write-Warning ("HuntGuard: you already have a function named " +
                "$Name; the interceptor now wraps it with its own " +
                "function of the same name (yours is no longer called). " +
                "Remove one of them if that is not what you want.")
        }
    }

    try {
        $cmd = Get-Command $qualified -ErrorAction Stop
    } catch {
        return $false
    }
    try {
        $meta = [System.Management.Automation.CommandMetadata]::new($cmd)
        $text = [System.Management.Automation.ProxyCommand]::Create($meta)
    } catch {
        Write-Warning ("HuntGuard: could not generate a wrapper for $Name " +
            "($($_.Exception.Message)); that cmdlet stays unchecked.")
        return $false
    }

    # Prepend the check to the process block. The generated text ends
    # the parameter bindings and starts with a "process" line -- inserting
    # there means $PSBoundParameters and every bound parameter are
    # already available, and the check runs once per pipeline item.
    #
    # Match the line endings tolerantly (\r?\n): ProxyCommand's output
    # uses "\n" on some builds and CRLF on others -- a fixed anchor
    # silently matched nothing on the first try (measured: both cmdlets
    # reported "unexpected proxy layout" and stayed unchecked, which
    # looks exactly like "the interceptor works" until you test a DELETE).
    #
    # If the anchor ever stops matching (a future PS version changing
    # ProxyCommand's output), we must NOT silently install a wrapper
    # that does nothing -- report it instead.
    $check = @'
    $__hgMethod = ''
    $__hgBody = $null
    $__hgHeaders = $null
    if ($PSBoundParameters.ContainsKey('Method')) { $__hgMethod = [string]$PSBoundParameters['Method'] }
    if ($PSBoundParameters.ContainsKey('Body')) { $__hgBody = $PSBoundParameters['Body'] }
    if ($PSBoundParameters.ContainsKey('Headers')) { $__hgHeaders = $PSBoundParameters['Headers'] }
    if ($PSBoundParameters.ContainsKey('Uri')) {
        __HuntGuardCheck -Method $__hgMethod -Uri ([string]$PSBoundParameters['Uri']) -Body $__hgBody -Headers $__hgHeaders
    }
'@

    $m = [regex]::Match($text, "process\r?\n\{\r?\n")
    if (-not $m.Success) {
        Write-Warning ("HuntGuard: unexpected proxy layout for $Name; " +
            "that cmdlet stays unchecked.")
        return $false
    }
    $patched = $text.Insert($m.Index + $m.Length, $check + "`n")

    try {
        $scriptBlock = [scriptblock]::Create($patched)
    } catch {
        Write-Warning ("HuntGuard: generated wrapper for $Name does not " +
            "parse ($($_.Exception.Message)); that cmdlet stays unchecked.")
        return $false
    }

    Set-Item -Path "Function:global:$Name" -Value $scriptBlock -Force
    return $true
}

$wrapped = @()
foreach ($name in @("Invoke-WebRequest", "Invoke-RestMethod")) {
    if (__HuntGuardWrapCmdlet $name) { $wrapped += $name }
}
if ($wrapped.Count -gt 0) {
    Write-Verbose ("HuntGuard: intercepting " + ($wrapped -join ", "))
}
