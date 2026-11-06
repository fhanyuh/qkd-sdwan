<#
.SYNOPSIS
Cross-Platform Windows CLI Installer for QKD-SDWAN Endpoint Client

.DESCRIPTION
Installs the portable QKD-SDWAN Endpoint Client (.pyz bundle, CLI client console,
Join Token auto-enrollment, and Windows scheduled task launcher).
#>

[CmdletBinding()]
param(
    [string]$Prefix = "",
    [string]$NodeId = "edge-node-01",
    [string]$OverlayIp = "10.200.0.10",
    [string]$ControllerUrl = "http://127.0.0.1:8080",
    [string]$JoinToken = "",
    [int]$WgPort = 51820,
    [int]$QkdPort = 52820,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

$IsAdmin = $false
try {
    $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsAdmin = $false
}

if (-not $PSBoundParameters.ContainsKey("Prefix") -or [string]::IsNullOrWhiteSpace($Prefix)) {
    if ($IsAdmin) {
        $Prefix = "$env:ProgramData\qkd-sdwan-client"
    } else {
        $Prefix = "$env:LOCALAPPDATA\qkd-sdwan-client"
    }
}

$ExplicitIp = $PSBoundParameters.ContainsKey("OverlayIp")
$HasExplicitConfigFlags = (
    $PSBoundParameters.ContainsKey("Prefix") -or
    $PSBoundParameters.ContainsKey("NodeId") -or
    $PSBoundParameters.ContainsKey("OverlayIp") -or
    $PSBoundParameters.ContainsKey("ControllerUrl") -or
    $PSBoundParameters.ContainsKey("JoinToken") -or
    $PSBoundParameters.ContainsKey("WgPort") -or
    $PSBoundParameters.ContainsKey("QkdPort")
)

if (-not $NonInteractive -and -not $HasExplicitConfigFlags -and [Environment]::UserInteractive) {
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host " QKD-SDWAN Endpoint Client -- Interactive Windows CLI Installer Wizard" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    $p = Read-Host "Installation directory [$Prefix]"
    if ($p) { $Prefix = $p }
    $n = Read-Host "Endpoint Node ID [$NodeId]"
    if ($n) { $NodeId = $n }
    $c = Read-Host "Central Controller URL [$ControllerUrl]"
    if ($c) { $ControllerUrl = $c }
    $j = Read-Host "Enrollment Join Token (optional)"
    if ($j) { $JoinToken = $j }
    if (-not $JoinToken) {
        $ip = Read-Host "Overlay IPv4 address [$OverlayIp]"
        if ($ip) {
            $OverlayIp = $ip
            $ExplicitIp = $true
        }
    }
    $w = Read-Host "WireGuard UDP port [$WgPort]"
    if ($w) { $WgPort = [int]$w }
    $q = Read-Host "BB84 QKD TCP port [$QkdPort]"
    if ($q) { $QkdPort = [int]$q }
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan
}

function Resolve-PythonExe {
    $PrevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $ProbeCode = "import sys; assert sys.version_info >= (3, 11); print(sys.executable)"
        $Candidates = @(
            @{ Exe = "python"; Args = @("-c", $ProbeCode) },
            @{ Exe = "py"; Args = @("-3", "-c", $ProbeCode) },
            @{ Exe = "python3"; Args = @("-c", $ProbeCode) }
        )
        foreach ($cand in $Candidates) {
            $cmd = Get-Command $cand.Exe -ErrorAction SilentlyContinue
            if ($cmd) {
                $out = & $cand.Exe @($cand.Args) 2>$null
                if ($LASTEXITCODE -eq 0 -and $out) {
                    $exePath = ($out | Select-Object -Last 1).ToString().Trim()
                    if ((Test-Path $exePath) -and ($exePath -notlike "*WindowsApps*")) {
                        return $exePath
                    }
                }
            }
        }
        $FallbackGlobs = @(
            "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
            "$env:ProgramFiles\Python3*\python.exe"
        )
        foreach ($glob in $FallbackGlobs) {
            $found = Get-Item $glob -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
            if ($found) {
                $out = & $found.FullName -c $ProbeCode 2>$null
                if ($LASTEXITCODE -eq 0 -and $out) {
                    return $found.FullName
                }
            }
        }
    } finally {
        $ErrorActionPreference = $PrevErr
    }
    return $null
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

Write-Host "[1/4] Checking Python runtime and cryptography dependency on Windows..." -ForegroundColor Yellow
$PythonExe = Resolve-PythonExe
if (-not $PythonExe) {
    Write-Error "Python 3.11+ is required but was not found in PATH (or only the Microsoft Store stub is present)."
    exit 1
}
Write-Host "      Python Executable: $PythonExe"

$PrevErr = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $PythonExe -c "import cryptography" 2>$null
$CryptoCheck = $LASTEXITCODE
$ErrorActionPreference = $PrevErr

if ($CryptoCheck -ne 0) {
    Write-Host "      Installing required Python package 'cryptography'..." -ForegroundColor Yellow
    $ErrorActionPreference = "Continue"
    & $PythonExe -m pip install --disable-pip-version-check cryptography
    if ($LASTEXITCODE -ne 0) {
        & $PythonExe -m pip install --disable-pip-version-check --user cryptography
    }
    & $PythonExe -c "import cryptography" 2>$null
    $VerifyCrypto = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($VerifyCrypto -ne 0) {
        Write-Error "Failed to install or import required Python package 'cryptography'."
        exit 1
    }
}

Write-Host "[2/4] Preparing directories under $Prefix..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "$Prefix\bin", "$Prefix\etc", "$Prefix\lib" | Out-Null

$PyzSrc = ""
if (Test-Path "$ScriptDir\qkd-sdwan-client.pyz") {
    $PyzSrc = "$ScriptDir\qkd-sdwan-client.pyz"
} elseif (Test-Path "$RepoRoot\dist\qkd-sdwan-client.pyz") {
    $PyzSrc = "$RepoRoot\dist\qkd-sdwan-client.pyz"
} elseif (Test-Path "$RepoRoot\scripts\build_installers.py") {
    & $PythonExe "$RepoRoot\scripts\build_installers.py" | Out-Null
    $PyzSrc = "$RepoRoot\dist\qkd-sdwan-client.pyz"
}

$PyzDest = "$Prefix\lib\qkd-sdwan-client.pyz"
if ($PyzSrc -and (Test-Path $PyzSrc)) {
    Copy-Item -Force $PyzSrc $PyzDest
}

Write-Host "[3/4] Generating WireGuard keypair and enrolling with Controller..." -ForegroundColor Yellow
$ConfigPath = "$Prefix\etc\endpoint.json"
$env:PYTHONPATH = "$PyzDest;$RepoRoot;$env:PYTHONPATH"

$InitArgs = @(
    "-m", "qkd_sdwan.client.agent", "init-config",
    "--output", "$ConfigPath",
    "--node-id", "$NodeId",
    "--overlay-ip", "$OverlayIp",
    "--controller-url", "$ControllerUrl",
    "--wg-port", "$WgPort",
    "--qkd-port", "$QkdPort"
)
if (-not [string]::IsNullOrWhiteSpace($JoinToken)) {
    $InitArgs += @("--join-token", "$JoinToken")
}
if ($ExplicitIp) {
    $InitArgs += "--explicit-ip"
}
& $PythonExe @InitArgs
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ConfigPath)) {
    Write-Error "Failed to initialize client configuration at $ConfigPath"
    exit 1
}

Write-Host "[4/4] Generating CLI wrappers, updating User PATH, and creating Scheduled Task script..." -ForegroundColor Yellow
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

$BatchWrapper = "$Prefix\bin\qkd-sdwan-client.bat"
$BatchContent = "@echo off`r`n" +
    "set `"PYTHONPATH=$PyzDest;$RepoRoot;%PYTHONPATH%`"`r`n" +
    "set `"QKD_SDWAN_CLIENT_CONFIG=$ConfigPath`"`r`n" +
    "`"$PythonExe`" -m qkd_sdwan.client.agent --config `"$ConfigPath`" %*`r`n"
[System.IO.File]::WriteAllText($BatchWrapper, $BatchContent, $Utf8NoBom)

Copy-Item -Force $BatchWrapper "$Prefix\bin\qkd-sdwan-agent.bat"

$Ps1Wrapper = "$Prefix\bin\qkd-sdwan-client.ps1"
$Ps1Content = "`$env:PYTHONPATH = `"$PyzDest;$RepoRoot;`$env:PYTHONPATH`"`r`n" +
    "`$env:QKD_SDWAN_CLIENT_CONFIG = `"$ConfigPath`"`r`n" +
    "& `"$PythonExe`" -m qkd_sdwan.client.agent --config `"$ConfigPath`" @args`r`n"
[System.IO.File]::WriteAllText($Ps1Wrapper, $Ps1Content, $Utf8NoBom)

$TaskScript = "$Prefix\register-windows-service.ps1"
$TaskContent = "# Run as Administrator to register startup task`r`n" +
    "schtasks.exe /Create /TN `"QKD-SDWAN-Client`" /TR `"`"$BatchWrapper`"`" /SC ONSTART /RU `"SYSTEM`" /F`r`n" +
    "Write-Host `"[+] QKD-SDWAN Client registered as Windows ONSTART task`"`r`n"
[System.IO.File]::WriteAllText($TaskScript, $TaskContent, $Utf8NoBom)

$BinDir = "$Prefix\bin"
if (($env:PATH -split ";") -notcontains $BinDir) {
    $env:PATH = "$BinDir;$env:PATH"
}
try {
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrWhiteSpace($UserPath)) {
        [Environment]::SetEnvironmentVariable("Path", $BinDir, "User")
    } elseif (($UserPath -split ";") -notcontains $BinDir) {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$BinDir", "User")
    }
} catch {
}
if ($IsAdmin) {
    $PrevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    netsh advfirewall firewall add rule name="QKD-SDWAN Client WG UDP $WgPort" dir=in action=allow protocol=UDP localport=$WgPort >$null 2>&1
    netsh advfirewall firewall add rule name="QKD-SDWAN Client BB84 TCP $QkdPort" dir=in action=allow protocol=TCP localport=$QkdPort >$null 2>&1
    $ErrorActionPreference = $PrevErr
}

Write-Host "`n[OK] QKD-SDWAN Endpoint Client installed successfully on Windows:" -ForegroundColor Green
Write-Host "     Configuration      : $ConfigPath"
Write-Host "     Portable Bundle    : $PyzDest"
Write-Host "     Batch CLI Wrapper  : $BatchWrapper"
Write-Host "     PowerShell Wrapper : $Ps1Wrapper"
Write-Host "     Interactive Console: & `"$BatchWrapper`" console"
Write-Host "     Interactive Dash   : & `"$BatchWrapper`" dashboard"
