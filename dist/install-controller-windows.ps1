<#
.SYNOPSIS
Cross-Platform Windows CLI Installer for QKD-SDWAN Central Controller

.DESCRIPTION
Installs the portable QKD-SDWAN Central Controller (.pyz bundle, CLI Dashboard,
token manager, and Windows scheduled task launcher).
#>

[CmdletBinding()]
param(
    [string]$Prefix = "",
    [string]$BindHost = "0.0.0.0",
    [int]$Port = 8080,
    [string]$SubnetPrefix = "10.200.0.",
    [string]$BootstrapToken = "",
    [switch]$NonInteractive,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"

$IsAdmin = $false
try {
    $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsAdmin = $false
}

if ($IsAdmin) {
    $DefaultPrefix = "$env:ProgramData\qkd-sdwan-controller"
} else {
    $DefaultPrefix = "$env:LOCALAPPDATA\qkd-sdwan-controller"
}
if (-not $PSBoundParameters.ContainsKey("Prefix") -or [string]::IsNullOrWhiteSpace($Prefix)) {
    $Prefix = $DefaultPrefix
}
$HasExplicitConfigFlags = (
    $PSBoundParameters.ContainsKey("Prefix") -or
    $PSBoundParameters.ContainsKey("BindHost") -or
    $PSBoundParameters.ContainsKey("Port") -or
    $PSBoundParameters.ContainsKey("SubnetPrefix") -or
    $PSBoundParameters.ContainsKey("BootstrapToken")
)

if (-not $NonInteractive -and -not $HasExplicitConfigFlags -and [Environment]::UserInteractive) {
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host " QKD-SDWAN Central Controller -- Interactive Windows CLI Installer Wizard" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    $p = Read-Host "Installation directory [$Prefix]"
    if ($p) { $Prefix = $p }
    $h = Read-Host "Controller bind host IP [$BindHost]"
    if ($h) { $BindHost = $h }
    $prt = Read-Host "Controller HTTP port [$Port]"
    if ($prt) { $Port = [int]$prt }
    $sub = Read-Host "Overlay IPv4 /24 prefix [$SubnetPrefix]"
    if ($sub) { $SubnetPrefix = $sub }
    $tok = Read-Host "Bootstrap Join Token (leave blank to auto-generate)"
    if ($tok) { $BootstrapToken = $tok }
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
if (Test-Path "$ScriptDir\qkd-sdwan-controller.pyz") {
    $PyzSrc = "$ScriptDir\qkd-sdwan-controller.pyz"
} elseif (Test-Path "$RepoRoot\dist\qkd-sdwan-controller.pyz") {
    $PyzSrc = "$RepoRoot\dist\qkd-sdwan-controller.pyz"
} elseif (Test-Path "$RepoRoot\scripts\build_installers.py") {
    & $PythonExe "$RepoRoot\scripts\build_installers.py" | Out-Null
    $PyzSrc = "$RepoRoot\dist\qkd-sdwan-controller.pyz"
}

$PyzDest = "$Prefix\lib\qkd-sdwan-controller.pyz"
if ($PyzSrc -and (Test-Path $PyzSrc)) {
    Copy-Item -Force $PyzSrc $PyzDest
}

Write-Host "[3/4] Generating cluster HMAC secret, bootstrap Join Token, and controller.json..." -ForegroundColor Yellow
$ConfigPath = "$Prefix\etc\controller.json"
$env:PYTHONPATH = "$PyzDest;$RepoRoot;$env:PYTHONPATH"
if (Test-Path "$Prefix\bin\qkd-sdwan-controller.bat") {
    $PrevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & "$Prefix\bin\qkd-sdwan-controller.bat" stop 2>$null | Out-Null
    $ErrorActionPreference = $PrevErr
}
$InitArgs = @(
    "-m", "qkd_sdwan.controller.cli", "init-config",
    "--output", "$ConfigPath",
    "--host", "$BindHost",
    "--port", "$Port",
    "--subnet-prefix", "$SubnetPrefix"
)
if (-not [string]::IsNullOrWhiteSpace($BootstrapToken)) {
    $InitArgs += @("--bootstrap-token", "$BootstrapToken")
}
$BootstrapTokenActual = (& $PythonExe @InitArgs | Select-Object -Last 1).ToString().Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ConfigPath)) {
    Write-Error "Failed to generate controller configuration at $ConfigPath"
    exit 1
}

Write-Host "[4/4] Generating CLI wrappers, updating User PATH, and creating Scheduled Task script..." -ForegroundColor Yellow
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

$BatchWrapper = "$Prefix\bin\qkd-sdwan-controller.bat"
$BatchContent = "@echo off`r`n" +
    "set `"PYTHONPATH=$PyzDest;$RepoRoot;%PYTHONPATH%`"`r`n" +
    "set `"QKD_SDWAN_CONTROLLER_CONFIG=$ConfigPath`"`r`n" +
    "`"$PythonExe`" -m qkd_sdwan.controller.cli --config `"$ConfigPath`" %*`r`n"
[System.IO.File]::WriteAllText($BatchWrapper, $BatchContent, $Utf8NoBom)

Copy-Item -Force $BatchWrapper "$Prefix\bin\qkd-sdwan-ctl.bat"
Copy-Item -Force $BatchWrapper "$Prefix\bin\qkd-ctl.bat"

$Ps1Wrapper = "$Prefix\bin\qkd-sdwan-controller.ps1"
$Ps1Content = "`$env:PYTHONPATH = `"$PyzDest;$RepoRoot;`$env:PYTHONPATH`"`r`n" +
    "`$env:QKD_SDWAN_CONTROLLER_CONFIG = `"$ConfigPath`"`r`n" +
    "& `"$PythonExe`" -m qkd_sdwan.controller.cli --config `"$ConfigPath`" @args`r`n"
[System.IO.File]::WriteAllText($Ps1Wrapper, $Ps1Content, $Utf8NoBom)
Copy-Item -Force $Ps1Wrapper "$Prefix\bin\qkd-sdwan-ctl.ps1"
Copy-Item -Force $Ps1Wrapper "$Prefix\bin\qkd-ctl.ps1"
$TaskScript = "$Prefix\register-windows-service.ps1"
$TaskContent = "# Run as Administrator to register startup task`r`n" +
    "schtasks.exe /Create /TN `"QKD-SDWAN-Controller`" /TR `"`"$BatchWrapper`" serve`" /SC ONSTART /RU `"SYSTEM`" /F`r`n" +
    "Write-Host `"[+] QKD-SDWAN Controller registered as Windows ONSTART task`"`r`n"
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
    netsh advfirewall firewall add rule name="QKD-SDWAN Controller TCP $Port" dir=in action=allow protocol=TCP localport=$Port >$null 2>&1
    $ErrorActionPreference = $PrevErr
}

if (($Prefix -eq $DefaultPrefix) -and (-not $NoStart)) {
    $PrevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $BatchWrapper serve --daemon
    $ErrorActionPreference = $PrevErr
}

Write-Host "`n[OK] QKD-SDWAN Central Controller installed successfully on Windows:" -ForegroundColor Green
Write-Host "     Configuration       : $ConfigPath"
Write-Host "     Portable Bundle     : $PyzDest"
Write-Host "     Global CLI Commands : qkd-ctl | qkd-sdwan-controller"
Write-Host "     Bootstrap Join Token: $BootstrapTokenActual"
Write-Host "     Start Background Cmd: qkd-ctl up"
Write-Host "     Stop Background Cmd : qkd-ctl down"
Write-Host "     Dashboard Snapshot  : qkd-ctl dashboard --once"
