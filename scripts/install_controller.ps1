<#
.SYNOPSIS
Cross-Platform Windows CLI Installer for QKD-SDWAN Central Controller

.DESCRIPTION
Installs the portable QKD-SDWAN Central Controller (.pyz bundle, CLI Dashboard,
token manager, and Windows scheduled task launcher).
#>

[CmdletBinding()]
param(
    [string]$Prefix = "$env:ProgramData\qkd-sdwan-controller",
    [string]$BindHost = "0.0.0.0",
    [int]$Port = 8080,
    [string]$SubnetPrefix = "10.200.0.",
    [string]$BootstrapToken = "",
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

if (-not $NonInteractive -and [Environment]::UserInteractive) {
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host " QKD-SDWAN Central Controller — Interactive Windows CLI Installer Wizard" -ForegroundColor Cyan
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

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

Write-Host "[1/4] Checking Python runtime on Windows..." -ForegroundColor Yellow
$PythonCmd = "python"
if (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonCmd = "py -3"
} elseif (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3 is required but not found in PATH."
    exit 1
}
Write-Host "      Python Command: $PythonCmd"

Write-Host "[2/4] Preparing directories under $Prefix..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "$Prefix\bin", "$Prefix\etc", "$Prefix\lib" | Out-Null

$PyzSrc = ""
if (Test-Path "$ScriptDir\qkd-sdwan-controller.pyz") {
    $PyzSrc = "$ScriptDir\qkd-sdwan-controller.pyz"
} elseif (Test-Path "$RepoRoot\dist\qkd-sdwan-controller.pyz") {
    $PyzSrc = "$RepoRoot\dist\qkd-sdwan-controller.pyz"
} elseif (Test-Path "$RepoRoot\scripts\build_installers.py") {
    & python "$RepoRoot\scripts\build_installers.py" | Out-Null
    $PyzSrc = "$RepoRoot\dist\qkd-sdwan-controller.pyz"
}

$PyzDest = "$Prefix\lib\qkd-sdwan-controller.pyz"
if ($PyzSrc -and (Test-Path $PyzSrc)) {
    Copy-Item -Force $PyzSrc $PyzDest
}

Write-Host "[3/4] Generating cluster HMAC secret, bootstrap Join Token, and controller.json..." -ForegroundColor Yellow
$ConfigPath = "$Prefix\etc\controller.json"
$TokenCode = @"
import json, secrets, time
token = '$BootstrapToken'.strip() or ('qkd-join-' + secrets.token_hex(12))
secret_hex = secrets.token_hex(32)
cfg = {
    'host': '$BindHost',
    'port': int('$Port'),
    'overlay_subnet_prefix': '$SubnetPrefix',
    'cluster_hmac_secret_hex': secret_hex,
    'bootstrap_join_token': token,
    'generated_at': time.time(),
}
with open(r'$ConfigPath', 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2)
print(token)
"@

$BootstrapTokenActual = & python -c $TokenCode

Write-Host "[4/4] Generating CLI wrappers and Scheduled Task installer..." -ForegroundColor Yellow
$BatchWrapper = "$Prefix\bin\qkd-sdwan-controller.bat"
@"
@echo off
set PYTHONPATH=$PyzDest;$RepoRoot;%PYTHONPATH%
python -m qkd_sdwan.controller.cli --config "$ConfigPath" %*
"@ | Set-Content -Path $BatchWrapper -Encoding ASCII

Copy-Item -Force $BatchWrapper "$Prefix\bin\qkd-sdwan-ctl.bat"

$Ps1Wrapper = "$Prefix\bin\qkd-sdwan-controller.ps1"
@"
`$env:PYTHONPATH = "$PyzDest;$RepoRoot;`$env:PYTHONPATH"
python -m qkd_sdwan.controller.cli --config "$ConfigPath" @args
"@ | Set-Content -Path $Ps1Wrapper -Encoding UTF8

$TaskScript = "$Prefix\register-windows-service.ps1"
@"
# Run as Administrator to register startup task
schtasks.exe /Create /TN "QKD-SDWAN-Controller" /TR "$BatchWrapper serve" /SC ONSTART /RU "SYSTEM" /F
Write-Host "[+] QKD-SDWAN Controller registered as Windows ONSTART task"
"@ | Set-Content -Path $TaskScript -Encoding UTF8

Write-Host "`n[OK] QKD-SDWAN Central Controller installed successfully on Windows:" -ForegroundColor Green
Write-Host "     Configuration       : $ConfigPath"
Write-Host "     Portable Bundle     : $PyzDest"
Write-Host "     Batch CLI Wrapper   : $BatchWrapper"
Write-Host "     PowerShell Wrapper  : $Ps1Wrapper"
Write-Host "     Bootstrap Join Token: $BootstrapTokenActual"
Write-Host "     Dashboard Command   : $BatchWrapper dashboard --controller-url http://127.0.0.1:$Port"
