<#
.SYNOPSIS
Cross-Platform Windows CLI Installer for QKD-SDWAN Endpoint Client

.DESCRIPTION
Installs the portable QKD-SDWAN Endpoint Client (.pyz bundle, CLI client console,
Join Token auto-enrollment, and Windows scheduled task launcher).
#>

[CmdletBinding()]
param(
    [string]$Prefix = "$env:ProgramData\qkd-sdwan-client",
    [string]$NodeId = "edge-node-01",
    [string]$OverlayIp = "10.200.0.10",
    [string]$ControllerUrl = "http://127.0.0.1:8080",
    [string]$JoinToken = "",
    [int]$WgPort = 51820,
    [int]$QkdPort = 52820,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

if (-not $NonInteractive -and [Environment]::UserInteractive) {
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host " QKD-SDWAN Endpoint Client — Interactive Windows CLI Installer Wizard" -ForegroundColor Cyan
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
        if ($ip) { $OverlayIp = $ip }
    }
    $w = Read-Host "WireGuard UDP port [$WgPort]"
    if ($w) { $WgPort = [int]$w }
    $q = Read-Host "BB84 QKD TCP port [$QkdPort]"
    if ($q) { $QkdPort = [int]$q }
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
if (Test-Path "$ScriptDir\qkd-sdwan-client.pyz") {
    $PyzSrc = "$ScriptDir\qkd-sdwan-client.pyz"
} elseif (Test-Path "$RepoRoot\dist\qkd-sdwan-client.pyz") {
    $PyzSrc = "$RepoRoot\dist\qkd-sdwan-client.pyz"
} elseif (Test-Path "$RepoRoot\scripts\build_installers.py") {
    & python "$RepoRoot\scripts\build_installers.py" | Out-Null
    $PyzSrc = "$RepoRoot\dist\qkd-sdwan-client.pyz"
}

$PyzDest = "$Prefix\lib\qkd-sdwan-client.pyz"
if ($PyzSrc -and (Test-Path $PyzSrc)) {
    Copy-Item -Force $PyzSrc $PyzDest
}

Write-Host "[3/4] Generating WireGuard keypair and enrolling with Controller..." -ForegroundColor Yellow
$ConfigPath = "$Prefix\etc\endpoint.json"
$ConfigCode = @"
import json, secrets, sys, time, urllib.error, urllib.request
from qkd_sdwan.client.wg_manager import generate_wg_keypair

priv, pub = generate_wg_keypair()
join_token = '$JoinToken'.strip()
ctrl_url = '$ControllerUrl'.rstrip('/')
node_id = '$NodeId'
overlay_ip = '$OverlayIp'
hmac_secret = secrets.token_hex(32)
auth_token_id = 'hmac-sha256-cluster-v1'
enrolled_token_id = None

if join_token:
    try:
        req_data = {
            'join_token': join_token,
            'node_id': node_id,
            'underlay_host': '127.0.0.1',
            'wg_port': int('$WgPort'),
            'qkd_port': int('$QkdPort'),
            'wg_public_key': pub,
            'overlay_ip': overlay_ip if not sys.argv[1] else overlay_ip,
        }
        body = json.dumps(req_data).encode('utf-8')
        req = urllib.request.Request(
            f'{ctrl_url}/api/v1/nodes/enroll',
            data=body,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            overlay_ip = data.get('allocated_overlay_ip', overlay_ip)
            hmac_secret = data.get('cluster_hmac_secret_hex', hmac_secret)
            auth_token_id = data.get('auth_token_id', f'enrolled-{data.get(\"token_id\", \"tok\")}')
            enrolled_token_id = data.get('token_id')
            print(f'      [+] Enrolled {node_id} via Join Token (allocated IP: {overlay_ip})')
    except Exception as exc:
        print(f'      [!] Controller enrollment skipped ({exc}); using standalone keys')

cfg = {
    'node_id': node_id,
    'overlay_ip': overlay_ip,
    'interface_name': 'wg-qkd0',
    'controller_url': ctrl_url,
    'wg_port': int('$WgPort'),
    'qkd_port': int('$QkdPort'),
    'wg_backend_mode': 'USERSPACE_CRYPTO_WG',
    'wg_private_key': priv,
    'wg_public_key': pub,
    'classical_hmac_secret_hex': hmac_secret,
    'cluster_hmac_secret_hex': hmac_secret,
    'auth_token_id': auth_token_id,
    'enrolled_token_id': enrolled_token_id,
    'qber_abort_threshold': 0.11,
    'generated_at': time.time(),
}
with open(r'$ConfigPath', 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2)
"@

& python -c $ConfigCode "explicit"

Write-Host "[4/4] Generating CLI wrappers and Scheduled Task installer..." -ForegroundColor Yellow
$BatchWrapper = "$Prefix\bin\qkd-sdwan-client.bat"
@"
@echo off
set PYTHONPATH=$PyzDest;$RepoRoot;%PYTHONPATH%
python -m qkd_sdwan.client.agent --config "$ConfigPath" %*
"@ | Set-Content -Path $BatchWrapper -Encoding ASCII

Copy-Item -Force $BatchWrapper "$Prefix\bin\qkd-sdwan-agent.bat"

$Ps1Wrapper = "$Prefix\bin\qkd-sdwan-client.ps1"
@"
`$env:PYTHONPATH = "$PyzDest;$RepoRoot;`$env:PYTHONPATH"
python -m qkd_sdwan.client.agent --config "$ConfigPath" @args
"@ | Set-Content -Path $Ps1Wrapper -Encoding UTF8

$TaskScript = "$Prefix\register-windows-service.ps1"
@"
# Run as Administrator to register startup task
schtasks.exe /Create /TN "QKD-SDWAN-Client" /TR "$BatchWrapper" /SC ONSTART /RU "SYSTEM" /F
Write-Host "[+] QKD-SDWAN Client registered as Windows ONSTART task"
"@ | Set-Content -Path $TaskScript -Encoding UTF8

Write-Host "`n[OK] QKD-SDWAN Endpoint Client installed successfully on Windows:" -ForegroundColor Green
Write-Host "     Configuration      : $ConfigPath"
Write-Host "     Portable Bundle    : $PyzDest"
Write-Host "     Batch CLI Wrapper  : $BatchWrapper"
Write-Host "     PowerShell Wrapper : $Ps1Wrapper"
Write-Host "     Interactive Console: $BatchWrapper console"
