#Requires -RunAsAdministrator
<#
=================================================================================
 RingQ NX Device Proxy -- Windows Uninstaller
=================================================================================
 Removes:
   - Windows service RingQProxy (stopped, deleted via NSSM)
   - C:\ProgramData\RingQProxy  (binary, config, logs, nssm.exe)
   - Firewall rules added by install.ps1
   - Go runtime (optional, asked)

 Does NOT remove:
   - Phone provisioning settings on the phones themselves
   - Any data on the Cloud PBX (registrations expire naturally)

 Usage: Right-click -> Run with PowerShell (as Administrator), or:
   powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
=================================================================================
#>

$ErrorActionPreference = 'Stop'

$InstallDir  = "C:\ProgramData\RingQProxy"
$ServiceName = "RingQProxy"
$NssmPath    = "$InstallDir\nssm.exe"

function Info    { param($m) Write-Host "[INFO]  $m" -ForegroundColor Green }
function Warn    { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Section { param($m) Write-Host "`n--- $m ---" -ForegroundColor Cyan }
function Ok      { param($m) Write-Host "  DONE $m" -ForegroundColor Green }
function Skip    { param($m) Write-Host "  SKIP $m (not found)" -ForegroundColor DarkCyan }

Write-Host @"

  ____  _             ___    _   _ __  __
 |  _ \(_)_ __   __ _/ _ \  | \ | \ \/ /
 | |_) | | '_ \ / _`  | | | | |  \| |\  /
 |  _ <| | | | | (_| | |_| | | |\  |/  \
 |_| \_\_|_| |_|\__, |\__\_\ |_| \_/_/\_\
                |___/
  NX Device Proxy -- Windows Uninstaller

"@ -ForegroundColor Red

Write-Host "This will completely remove the RingQ NX Device Proxy from this machine." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Service   : $ServiceName"
Write-Host "  Directory : $InstallDir"
Write-Host ""
$confirm = Read-Host "Are you sure you want to uninstall? [y/N]"
if ($confirm.ToLower() -ne "y") { Info "Aborted -- nothing removed."; exit 0 }
Write-Host ""

$removeGo = (Read-Host "Also remove Go runtime? [y/N]").ToLower() -eq "y"

# =============================================================================
# STEP 1 -- Stop and remove the service
# =============================================================================
Section "Stopping Service"

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        Info "Sending stop signal (allows OFFLINE status to reach PBX)..."
        Stop-Service $ServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 6
        Ok "Service stopped"
    } else {
        Skip "Service $ServiceName was not running"
    }
    if (Test-Path $NssmPath) {
        & $NssmPath remove $ServiceName confirm | Out-Null
        Ok "Service removed from SCM"
    } else {
        sc.exe delete $ServiceName | Out-Null
        Ok "Service removed via sc.exe (nssm.exe was missing)"
    }
} else {
    Skip "Service $ServiceName"
}

# =============================================================================
# STEP 2 -- Remove firewall rules
# =============================================================================
Section "Removing Firewall Rules"

foreach ($name in @("RingQ-phones-udp", "RingQ-phones-tcp", "RingQ-admin-lan")) {
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $name
        Ok "Removed firewall rule: $name"
    } else {
        Skip "Firewall rule: $name"
    }
}

# =============================================================================
# STEP 3 -- Remove install directory
# =============================================================================
Section "Removing Install Directory"

if (Test-Path $InstallDir) {
    Write-Host "  Contents of ${InstallDir}:"
    Get-ChildItem $InstallDir | ForEach-Object { Write-Host "    $($_.Name)" }
    Write-Host ""
    Remove-Item $InstallDir -Recurse -Force
    Ok "Removed: $InstallDir"
} else {
    Skip "$InstallDir (already gone)"
}

# =============================================================================
# STEP 4 -- Go runtime (optional)
# =============================================================================
Section "Go Runtime"

if ($removeGo) {
    $goUninstall = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "Go Programming Language*" }
    if ($goUninstall) {
        Info "Uninstalling Go via MSI..."
        Start-Process msiexec.exe -ArgumentList "/x", $goUninstall.PSChildName, "/quiet", "/norestart" -Wait
        Ok "Go runtime removed"
    } else {
        Skip "Go runtime (not found via MSI registry -- remove manually if installed via zip)"
    }
} else {
    Skip "Go runtime (kept -- you chose not to remove it)"
}

# =============================================================================
# Final summary
# =============================================================================
Section "Uninstall Complete"
Write-Host ""
Write-Host "RingQ NX Device Proxy has been completely removed." -ForegroundColor Green
Write-Host ""
Write-Host "  Removed:" -ForegroundColor Green
Write-Host "    - Windows service $ServiceName (stopped, removed)"
Write-Host "    - Install directory $InstallDir (binary + config + logs)"
Write-Host "    - Firewall rules added by the RingQ installer"
if ($removeGo) { Write-Host "    - Go runtime" }
Write-Host ""
Write-Host "  Not removed:" -ForegroundColor Yellow
Write-Host "    - Phone provisioning settings (change SIP server on each phone manually)"
Write-Host "    - Cloud PBX registrations (will expire naturally within 10 minutes)"
Write-Host "    - Cloud PBX tunnel_config entry (delete from RingQ portal if needed)"
Write-Host ""
Write-Host "  To reinstall later:" -ForegroundColor Cyan
Write-Host "    Invoke-WebRequest -Uri https://raw.githubusercontent.com/Cal4Care-Developers/ringqproxy_windows/main/install.ps1 -OutFile install.ps1"
Write-Host "    powershell -ExecutionPolicy Bypass -File .\install.ps1"
Write-Host ""
