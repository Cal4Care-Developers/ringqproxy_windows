#Requires -RunAsAdministrator
<#
=================================================================================
 RingQ NX Device Proxy -- Windows Installer  v1.0
=================================================================================
 REQUIRED input (2 values only):
   1. PBX Domain     (e.g. customer.ringq.ai)
   2. Tunnel Auth Key (from RingQ portal -> Tunnel Connections)

 Everything else is auto-detected:
   PBX API URL      -> https://<domain>:8443
   PBX Tunnel host  -> <domain>:6010
   LAN IP           -> first non-loopback IPv4 on an active adapter
   Public IP        -> https://api.ipify.org
   Device ID        -> left blank; sipproxy.exe self-populates it from
                        HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
                        at startup (same mechanism as /etc/machine-id on Linux)
   SIP ports        -> UDP/5060, TCP/5061
   Admin port       -> 8899

 Binary source (in priority order):
   1. Pre-built sipproxy.exe committed to the repo root -- copied directly,
      Go is NOT installed or touched at all. This is the expected path:
      build once on a dev machine (go build -o sipproxy.exe) and push the
      exe -- every customer PC just downloads and runs it.
   2. Go source (.go files) with no exe present -- Go is installed on
      demand and the binary is built locally. Fallback only.

 Usage:
   .\install.ps1                                  interactive
   .\install.ps1 -Yes                              non-interactive, reuse existing config
   .\install.ps1 -PbxDomain X -AuthKey Y -Yes      fully scripted (silent deploy)
   .\install.ps1 -Advanced                         show all prompts for manual override
   .\install.ps1 -Reconfigure                      force re-prompt (domain + key)
   .\install.ps1 -Reinstall                        force re-download Go + rebuild

 GitHub : https://github.com/Cal4Care-Developers/ringqproxy_windows.git
 Install: C:\ProgramData\RingQProxy
 Service: RingQProxy (via NSSM, since sipproxy.exe has no native SCM code)
=================================================================================
#>

[CmdletBinding()]
param(
    [string]$PbxDomain,
    [string]$AuthKey,
    [switch]$Yes,
    [switch]$Advanced,
    [switch]$Reconfigure,
    [switch]$Reinstall
)

$ErrorActionPreference = 'Stop'

# ---- Constants --------------------------------------------------------------
$RepoOwner      = "Cal4Care-Developers"
$RepoName       = "ringqproxy_windows"
$RepoUrl        = "https://github.com/$RepoOwner/$RepoName.git"
$InstallDir     = "C:\ProgramData\RingQProxy"
$LogDir         = "$InstallDir\logs"
$BuildDir       = "$env:TEMP\ringqproxy-build"
$ServiceName    = "RingQProxy"
$BinaryName     = "sipproxy.exe"
$ConfigFile     = "$InstallDir\sip-proxy.yaml"
$NssmPath       = "$InstallDir\nssm.exe"
$RollbackBinary = "$InstallDir\$BinaryName.rollback"
$VersionFile    = "$InstallDir\version.txt"
$GoInstallVer   = "1.22.4"
$GoMinMajor     = 1
$GoMinMinor     = 21

# ---- Colour helpers -----------------------------------------------------------
function Info    { param($m) Write-Host "[INFO]  $m" -ForegroundColor Green }
function Warn    { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function ErrMsg  { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }
function Section { param($m) Write-Host "`n--- $m ---" -ForegroundColor Cyan -BackgroundColor Black }
function Ok      { param($m) Write-Host "  OK   $m" -ForegroundColor Green }
function Skip    { param($m) Write-Host "  SKIP $m (already done)" -ForegroundColor DarkCyan }

# ---- Banner -------------------------------------------------------------------
Write-Host @"

  ____  _             ___    _   _ __  __
 |  _ \(_)_ __   __ _/ _ \  | \ | \ \/ /
 | |_) | | '_ \ / _`  | | | | |  \| |\  /
 |  _ <| | | | | (_| | |_| | | |\  |/  \
 |_| \_\_|_| |_|\__, |\__\_\ |_| \_/_/\_\
                |___/
  NX Device Proxy -- Windows Installer v1.0

"@ -ForegroundColor Cyan

# ---- Single-instance lock (Mutex, equivalent to flock) ------------------------
$Mutex = New-Object System.Threading.Mutex($false, "Global\RingQProxyInstallLock")
if (-not $Mutex.WaitOne(0)) {
    ErrMsg "Another install is already running."
    exit 1
}

$InstallPhase = "init"

function Invoke-Rollback {
    param([int]$Code)
    Write-Host ""
    ErrMsg "Failed during: $InstallPhase (exit code: $Code)"
    Remove-Item "$InstallDir\$BinaryName.new" -ErrorAction SilentlyContinue
    if ((Test-Path $RollbackBinary) -and -not (Test-Path "$InstallDir\$BinaryName")) {
        Move-Item $RollbackBinary "$InstallDir\$BinaryName" -Force
        Warn "Restored previous binary from rollback copy"
        Start-Service $ServiceName -ErrorAction SilentlyContinue
    }
    Remove-Item $BuildDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "`nRe-run the installer -- completed steps will be skipped." -ForegroundColor Yellow
}

try {

# =============================================================================
# STEP 1 -- System check
# =============================================================================
Section "System Check"
$InstallPhase = "system-check"

$OS = Get-CimInstance Win32_OperatingSystem
Ok "OS: $($OS.Caption) ($($OS.Version))"

$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
if ($Arch -ne "amd64") {
    ErrMsg "Only 64-bit Windows is supported."
    exit 1
}
Ok "Architecture: $Arch"

# Auto-detect LAN IP: first active, non-loopback, non-APIPA IPv4 address
$DetectedLanIp = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {
        $_.IPAddress -notlike "127.*" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.PrefixOrigin -ne "WellKnown" -and
        (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Status -eq "Up"
    } | Select-Object -First 1 -ExpandProperty IPAddress)
if (-not $DetectedLanIp) { $DetectedLanIp = "0.0.0.0" }
Ok "Detected LAN IP: $DetectedLanIp"

# Auto-detect public IP
Info "Detecting public IP..."
$DetectedPublicIp = $DetectedLanIp
try {
    $DetectedPublicIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10)
} catch {
    try {
        $DetectedPublicIp = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 10)
    } catch {
        Warn "Could not detect public IP -- falling back to LAN IP (fix manually in yaml if wrong)"
    }
}
Ok "Detected Public IP: $DetectedPublicIp"

# =============================================================================
# STEP 2 -- Read existing config if present (pre-fill on reinstall/update)
# =============================================================================
function Read-YamlValue {
    param([string]$Key, [string]$File)
    if (-not (Test-Path $File)) { return "" }
    $line = Select-String -Path $File -Pattern "^\s*${Key}:" | Select-Object -First 1
    if (-not $line) { return "" }
    if ($line.Line -match "^\s*${Key}:\s*(.*)$") {
        return ($Matches[1] -replace '"', '').Trim()
    }
    return ""
}

$ConfigExists = Test-Path $ConfigFile
$E = @{
    PbxDomain = ""; AuthKey = ""; ApiUrl = ""; TunnelHost = ""; TunnelPort = "";
    LanIp = ""; PublicIp = ""; UdpPort = ""; TcpPort = ""; AdminPort = ""
}
if ($ConfigExists) {
    $E.PbxDomain  = Read-YamlValue "pbx-domain" $ConfigFile
    $E.AuthKey    = Read-YamlValue "auth-key" $ConfigFile
    $E.ApiUrl     = Read-YamlValue "pbx-api-url" $ConfigFile
    $backendLine  = Select-String -Path $ConfigFile -Pattern 'address:\s*"tcp://' | Select-Object -First 1
    if ($backendLine) {
        if ($backendLine.Line -match 'tcp://([^:]+):(\d+)') {
            $E.TunnelHost = $Matches[1]; $E.TunnelPort = $Matches[2]
        }
    }
    $addrLine = Select-String -Path $ConfigFile -Pattern '^\s*address:\s*"' | Select-Object -First 1
    if ($addrLine -and ($addrLine.Line -match '"([^"]+)"')) { $E.LanIp = $Matches[1] }
    $viaLine = Select-String -Path $ConfigFile -Pattern 'via:\s*"udp://' | Select-Object -First 1
    if ($viaLine -and ($viaLine.Line -match 'udp://([^:]+):')) { $E.PublicIp = $Matches[1] }
    $E.UdpPort   = Read-YamlValue "udp-port" $ConfigFile
    $E.TcpPort   = Read-YamlValue "tcp-port" $ConfigFile
    $adminLine = Select-String -Path $ConfigFile -Pattern 'addr:' | Select-Object -First 1
    if ($adminLine -and ($adminLine.Line -match ':(\d+)"')) { $E.AdminPort = $Matches[1] }
    Info "Existing config found: will pre-fill values"
}

# =============================================================================
# STEP 3 -- Configuration prompts (minimal: domain + auth key only)
# =============================================================================
Section "Configuration"
$InstallPhase = "config-input"

if ($Yes -and $ConfigExists -and -not $Reconfigure -and -not $PbxDomain -and -not $AuthKey) {
    $FinalPbxDomain = $E.PbxDomain
    $FinalAuthKey   = $E.AuthKey
    Write-Host "  Using existing configuration (-Yes). Use -Reconfigure to change." -ForegroundColor Cyan
} else {
    Write-Host "  Enter PBX Domain and Auth Key. All other values are auto-detected." -ForegroundColor Cyan
    if ($Advanced) { Write-Host "  Advanced mode: all values will be shown for override." -ForegroundColor Yellow }
    Write-Host ""

    if ($PbxDomain) {
        $FinalPbxDomain = $PbxDomain
    } elseif ($Yes -and $E.PbxDomain) {
        $FinalPbxDomain = $E.PbxDomain
        Write-Host "  [auto] PBX Domain: $FinalPbxDomain" -ForegroundColor Yellow
    } else {
        $hint = if ($E.PbxDomain) { " [$($E.PbxDomain)]" } else { "" }
        $FinalPbxDomain = Read-Host "  PBX Domain (e.g. customer.ringq.ai)$hint"
        if (-not $FinalPbxDomain) { $FinalPbxDomain = $E.PbxDomain }
        if (-not $FinalPbxDomain) { ErrMsg "PBX Domain is required"; exit 1 }
    }

    if ($AuthKey) {
        $FinalAuthKey = $AuthKey
    } elseif ($Yes -and $E.AuthKey) {
        $FinalAuthKey = $E.AuthKey
        Write-Host "  [auto] Auth Key: $($FinalAuthKey.Substring(0,[Math]::Min(12,$FinalAuthKey.Length)))..." -ForegroundColor Yellow
    } else {
        $hint = if ($E.AuthKey) { " [$($E.AuthKey.Substring(0,[Math]::Min(12,$E.AuthKey.Length)))...]" } else { "" }
        $FinalAuthKey = Read-Host "  Tunnel Auth Key (from RingQ portal)$hint"
        if (-not $FinalAuthKey) { $FinalAuthKey = $E.AuthKey }
        if (-not $FinalAuthKey) { ErrMsg "Auth Key is required"; exit 1 }
    }
}

Write-Host ""

# Smart defaults derived from domain
$AutoApiUrl     = if ($E.ApiUrl)     { $E.ApiUrl }     else { "https://${FinalPbxDomain}:8443" }
$AutoTunnelHost = if ($E.TunnelHost) { $E.TunnelHost }  else { $FinalPbxDomain }
$AutoTunnelPort = if ($E.TunnelPort) { $E.TunnelPort }  else { "6010" }
$AutoLanIp      = if ($E.LanIp)      { $E.LanIp }       else { $DetectedLanIp }
$AutoPublicIp   = if ($E.PublicIp)   { $E.PublicIp }    else { $DetectedPublicIp }
$AutoUdpPort    = if ($E.UdpPort)    { $E.UdpPort }     else { "5060" }
$AutoTcpPort    = if ($E.TcpPort)    { $E.TcpPort }     else { "5061" }
$AutoAdminPort  = if ($E.AdminPort)  { $E.AdminPort }   else { "8899" }

if ($Advanced) {
    Write-Host "  Advanced: press Enter to accept auto-detected value, or type new value.`n" -ForegroundColor Yellow
    function Ask-Adv { param($Label, $Default)
        $v = Read-Host "  $Label [$Default]"
        if ($v) { return $v } else { return $Default }
    }
    $ApiUrl     = Ask-Adv "PBX API URL"             $AutoApiUrl
    $TunnelHost = Ask-Adv "PBX Tunnel host/IP"      $AutoTunnelHost
    $TunnelPort = Ask-Adv "PBX Tunnel TCP port"     $AutoTunnelPort
    $LanIp      = Ask-Adv "NX Device LAN listen IP" $AutoLanIp
    $PublicIp   = Ask-Adv "NX Device Public IP"     $AutoPublicIp
    $UdpPort    = Ask-Adv "UDP SIP port for phones" $AutoUdpPort
    $TcpPort    = Ask-Adv "TCP SIP port for phones" $AutoTcpPort
    $AdminPort  = Ask-Adv "Admin API port"          $AutoAdminPort
} else {
    $ApiUrl = $AutoApiUrl; $TunnelHost = $AutoTunnelHost; $TunnelPort = $AutoTunnelPort
    $LanIp = $AutoLanIp; $PublicIp = $AutoPublicIp
    $UdpPort = $AutoUdpPort; $TcpPort = $AutoTcpPort; $AdminPort = $AutoAdminPort
}

Write-Host ""
Write-Host "  Configuration:" -ForegroundColor Cyan
Write-Host "    PBX Domain    : $FinalPbxDomain" -ForegroundColor Yellow
Write-Host "    Auth Key      : $($FinalAuthKey.Substring(0,[Math]::Min(16,$FinalAuthKey.Length)))..." -ForegroundColor Yellow
Write-Host "    PBX API URL   : $ApiUrl" -ForegroundColor Yellow
Write-Host "    PBX Tunnel    : tcp://${TunnelHost}:${TunnelPort}" -ForegroundColor Yellow
Write-Host "    NX LAN IP     : $LanIp" -ForegroundColor Yellow
Write-Host "    NX Public IP  : $PublicIp" -ForegroundColor Yellow
Write-Host "    Phone ports   : UDP/$UdpPort  TCP/$TcpPort" -ForegroundColor Yellow
Write-Host "    Device ID     : (auto -- read from registry MachineGuid at startup)" -ForegroundColor Yellow

if (-not $Yes) {
    Write-Host ""
    $confirm = Read-Host "  Proceed with installation? [Y/n]"
    if ($confirm -eq "n") { Info "Aborted."; exit 0 }
}

# =============================================================================
# STEP 4 -- Install directory
# =============================================================================
Section "Install Directory"
$InstallPhase = "directory"

if (Test-Path $InstallDir) {
    Skip "Directory $InstallDir exists"
} else {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Ok "Created: $InstallDir"
}
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# =============================================================================
# STEP 5 -- Fetch and install the binary (zip download -- no git needed on the PC)
# =============================================================================
Section "Fetch Binary"
$InstallPhase = "fetch"

$NeedFetch = $true
$RemoteHash = ""
foreach ($branch in @("master", "main")) {
    try {
        $headers = @{ "User-Agent" = "RingQProxy-Installer" }
        $commitInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/commits/$branch" -Headers $headers -TimeoutSec 15
        $RemoteHash = $commitInfo.sha.Substring(0,7)
        break
    } catch { continue }
}
if (-not $RemoteHash) {
    Warn "Could not query GitHub API for latest commit -- will re-fetch unconditionally"
}
$CurrentVer = if (Test-Path $VersionFile) { Get-Content $VersionFile -Raw } else { "" }
$CurrentVer = $CurrentVer.Trim()

if ($RemoteHash -and ($CurrentVer -eq $RemoteHash) -and (Test-Path "$InstallDir\$BinaryName") -and -not $Reinstall) {
    Skip "Binary already at latest ($CurrentVer)"
    $NeedFetch = $false
} else {
    if ($CurrentVer) { Info "Update: $CurrentVer -> $(if($RemoteHash){$RemoteHash}else{'latest'})" }
    else { Info "Fresh build from $RepoUrl" }
}

if ($NeedFetch) {
    if (Test-Path "$InstallDir\$BinaryName") {
        Copy-Item "$InstallDir\$BinaryName" $RollbackBinary -Force
        Ok "Rollback copy saved"
    }
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    if ($?) { Info "Service stopped" }

    Remove-Item $BuildDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null

    $zipPath = "$env:TEMP\ringqproxy-src.zip"
    $downloaded = $false
    foreach ($branch in @("master", "main")) {
        try {
            Info "Downloading repository (branch: $branch)..."
            Invoke-WebRequest -Uri "https://github.com/$RepoOwner/$RepoName/archive/refs/heads/$branch.zip" `
                -OutFile $zipPath -TimeoutSec 60
            $downloaded = $true
            break
        } catch { continue }
    }
    if (-not $downloaded) { ErrMsg "Could not download source from $RepoUrl (checked main and master branches)"; exit 1 }

    Expand-Archive -Path $zipPath -DestinationPath $BuildDir -Force
    Remove-Item $zipPath -Force
    $SrcDir = (Get-ChildItem $BuildDir -Directory | Select-Object -First 1).FullName
    if (-not $SrcDir) { ErrMsg "Downloaded archive was empty"; exit 1 }
    Ok "Source fetched to $SrcDir"

    # Grab a bundled nssm.exe now, while the repo zip is still on disk --
    # avoids depending on nssm.cc being reachable later (blocked on some
    # office networks). Look in tools\nssm.exe first, then anywhere in repo.
    if (-not (Test-Path $NssmPath)) {
        $bundledNssm = Get-ChildItem -Path $SrcDir -Filter "nssm.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bundledNssm) {
            Copy-Item $bundledNssm.FullName $NssmPath -Force
            Ok "NSSM found bundled in repository -- no external download needed"
        }
    }

    # -- Decide: pre-built exe in repo (preferred, no Go needed), or build
    #    from source as a fallback if only .go files are present --
    $PrebuiltExe = Get-ChildItem -Path $SrcDir -Filter $BinaryName -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($PrebuiltExe) {
        Info "Pre-built $BinaryName found in repository -- copying directly (Go not required)"
        Copy-Item $PrebuiltExe.FullName "$InstallDir\$BinaryName.new" -Force
    } else {
        $GoFileCount = (Get-ChildItem -Path $SrcDir -Filter "*.go" -Recurse -Depth 2 -ErrorAction SilentlyContinue).Count
        if ($GoFileCount -eq 0) {
            ErrMsg "Repository contains neither a pre-built $BinaryName nor Go source files."
            ErrMsg "Push the compiled exe (built with: go build -o $BinaryName) to: $RepoUrl"
            exit 1
        }

        Warn "No pre-built $BinaryName in repository -- falling back to source build ($GoFileCount .go files found)"

        # Go is only installed here, on demand, because the repo had no exe.
        function Test-GoVersionOk {
            $goCmd = Get-Command go -ErrorAction SilentlyContinue
            if (-not $goCmd) { return $false }
            $verStr = (& go version) 2>$null
            if ($verStr -match 'go(\d+)\.(\d+)') {
                $maj = [int]$Matches[1]; $min = [int]$Matches[2]
                return ($maj -gt $GoMinMajor) -or ($maj -eq $GoMinMajor -and $min -ge $GoMinMinor)
            }
            return $false
        }
        if ((Test-GoVersionOk) -and -not $Reinstall) {
            Ok "Go already installed ($(& go version))"
        } else {
            $goMsi = "$env:TEMP\go$GoInstallVer.windows-amd64.msi"
            $goUrl = "https://go.dev/dl/go$GoInstallVer.windows-amd64.msi"
            if (-not (Test-Path $goMsi)) {
                Info "Downloading Go $GoInstallVer for windows-amd64..."
                Invoke-WebRequest -Uri $goUrl -OutFile $goMsi -TimeoutSec 120
            }
            Info "Installing Go $GoInstallVer (silent)..."
            $p = Start-Process msiexec.exe -ArgumentList "/i", "`"$goMsi`"", "/quiet", "/norestart" -Wait -PassThru
            if ($p.ExitCode -ne 0) { ErrMsg "Go MSI install failed (exit $($p.ExitCode))"; exit 1 }
            $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath    = [System.Environment]::GetEnvironmentVariable("Path", "User")
            $env:Path    = "$machinePath;$userPath"
            if (-not (Test-GoVersionOk)) { ErrMsg "Go installed but not found on PATH -- restart the terminal and re-run"; exit 1 }
            Ok "Go $GoInstallVer installed: $(& go version)"
        }

        Info "Building from source..."
        $GoSrc = $SrcDir
        if (-not (Test-Path "$GoSrc\go.mod")) {
            $foundMod = Get-ChildItem -Path $SrcDir -Filter "go.mod" -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($foundMod) {
                $GoSrc = $foundMod.DirectoryName
                Info "Go module found in: $GoSrc"
            } else {
                ErrMsg "No go.mod found in repository -- cannot build"
                exit 1
            }
        }
        Push-Location $GoSrc
        try {
            & go build -ldflags="-s -w" -o "$InstallDir\$BinaryName.new" .
            if ($LASTEXITCODE -ne 0) { throw "go build exited with code $LASTEXITCODE" }
        } finally {
            Pop-Location
        }
    }

    if (-not (Test-Path "$InstallDir\$BinaryName.new")) { ErrMsg "Build produced no executable"; exit 1 }
    $binSize = "{0:N1} MB" -f ((Get-Item "$InstallDir\$BinaryName.new").Length / 1MB)

    Move-Item "$InstallDir\$BinaryName.new" "$InstallDir\$BinaryName" -Force
    if ($RemoteHash) { Set-Content $VersionFile $RemoteHash -NoNewline } else { Set-Content $VersionFile "unknown" -NoNewline }
    Remove-Item $RollbackBinary -Force -ErrorAction SilentlyContinue
    Remove-Item $BuildDir -Recurse -Force -ErrorAction SilentlyContinue

    Ok "Binary installed: $InstallDir\$BinaryName ($binSize, v$(Get-Content $VersionFile -Raw))"
}

# =============================================================================
# STEP 6 -- Configuration file
# =============================================================================
Section "Configuration File"
$InstallPhase = "config-write"

$DesiredCfg = @"
# RingQ NX Device SIP Proxy Configuration
# Generated: $(Get-Date)
# Edit then run: Restart-Service $ServiceName

admin:
  addr: "${LanIp}:${AdminPort}"

proxies:
  - name: "RingQ-Proxy"
    auth-key: "$FinalAuthKey"
    device-id: ""
    pbx-domain: "$FinalPbxDomain"
    pbx-api-url: "$ApiUrl"
    dialog-timeout: 1200
    must-record-route: true
    keep-next-hop-route: "no"

    listens:
      - address: "$LanIp"
        udp-port: $UdpPort
        tcp-port: $TcpPort
        via: "udp://${PublicIp}:${UdpPort}"
        backends:
          - address: "tcp://${TunnelHost}:${TunnelPort}"

    route:
      - dests: ["$TunnelHost"]
        protocol: tcp
        nexthop: "${TunnelHost}:${TunnelPort}"
      - dests: ["default"]
        protocol: tcp
        nexthop: "${TunnelHost}:${TunnelPort}"

    hosts:
      - name: "$TunnelHost"
        ip: "$TunnelHost"
      - name: "$LanIp,$PublicIp"
        ip: "$LanIp"

hosts:
  - name: "$TunnelHost"
    ip: "$TunnelHost"
  - name: "$LanIp,$PublicIp"
    ip: "$LanIp"
"@

$CfgChanged = $true
if (Test-Path $ConfigFile) {
    $existingNorm = (Get-Content $ConfigFile) -notmatch '^# Generated:' -join "`n"
    $desiredNorm  = ($DesiredCfg -split "`n") -notmatch '^# Generated:' -join "`n"
    if ($existingNorm -eq $desiredNorm) { $CfgChanged = $false }
}

if ($CfgChanged) {
    if (Test-Path $ConfigFile) {
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        Copy-Item $ConfigFile "$ConfigFile.bak.$stamp"
        Ok "Previous config backed up"
    }
    Set-Content -Path $ConfigFile -Value $DesiredCfg
    Ok "Config written: $ConfigFile"
} else {
    Skip "Config unchanged"
}

# =============================================================================
# STEP 7 -- NSSM (service wrapper -- sipproxy.exe has no native Windows
#           Service Control Manager code, so NSSM hosts it as a service,
#           same role systemd plays on the Linux build)
# =============================================================================
Section "Service Wrapper (NSSM)"
$InstallPhase = "nssm"

if (-not (Test-Path $NssmPath)) {
    Info "NSSM not bundled in repository -- attempting external download..."
    try {
        $nssmZip = "$env:TEMP\nssm.zip"
        Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $nssmZip -TimeoutSec 30
        $nssmExtract = "$env:TEMP\nssm-extract"
        Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
        $nssmExe = Get-ChildItem -Path $nssmExtract -Filter "nssm.exe" -Recurse |
            Where-Object { $_.FullName -like "*win64*" } | Select-Object -First 1
        Copy-Item $nssmExe.FullName $NssmPath -Force
        Remove-Item $nssmZip, $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
        Ok "NSSM downloaded and installed"
    } catch {
        ErrMsg "Could not reach nssm.cc from this network (blocked or unreachable)."
        ErrMsg ""
        ErrMsg "Fix: commit nssm.exe (win64 build) to tools\nssm.exe in $RepoUrl"
        ErrMsg "     and re-run -- it will be picked up automatically next time."
        ErrMsg ""
        ErrMsg "Or right now: copy a win64 nssm.exe onto this PC as:"
        ErrMsg "     $NssmPath"
        ErrMsg "     then re-run: .\install.ps1 -Yes"
        exit 1
    }
} else {
    Skip "NSSM already present"
}


# =============================================================================
# STEP 8 -- Register / update the Windows service
# =============================================================================
Section "Windows Service"
$InstallPhase = "service"

$serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($serviceExists) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    & $NssmPath remove $ServiceName confirm | Out-Null
    Info "Existing service removed for re-registration"
}

& $NssmPath install $ServiceName "$InstallDir\$BinaryName" "-c" $ConfigFile "--log-level" "Info"
& $NssmPath set $ServiceName AppDirectory $InstallDir
& $NssmPath set $ServiceName DisplayName $ServiceName
& $NssmPath set $ServiceName Description "SIP proxy tunneling LAN IP phones to the RingQ Cloud PBX"
& $NssmPath set $ServiceName Start SERVICE_AUTO_START
& $NssmPath set $ServiceName AppStdout "$LogDir\service.log"
& $NssmPath set $ServiceName AppStderr "$LogDir\service.log"
& $NssmPath set $ServiceName AppRotateFiles 1
& $NssmPath set $ServiceName AppRotateOnline 1
& $NssmPath set $ServiceName AppRotateBytes 10485760
& $NssmPath set $ServiceName AppExit Default Restart
& $NssmPath set $ServiceName AppRestartDelay 10000
& $NssmPath set $ServiceName AppStopMethodSkip 0
& $NssmPath set $ServiceName AppStopMethodConsole 6000
& $NssmPath set $ServiceName AppStopMethodWindow 6000

# Verify AppParameters actually stored the full config path (cheap
# insurance -- ProgramData has no spaces so this should always pass now,
# but fail loudly rather than silently if that ever changes).
$storedParams = & $NssmPath get $ServiceName AppParameters
if ($storedParams -notmatch [regex]::Escape($ConfigFile)) {
    ErrMsg "AppParameters did not store as expected: $storedParams"
    exit 1
}
Ok "Service registered: $ServiceName"
Ok "Verified AppParameters: $storedParams"

# =============================================================================
# STEP 9 -- Firewall rules
# =============================================================================
Section "Firewall"
$InstallPhase = "firewall"

function Add-FwRule {
    param($Name, $Direction, $Protocol, $LocalPort, $RemoteAddress = "Any")
    if (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue) {
        Write-Host "  SKIP firewall rule: $Name" -ForegroundColor DarkCyan
    } else {
        New-NetFirewallRule -DisplayName $Name -Direction $Direction -Protocol $Protocol `
            -LocalPort $LocalPort -RemoteAddress $RemoteAddress -Action Allow | Out-Null
        Ok "Firewall rule: $Name"
    }
}

Add-FwRule "RingQ-phones-udp" "Inbound" "UDP" $UdpPort
Add-FwRule "RingQ-phones-tcp" "Inbound" "TCP" $TcpPort
Add-FwRule "RingQ-admin-lan"  "Inbound" "TCP" $AdminPort @("192.168.0.0/16", "10.0.0.0/8")

# =============================================================================
# STEP 10 -- Start service and verify bind
# =============================================================================
Section "Starting Service"
$InstallPhase = "start"

Start-Service $ServiceName
Start-Sleep -Seconds 4

$svc = Get-Service $ServiceName
if ($svc.Status -ne "Running") {
    ErrMsg "Service not running after start. Log tail:"
    Get-Content "$LogDir\service.log" -Tail 30 -ErrorAction SilentlyContinue
    exit 1
}
Ok "Service is running"

Start-Sleep -Seconds 3
$recent = Get-Content "$LogDir\service.log" -Tail 30 -ErrorAction SilentlyContinue
if ($recent -match "bind successful") {
    Ok "Tunnel authenticated (ONLINE)"
} elseif ($recent -match "bind rejected|auth failed|BLOCKED|auth rejected") {
    Warn "Tunnel auth FAILED -- check auth-key and pbx-domain in:"
    Warn "  $ConfigFile"
    Warn "Fix then: Restart-Service $ServiceName"
} else {
    Info "Bind result pending -- watch: Get-Content `"$LogDir\service.log`" -Wait"
}

# =============================================================================
# Final summary
# =============================================================================
Section "Done"
Write-Host ""
Write-Host "RingQ NX Device Proxy installed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "  Version   : $(if (Test-Path $VersionFile) { Get-Content $VersionFile -Raw } else { 'unknown' })" -ForegroundColor Cyan
Write-Host "  Config    : $ConfigFile" -ForegroundColor Cyan
Write-Host "  Logs      : Get-Content `"$LogDir\service.log`" -Wait" -ForegroundColor Yellow
Write-Host "  Status    : Get-Service $ServiceName" -ForegroundColor Yellow
Write-Host "  Restart   : Restart-Service $ServiceName" -ForegroundColor Yellow
Write-Host "  Re-run    : .\install.ps1 -Yes" -ForegroundColor Yellow
Write-Host "  Re-config : .\install.ps1 -Reconfigure" -ForegroundColor Yellow
Write-Host "  Advanced  : .\install.ps1 -Advanced -Reconfigure" -ForegroundColor Yellow
Write-Host ""
Write-Host "Phone provisioning:" -ForegroundColor White
Write-Host "  SIP Server : $LanIp  (port $UdpPort UDP)" -ForegroundColor Yellow
Write-Host "  SIP Domain : $LanIp" -ForegroundColor Yellow
Write-Host ""

}
catch {
    Invoke-Rollback -Code 1
    throw
}
finally {
    $Mutex.ReleaseMutex() | Out-Null
    $Mutex.Dispose()
}
