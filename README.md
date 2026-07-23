# RingQ Tunnel -- Windows Architecture Guide

This mirrors `ARCHITECTURE.md` (Linux/Debian NX Device). The SIP/tunnel
protocol, RTP relay logic, header rewrites, and authentication model are
identical -- same Go binary, same wire behavior. Only the OS integration
differs: process supervision, device identity, firewall, and install
tooling.

---

## 1. Authentication Model

Identical to Linux. The Windows PC POSTs to `https://<pbx-domain>:443/tunnel/bind` with:

```json
{
  "auth_key":         "R1_2T8cPh...",
  "device_id":        "b8258c3d5a4549c189b1ef1333045107",
  "device_public_ip": "43.225.164.198",
  "device_local_ip":  "192.168.10.112"
}
```

**API port is 443**, not 8443. Confirmed live in a real deployed config
(`pbx-api-url: "https://sgringq96.ringq.ai:443"`), and both `install.ps1`
and `install-offline.ps1` generate `sip-proxy.yaml` with `:443` by default.

The PBX queries `tunnel_config` on `auth_key + domain`, same as Linux. Wrong
domain -> HTTPS endpoint rejects; wrong auth-key -> DB lookup returns nothing
-> 401/403 -> SIP gate (`tunnelBound`) stays closed -> phones get 503
immediately, same behavior as the Linux build.

**Only difference: how `device_id` is derived.**

| | Linux | Windows |
|---|---|---|
| Source | `/etc/machine-id` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| Set by | systemd at OS install | Windows Setup, at OS install |
| Read by | `readMachineID()` in `util.go` (Linux build) | `readMachineID()` in `util.go` (Windows build, registry version) |
| Config | leave `device-id: ""` blank -- binary self-populates at startup | same |

---

## 2. Network Topology

Two completely separate internet paths exist between the Windows PC and
PBX, same as Linux:
- **TCP/6010**: SIP signalling only (REGISTER, INVITE, 200 OK, BYE, OPTIONS...)
- **UDP direct**: RTP media only -- voice audio, relayed by the proxy itself, does NOT go through TCP/6010

```
 LAN SIDE (Windows PC)              INTERNET                      CLOUD PBX
 ========================       ==============                =====================
                                                              +-----------------------+
 IP Phones (192.168.x.x)                                     | Cloud Security Group  |
   Yealink 1007                                               |                       |
        |                                                     | MUST ALLOW:           |
        | (1) SIP UDP/5060                                    |  TCP 6010 (tunnel)    |
        |     (to Windows PC, LAN only)                       |  TCP 443  (API)       |
        |                                                     |  UDP 16384-32768      |
        | (2) RTP UDP                                         |  FROM <public IP> only|
        |     to 192.168.x.x:40000-41999                      +-----------┬-----------+
        |     (to relay, LAN only, no internet)                           |
        v                                                                 v
  +----------------------+   (3) TCP/6010 ==================>  RingQ PBX (FS)
  | RingQ Proxy (exe)    |===================================  172.16.x.x:5060
  | Windows 10/11 PC     |   (SIP only, all messages)          (SIP signalling)
  | LAN:  192.168.10.112 |
  | WAN:  43.225.164.198 |   (4) UDP direct ------------------> FS RTP port
  |                      |------------------------------------> 16384-32768
  |  SIP proxy           |   src: 43.225.164.198:wanPort        (voice audio)
  |  RTP relay:          |   dst: FS_IP:FS_RTP_port
  |   lanHalf <- phones  |
  |   wanHalf --------->  |
  +----------------------+
  Runs as Windows Service "RingQProxy" (via NSSM)
  Admin API (port 8899)
  Heartbeat -> :443/tunnel/heartbeat
```

**Critical requirement, unchanged from Linux**: if the cloud security
group blocks UDP 16384-32768 from this Windows PC's public IP, RTP path
(4) cannot reach RingQ and there will be no voice. Windows Defender
Firewall rules on this PC alone are not enough -- the **cloud provider's**
firewall/security group must also allow it, same as the Linux doc's
warning.

**RTP firewall rule (cloud security group AND PBX OS level, unchanged from Linux):**
```
UDP  16384-32768  FROM <Windows PC public IP>  -> ALLOW
```
Restrict to this PC's IP only (not 0.0.0.0/0). Only the proxy sends RTP
to the PBX -- phones never send directly to the PBX.

---

## 3. Port Reference

### Windows PC (customer office)

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 5060 | UDP | Inbound | SIP from LAN phones |
| 5061 | TCP | Inbound | SIP from LAN phones (TCP mode) |
| 8899 | TCP | Inbound | Admin API (LAN only) |
| 40000-41999 | UDP | Inbound | RTP relay -- LAN phones send audio here |
| 6010 | TCP | Outbound | SIP tunnel to Cloud PBX |
| 443  | TCP | Outbound | REST API to Cloud PBX (bind/heartbeat) + RingQ portal |
| 40000-41999 | UDP | Outbound | RTP relay -- proxy forwards audio to PBX |

Inbound rules are created by `install.ps1` / `install-offline.ps1` via
`New-NetFirewallRule` (Windows Defender Firewall) -- the direct
equivalent of `nftables`/`iptables` on the Linux build. **All four
inbound rules, including RTP relay, are live in both scripts as of this
revision.**

### Cloud PBX

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 6010 | TCP | Inbound | NX Device / Windows PC tunnel connections |
| 5060 | TCP/UDP | Internal | RingQ SIP (behind firewall) |
| 443  | TCP | Inbound | RingQ REST API |

> RTP media from phones is relayed through the Windows PC proxy, same as
> Linux. The PBX only needs to accept UDP from the proxy's public IP --
> not from all internet.

---

## 4. How Data Travels

Registration flow and keepalive flow are byte-for-byte identical to the
Linux build -- see `ARCHITECTURE.md` Sections 4.1-4.2, nothing OS-specific
there.

Call flow includes RTP relay, not just SIP signalling passthrough -- RTP
no longer bypasses the proxy on either platform.

### 4.1 Outbound Call + RTP Relay (Phone -> PBX)

```
Phone A              Windows PC Proxy (RTP relay)      Cloud PBX (FS)
  |                         |                               |
  |--INVITE SDP(A_IP:A_rtp)->|  Alloc lanPort P1, wanPort P2 |
  |                         |  Rewrite SDP: c=publicIP:P2   |
  |                         |--INVITE SDP(publicIP:P2)----->|
  |                         |                               |-- allocate FS_RTP
  |                         |<--200 OK SDP(FS_IP:FS_RTP)----|
  |                         |  Rewrite SDP: c=LAN_IP:P1     |
  |<--200 OK SDP(LAN_IP:P1)-|  Start relay goroutines       |
  |--ACK------------------->|--ACK-------------------------->|
  |                         |                               |
  |--RTP->LAN_IP:P1(lanHalf)->|->(via wanHalf.conn)->FS_IP:P2->|  phone audio
  |<-RTP<-LAN_IP:P1(wanHalf)<-|<-FS sends to publicIP:P2<-----|  PBX audio
```

### 4.2 Inbound Call + RTP Relay (PBX -> LAN Phone, B-leg)

```
Cloud PBX (FS)      Windows PC Proxy (RTP relay)      LAN Phone B
      |                         |                            |
      |--INVITE SDP(FS_IP:FS_P)->|  Alloc lanPort P3, wanPort P4
      |                         |  Rewrite SDP: c=LAN_IP:P3  |
      |                         |--INVITE SDP(LAN_IP:P3)---->|
      |                         |<--200 OK SDP(B_IP:B_rtp)---|
      |                         |  Start relay goroutines    |
      |<--200 OK SDP(publicIP:P4)|  Rewrite SDP: c=publicIP:P4|
      |--ACK------------------->|--ACK---------------------->|
      |                         |                            |
      |<-RTP<- from publicIP:P4<-|<-(wanHalf P4 receives)<-B-|  phone B audio
      |->RTP-> to LAN_IP:P3 ---->|->(wanHalf.conn P4 forwards)->|  PBX audio
```

> **Cross-socket write** (same mechanism as Linux, unrelated to OS):
> phone audio received on `lanHalf` is forwarded to the PBX using
> `wanHalf.conn` as the source. The PBX always sees one consistent source
> port for both hole-punch and audio, which keeps FS's symmetric-RTP
> handling from redirecting audio away from `wanHalf`.

**Implementation files** (same source tree as Linux, cross-compiled):
`rtprelay.go` (lanHalf/wanHalf socket management), `sdp.go` (SDP parse
and rewrite), `proxy_rtp.go` (the four hooks wiring relay into the SIP
message pipeline: outbound INVITE, inbound INVITE, 200 OK/183 responses,
BYE/CANCEL teardown).

---

## 5. Security Layers

| Layer | Mechanism | Where enforced |
|-------|-----------|-----------------|
| Tunnel | auth-key + domain validated via REST API | Proxy startup (`bindDevice`) |
| Heartbeat | auth-key re-validated every 60s | `heartbeatLoop` |
| Revocation | On 401/403 (or 200+`status:false`): `tunnelBound=0`, registry cleared, OPTIONS dropped -> FS expires registrations within ~92s | Proxy |
| SIP Auth | Digest MD5, realm=pbxdomain, per phone | RingQ (PBX-side) |
| Transport | TCP/6010 only for SIP; RTP via the proxy's relay, not direct | No inbound hole needed on the office firewall for SIP signalling itself |
| Device | `device-id` bound per tunnel, read from Windows registry `MachineGuid` | RingQ DB `tunnel_config` |
| RTP | PBX only accepts RTP from this PC's public IP | PBX-side firewall (cloud security group + OS) |
| Headers | `X-Device-ID` + `X-RingQ-Auth` on all upstream SIP | Proxy rewrite |
| TLS | Forced to TLS 1.2 max, HTTP/2 disabled on the tunnel HTTP client | See Section 7 -- required for reliability on some Windows office networks, not a security downgrade |

---

## 6. Windows Deployment Specifics

### 6.1 Install Layout

```
C:\RingQProxy\
  sipproxy.exe          the proxy binary (pre-built, pushed to repo -- see 6.3)
  sip-proxy.yaml         config (device-id left blank; self-populated at runtime)
  nssm.exe                service wrapper (bundled in repo under tools\)
  version.txt             short commit hash of the installed build
  logs\
    service.log           stdout+stderr, auto-rotated at 10 MB
```

A flat `C:\RingQProxy` path was chosen deliberately -- both `C:\Program
Files\...` and `C:\ProgramData\...` introduce spaces or extra nesting that
have historically tripped up NSSM's own argument handling (see Section 7).
A space-free path removes the entire class of problem.

### 6.2 Service Supervision (NSSM, not native SCM)

`sipproxy.exe` has no native Windows Service Control Manager code built
in -- it's the same binary as the Linux build, just cross-compiled. NSSM
(Non-Sucking Service Manager) wraps it as a real Windows service, playing
the same role `systemd` plays on Linux:

| Linux (systemd) | Windows (NSSM) |
|---|---|
| `Restart=on-failure` | `AppExit Default Restart` |
| `RestartSec=10s` | `AppRestartDelay 10000` |
| `StandardOutput=journal` | `AppStdout` / `AppStderr` -> `logs\service.log` |
| log rotation via journald | `AppRotateFiles` / `AppRotateBytes` (10 MB) |
| `WantedBy=multi-user.target` (auto-start) | `Start SERVICE_AUTO_START` |
| `journalctl -u ringqproxy -f` | `Get-Content logs\service.log -Wait` |
| `systemctl status ringqproxy` | `Get-Service RingQProxy` |
| `systemctl restart ringqproxy` | `Restart-Service RingQProxy` |

### 6.3 Binary Distribution -- Pre-built exe, not Go source

Unlike the Linux installer (which can build from source on the target
machine), the Windows installer's primary path is a **pre-built
`sipproxy.exe` committed to the repo**:

```
Dev machine:  go build -ldflags="-s -w" -o sipproxy.exe .
              git add sipproxy.exe && git commit && git push
Customer PC:  install.ps1 downloads the repo zip, finds sipproxy.exe,
              copies it directly. Go is never installed.
```

Go is only installed on the customer PC as a fallback, if the repo
contains `.go` source files but no compiled exe. In normal operation this
path is never used -- keeps the deployment footprint minimal.

### 6.4 Firewall

`New-NetFirewallRule` creates four inbound allow rules -- the Windows
equivalent of the Linux `nftables`/`iptables` rules, including the RTP
relay rule that a prior revision of this doc was missing:

```powershell
RingQ-phones-udp   Inbound  UDP  5060
RingQ-phones-tcp   Inbound  TCP  5061
RingQ-admin-lan    Inbound  TCP  8899          (RemoteAddress 192.168.0.0/16, 10.0.0.0/8)
RingQ-rtp-relay    Inbound  UDP  40000-41999
```

Present in `install.ps1`, `install-offline.ps1` (the GUI/MSI installer's
config script), and cleaned up correctly by `uninstall.ps1`.

---

## 7. Windows-Specific Issues Resolved (worth knowing before touching this again)

These were found and fixed during Windows bring-up. Documented here so
the reasoning isn't lost if this code is touched again later.

**TLS 1.3 ClientHello blackholed on some office networks.**
Go's `net/http` offers TLS 1.3 by default; on at least one tested office
Wi-Fi/router path, the larger TLS 1.3 `ClientHello` (vs. TLS 1.2) was
silently dropped after the TCP handshake completed -- `curl`/Schannel
were unaffected since they use the OS TLS stack, not Go's own. Fixed by
pinning `MaxVersion: tls.VersionTLS12` on the shared tunnel HTTP client in
`proxy.go`. Not a security downgrade -- TLS 1.2 is still fully secure --
just avoids a handshake size that some network path couldn't handle.

**HTTP/2 also disabled on the same client**, as an additional precaution
alongside the TLS 1.2 pin, since Go offers `h2` via ALPN by default and
the working `curl` comparison only ever negotiated `http/1.1`.

**Windows Defender adds latency to first outbound connections from
freshly-built, unsigned executables.** Since the dev binary is rebuilt
frequently, every rebuild is a "new" unrecognized file to Defender.
Combined with Go's 10s default `TLSHandshakeTimeout`, this alone was
enough to cause spurious "TLS handshake timeout" errors that had nothing
to do with the network. Mitigated with `Add-MpPreference -ExclusionPath`
during development; the installed production binary at `C:\RingQProxy`
sees this far less since it isn't rebuilt on every run.

**NSSM does not add quotes around individual `AppParameters` tokens that
contain spaces.** The durable fix was structural, not a quoting trick:
**install to a space-free path** (`C:\RingQProxy`), which removes the
entire class of problem rather than working around it.

**Banner text bug (found and fixed after RTP relay merge).** Both
`install.ps1` and `uninstall.ps1` briefly had literal Linux `install.sh`
bash script text (`echo -e`, `cat << 'EOF'`) pasted directly inside a
PowerShell here-string, presumably from copying the Linux banner over
without converting it -- this printed garbled bash syntax instead of a
clean banner on every run. Fixed by replacing with plain PowerShell
`Write-Host` text. Worth a quick visual check of console output after any
future copy from the Linux scripts into the Windows ones, since this is
an easy mistake to reintroduce.

---

## 8. What Does NOT Need Configuration

- **No open RTP to the world** -- PBX only needs UDP from this PC's public IP
- **No STUN server** -- proxy detects public IP via the bind API response
- **No OpenVPN / IPSec** -- the TCP/6010 tunnel IS the secure channel
- **No port-forwarding for phones** -- phones talk to the Windows PC on the LAN only

---

## 9. Installation

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Cal4Care-Developers/ringqproxy_windows/master/install.ps1" -OutFile install.ps1

# First install (interactive -- prompts for PBX domain + auth key)
powershell -ExecutionPolicy Bypass -File .\install.ps1

# Re-run after partial failure, or to update -- reuses existing config
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Yes

# Change PBX domain or auth-key
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Reconfigure

# Show every value (ports, IPs, etc.) for manual override
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Advanced -Reconfigure

# Force re-fetch even if the installed build looks current
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Reinstall

# Fully unattended (e.g. from an RMM tool)
powershell -ExecutionPolicy Bypass -File .\install.ps1 -PbxDomain customer.ringq.ai -AuthKey R1_xxxxx -Yes
```

Must be run as Administrator (the script self-checks this via
`#Requires -RunAsAdministrator`).

---

## 10. Uninstall

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Cal4Care-Developers/ringqproxy_windows/master/uninstall.ps1" -OutFile uninstall.ps1
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

Removes the `RingQProxy` service, `C:\RingQProxy` (binary, config, logs,
`nssm.exe`), and all four firewall rules including RTP relay. Does not
touch phone provisioning or PBX-side data (registrations expire
naturally; delete the `tunnel_config` entry from the RingQ portal if
needed).

---

## 11. Status and Troubleshooting (Windows equivalents of the Linux commands)

| Purpose | Linux | Windows |
|---------|-------|---------|
| Live service logs | `journalctl -u ringqproxy -f` | `Get-Content C:\RingQProxy\logs\service.log -Wait` |
| Filter for RTP relay activity | `journalctl ... \| grep -iE "forwarding\|lan.pbx\|wan.phone"` | `Get-Content ... -Wait \| Select-String -Pattern "forwarding","lan.pbx","wan.phone"` |
| Service status | `systemctl status ringqproxy` | `Get-Service RingQProxy` |
| Restart | `systemctl restart ringqproxy` | `Restart-Service RingQProxy` |
| Confirm RTP firewall rule exists | `nft list ruleset \| grep -E "40000\|policy"` | `Get-NetFirewallRule -DisplayName RingQ-rtp-relay` |
| Packet capture (confirm audio flowing) | `tcpdump -n 'udp and src host <IP>'` | `pktmon` or Wireshark -- no direct one-line equivalent; capture on the relay port range and filter by the PBX's IP |
| Manual binary run (debug mode) | `./sipproxy -config sip-proxy.yaml --log-level Debug` | `.\sipproxy.exe -c .\sip-proxy.yaml --log-level Debug` |

PBX-side troubleshooting commands (`fs_cli`, `iptables`, `fail2ban-client`,
etc.) are unchanged regardless of which OS the tunnel endpoint runs on --
see `ARCHITECTURE.md` Section 12 for those, they're identical either way.
