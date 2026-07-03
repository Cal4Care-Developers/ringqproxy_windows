# RingQ Proxy -- Windows Architecture Guide

This mirrors `ARCHITECTURE.md` (Linux/Debian NX Device). The SIP/tunnel
protocol, header rewrites, and authentication model are identical --
same Go binary, same wire behavior. Only the OS integration differs:
process supervision, device identity, firewall, and install tooling.

---

## 1. Authentication Model

Identical to Linux. The Windows PC POSTs to `https://<pbx-domain>:8443/tunnel/bind` with:

```json
{
  "auth_key":         "R1_2T8cPh...",
  "device_id":        "b8258c3d5a4549c189b1ef1333045107",
  "device_public_ip": "43.225.164.198",
  "device_local_ip":  "192.168.10.112"
}
```

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

Both are stable per-machine identifiers that survive reboots and don't
require anything in the YAML.

---

## 2. Network Topology

```
 LAN SIDE (Windows PC)                 INTERNET                CLOUD PBX
 ========================          ==============          =====================
                                                           Firewall
 IP Phones (192.168.x.x)                                  +-----------------+
   Yealink 1007                                           | DNAT:           |
   Yealink 1016                                           | <public>:6010   |
        |                                                 |  -> FS:5060     |
        | UDP/5060                                        +-----------------+
        v                                                          |
  +---------------------+       TCP/6010 (persistent)   +--------v--------+
  | RingQ Proxy (exe)   |================================| RingQ PBX      |
  | Windows 10/11 PC     |  single long-lived connection  | (FreeSWITCH)   |
  | LAN: 192.168.10.112  |  CRLF keepalive every 30s      | (internal)     |
  | Public: 43.225.164.198|                               +-----------------+
  +---------------------+                                          |
  Runs as Windows Service                                  RingQ DB
  "RingQProxy" (via NSSM)                                 tunnel_config table
  Admin API (port 8899)
  Heartbeat -> :8443/tunnel/heartbeat
```

The customer's office PC plays the same role the Linux NX Device plays at
other sites: one always-on box per office, IP phones on the LAN register
through it, it tunnels SIP to the Cloud PBX over a single persistent TCP
connection.

---

## 3. Port Reference

### Windows PC (customer office)

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 5060 | UDP | Inbound | SIP from LAN phones |
| 5061 | TCP | Inbound | SIP from LAN phones (TCP mode) |
| 8899 | TCP | Inbound | Admin API (LAN only) |
| 6010 | TCP | Outbound | SIP tunnel to Cloud PBX |
| 8443 | TCP | Outbound | REST API to Cloud PBX (bind/heartbeat) |
| 443  | TCP | Outbound | HTTPS fallback |

Inbound rules are created by `install.ps1` via `New-NetFirewallRule`
(Windows Defender Firewall) -- the direct equivalent of `iptables` on the
Linux build. Outbound is left to Windows' default allow-outbound policy;
no explicit outbound rules are created unless the office's IT policy
default-denies outbound (uncommon, but see Section 6 if so).

### Cloud PBX

Unchanged from the Linux doc -- same PBX, same ports, regardless of which
OS the NX Device/proxy runs on.

---

## 4. How Data Travels

Registration flow, keepalive flow, outbound call flow, and inbound call
flow are **byte-for-byte identical** to the Linux build -- same Go source,
same SIP message rewriting, same header logic. See `ARCHITECTURE.md`
Section 4 for the full sequence diagrams; nothing here is OS-specific.

---

## 5. Security Layers

| Layer | Mechanism | Where enforced |
|-------|-----------|-----------------|
| Tunnel | auth-key + domain validated via REST API | Proxy startup (`bindDevice`) |
| Tunnel (ongoing) | Heartbeat every 60s; 401/403 (or 200+`status:false`) closes the SIP gate and clears the registry | `heartbeatLoop` |
| SIP Auth | Digest MD5, realm=pbxdomain, per phone | RingQ (PBX-side) |
| Transport | TCP/6010 only, outbound-initiated from the proxy | No inbound hole needed on the office firewall for the tunnel itself |
| Device | `device-id` bound per tunnel, read from Windows registry `MachineGuid` | RingQ DB `tunnel_config` |
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

`New-NetFirewallRule` creates the same three inbound allow rules the
Linux `iptables` script creates:

```powershell
RingQ-phones-udp   Inbound  UDP  5060
RingQ-phones-tcp   Inbound  TCP  5061
RingQ-admin-lan    Inbound  TCP  8899   (RemoteAddress restricted to 192.168.0.0/16, 10.0.0.0/8)
```

---

## 7. Windows-Specific Issues Resolved (worth knowing before touching this again)

These were found and fixed during initial Windows bring-up. Documented
here so the reasoning isn't lost if this code is touched again later.

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
contain spaces.** Passing `-c "C:\Program Files\...\sip-proxy.yaml"` as
a single pre-quoted PowerShell string collided with PowerShell's own
outer auto-quoting (nested quotes aren't supported by Win32's command-line
parser), truncating the path at the first space. Passing each token as a
separate array element didn't fully solve it either, because NSSM's own
`install` command joins trailing arguments with plain spaces, with no
added quoting. The durable fix was structural, not a quoting trick:
**install to a space-free path** (`C:\RingQProxy`), which removes the
entire class of problem rather than working around it.

---

## 8. What Does NOT Need Configuration

Same as Linux -- no STUN server, no VPN/IPSec, no port-forwarding for
phones, no separate UDP hole for PBX->proxy traffic (the TCP/6010 tunnel
handles all directions, outbound-initiated from the proxy).

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
`nssm.exe`), and the three firewall rules. Does not touch phone
provisioning or PBX-side data (registrations expire naturally; delete the
`tunnel_config` entry from the RingQ portal if needed).
