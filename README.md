# ys-sec

> **Modular Security & Network Auditing Framework**  
> Developed in **Yolish** by **Exploidus Labs**  
> Repository: https://github.com/Exploidus/ys-sec

---

## Overview

`ys-sec` is a modular, zero-dependency network auditing, reconnaissance, and security qualification toolkit written natively in the [Yolish Programming Language](https://github.com/rahadbhuiya/Yolish) for [Exploidus OS](https://github.com/rahadbhuiya/Exploidus), Linux, and Windows.

Unlike conventional security tools that depend on heavy external runtimes (Python, Node.js) or shell wrappers (PowerShell, Bash), `ys-sec` compiles into standalone native executables (`.fozu` on Exploidus OS, `.exe` on Windows, and static ELF on Linux) with zero runtime dependencies.

---

## Architectural Highlights

- **Pure Native Sockets**: Direct TCP/UDP socket connections, connection timeouts, and packet math implemented natively in Yolish without external subprocesses.
- **Dual Architecture (Tool + Framework)**:
  - **As a CLI Tool**: Ready-to-use commands for fast port scanning, banner grabbing, and HTTP security auditing.
  - **As a Framework**: Importable modules for writing custom security automation scripts in Yolish.
- **Exploidus Kernel Security Auditing**: The exclusive security toolkit equipped to audit Exploidus OS kernel subsystems, including BLAKE3 capability token verification, CNSL (Correlated Network Security Layer) attack tables, and File Integrity Monitoring (FIM).
- **Single-Binary Portability**: Native compilation target support (`ys -c ys-sec.y --target exploidus` -> `ys-sec.fozu`).

---

## Modules & Capabilities

| Module | Description | Supported Platforms |
|---|---|---|
| `portscan` | Fast TCP port scanner supporting single ports, ranges, and common service identification | Windows, Linux, Exploidus OS |
| `banner` | Active service banner grabbing and protocol version fingerprinting (SSH, HTTP, FTP, SMTP, MySQL, Redis) | Windows, Linux, Exploidus OS |
| `headers` | Web security header auditing: inspects CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and CORS | Windows, Linux, Exploidus OS |
| `http` | Zero-dependency HTTP protocol inspector and latency analyzer | Windows, Linux, Exploidus OS |
| `subnet` | IPv4 CIDR calculation, broadcast analysis, host enumeration, and live host sweeps (`subnet-scan`) | Windows, Linux, Exploidus OS |
| `whois` | Pure native TCP port 43 WHOIS client querying IANA resolvers directly | Windows, Linux, Exploidus OS |
| `dns` | DNS record queries and resolver verification | Windows, Linux, Exploidus OS |
| `cap-audit` | Exploidus OS BLAKE3 capability token boundary audit & delegation verification | Exploidus OS, Windows, Linux |
| `cnsl-audit` | Exploidus kernel CNSL (Correlated Network Security Layer) attack table and honeypot inspector | Exploidus OS, Windows, Linux |
| `fim-audit` | Exploidus File Integrity Monitor (FIM) verification across 13 critical system paths | Exploidus OS, Windows, Linux |

---

## CLI Usage

### Running via Yolish Interpreter:

```bash
# General help and command list
ys ys-sec.y help

# Fast port scan across range or target
ys ys-sec.y portscan 192.168.1.1 1 1000

# Inspect HTTP security headers
ys ys-sec.y headers https://example.com

# Service banner grab & version fingerprinting
ys ys-sec.y banner 192.168.1.1 22

# Subnet CIDR calculation & live host sweep
ys ys-sec.y subnet 192.168.1.0/24
ys ys-sec.y subnet-scan 192.168.1.0/24 80

# Exploidus OS Kernel & Security Auditing
ys ys-sec.y cap-audit 1
ys ys-sec.y cnsl-audit
ys ys-sec.y fim-audit
```

### Running on Exploidus OS:

```bash
# Executed natively in exploish or terminal
star@exploidus:~$ ys-sec.fozu portscan 10.0.2.2 1 100
star@exploidus:~$ ys-sec.fozu cap-audit
star@exploidus:~$ ys-sec.fozu cnsl-audit
star@exploidus:~$ ys-sec.fozu fim-audit
```

---

## Framework Integration

You can import `ys-sec` modules directly into your own Yolish scripts:

```yolish
import "modules/portscan.y"
import "modules/headers.y"
import "modules/cap_audit.y"

fn main() {
    let host = "192.168.1.1"
    let open_ports = portscan.scan(host, 1, 100)

    if open_ports.contains(80) {
        y.println("[ALERT] HTTP detected, analyzing security headers...")
        headers.audit("http://" + host)
    }

    cap_audit.verify_boundary()
}
```

---

## Roadmap & Milestones

All milestones are fully implemented and qualified:

- [x] **Milestone 1 (v0.2.0)**: Pure Native Sockets & CLI Migration (zero PowerShell dependency)
- [x] **Milestone 2 (v0.3.0)**: Active Service Fingerprinting, Protocol Probes & Live Subnet Sweeps
- [x] **Milestone 3 (v0.4.0)**: Exploidus OS Kernel, BLAKE3 Capability & CNSL/FIM Auditor
- [x] **Milestone 4 (v1.0.0)**: Automated Multi-Platform CI/CD & Production Unified Dispatcher

See [MILESTONES.md](MILESTONES.md) for full engineering specifications.

---

## Security Disclaimer

`ys-sec` is developed for authorized system administration, defensive verification, and educational security research. Only scan and audit systems you own or have explicit written authorization to test.

---

## License & Commercial Inquiries

`ys-sec` is dual-licensed under open-source and commercial terms:

### 1. Open Source (GNU AGPLv3 or Later)
For open-source projects, community auditing, security researchers, and educational exploration, `ys-sec` is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**.
Under this license, any network scanner, cloud vulnerability assessment platform, hosted security auditor, or remote verification service that incorporates, modifies, or runs `ys-sec` over a network must provide complete source code under AGPL-3.0-or-later to users interacting with it remotely. See [LICENSE](LICENSE) for the full text.

### 2. Proprietary Commercial License
For cybersecurity vendors, Managed Security Service Providers (MSSPs), enterprise vulnerability management suites, hardware security appliance manufacturers, and proprietary DevSecOps platforms that wish to embed `ys-sec` modules into proprietary closed-source solutions without AGPL-3.0 copyleft obligations:
- Commercial licenses are available without copyleft requirements.
- Includes custom Yolish auditing module development, dedicated API bindings, and priority support.
- For commercial licensing terms and enterprise inquiries, contact: **`rahadbhuiya2021@gmail.com`**.
