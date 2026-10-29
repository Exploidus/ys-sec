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
| `banner` | Active service banner grabbing and protocol identification (SSH, HTTP, FTP, SMTP) | Windows, Linux, Exploidus OS |
| `headers` | Web security auditing: inspects CSP, HSTS, X-Frame-Options, CORS, and cookie flags | Windows, Linux, Exploidus OS |
| `subnet` | IPv4 CIDR calculation, network/broadcast range analysis, and live host sweeps | Windows, Linux, Exploidus OS |
| `dns` | DNS record queries and resolver verification | Windows, Linux, Exploidus OS |
| `audit` | Exploidus OS BLAKE3 capability boundary audit and kernel security log inspection | Exploidus OS |

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

# Service banner grab
ys ys-sec.y banner 192.168.1.1 22

# Subnet CIDR calculation
ys ys-sec.y subnet 192.168.1.0/24
```

### Running on Exploidus OS:

```bash
# Executed natively in exploish or terminal
star@exploidus:~$ ys-sec.fozu portscan 10.0.2.2 1 100
star@exploidus:~$ ys-sec.fozu audit --capability
```

---

## Framework Integration

You can import `ys-sec` modules directly into your own Yolish scripts:

```yolish
import "modules/portscan.y"
import "modules/headers.y"

fn main() {
    let host = "192.168.1.1"
    let open_ports = portscan.scan(host, 1, 100)

    if open_ports.contains(80) {
        y.println("[ALERT] HTTP detected, analyzing security headers...")
        headers.audit("http://" + host)
    }
}
```

---

## Roadmap & Milestones

Development is tracked across four phased milestones:

- **Milestone 1 (v0.2.0)**: Pure Native Sockets & CLI Migration (zero PowerShell dependency)
- **Milestone 2 (v0.3.0)**: Active Service Fingerprinting & Protocol Probes
- **Milestone 3 (v0.4.0)**: Exploidus OS Kernel & Capability Auditor
- **Milestone 4 (v1.0.0)**: Standalone Native Binary Compilation (.fozu / .exe / ELF)

See [MILESTONES.md](MILESTONES.md) and the [GitHub Milestones](https://github.com/Exploidus/ys-sec/milestones) for real-time progress.

---

## Security Disclaimer

`ys-sec` is developed for authorized system administration, defensive verification, and educational security research. Only scan and audit systems you own or have explicit written authorization to test.

---

## License

MIT License. Copyright (c) 2026 Rahad Bhuiya / Exploidus Labs.
