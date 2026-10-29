# ys-sec Engineering Milestones & Security Architecture

> **Author**: Rahad Bhuiya  
> **Organization**: Exploidus Labs  
> **Repository**: https://github.com/Exploidus/ys-sec  
> **Status**: Active Master Plan (v0.1.0 -> v1.0.0)

---

## 1. Vision & Architecture Pillars

`ys-sec` is the official network auditing, reconnaissance, and security qualification toolkit written in Yolish for Exploidus OS, Linux, and Windows.

1. **Pure Native Execution**: Zero reliance on external PowerShell, Python, or shell wrappers. All TCP/UDP sockets, protocol handshakes, and packet math are implemented in native Yolish.
2. **Exploidus Capability Auditing**: The only toolkit designed to audit Exploidus OS kernel security subsystems, including BLAKE3 capability tokens, CNSL (Correlated Network Security Layer) attack tables, and File Integrity Monitoring (FIM).
3. **Single Standalone Binary**: Cross-compiled natively into a standalone `.fozu` executable on Exploidus OS, `.exe` on Windows, and static ELF on Linux.

---

## 2. GitHub Milestones & Issue Breakdown

### Milestone 1: Pure Native Sockets & CLI Migration (v0.2.0)
*Target: Eliminate PowerShell/batch wrappers and run pure native Yolish networking.*

- [ ] **Issue #1**: Implement pure native Yolish TCP socket connection without PowerShell.
- [ ] **Issue #2**: Migrate from `YS_SEC_CMD` environment variables to native CLI arguments (`ys ys-sec.y <cmd> <args>`).
- [ ] **Issue #3**: Add multi-port fast range scanner (e.g. `1-1000`, `22,80,443`).

---

### Milestone 2: Active Service Fingerprinting & Protocol Probes (v0.3.0)
*Target: High-speed service version detection, security headers, and CIDR subnet math.*

- [ ] **Issue #4**: Add HTTP/HTTPS security header analyzer (CSP, HSTS, CORS, X-Frame-Options).
- [ ] **Issue #5**: Add service banner grabbing and protocol version extractor (SSH, FTP, SMTP, MySQL).
- [ ] **Issue #6**: Add CIDR subnet math and live host probing in pure Yolish.

---

### Milestone 3: Exploidus OS Kernel & Capability Auditor (v0.4.0)
*Target: Deep kernel security inspection exclusive to Exploidus OS.*

- [ ] **Issue #7**: Add Exploidus BLAKE3 capability token audit module (`modules/cap_audit.y`).
- [ ] **Issue #8**: Add Exploidus kernel CNSL (Correlated Network Security Layer) attack table inspector.
- [ ] **Issue #9**: Add Exploidus File Integrity Monitor (FIM) verification across 13 critical system paths.

---

### Milestone 4: Standalone Native Binary Compilation (v1.0.0)
*Target: Production single-binary distribution with zero external dependencies.*

- [ ] **Issue #10**: Compile `ys-sec` to native `.fozu` executable for Exploidus OS (`ys -c ys-sec.y --target exploidus`).
- [ ] **Issue #11**: Add GitHub Actions CI/CD for multi-platform releases (`.fozu`, `.exe`, ELF).
