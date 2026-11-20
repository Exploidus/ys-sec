-- ys-sec main dispatcher
import "./modules/common.y"
import "./modules/portscan.y"
import "./modules/dns.y"
import "./modules/ping.y"
import "./modules/banner.y"
import "./modules/http.y"
import "./modules/headers.y"
import "./modules/whois.y"
import "./modules/subnet.y"
import "./modules/cap_audit.y"
import "./modules/cnsl_audit.y"
import "./modules/fim_audit.y"

fn main() {
    let cmd = y.env.get("YS_SEC_CMD")

    if y.is_nil(cmd) || cmd == "" {
        help()
        return
    }

    if cmd == "help" { help() return }
    if cmd == "portscan" { portscan() return }
    if cmd == "dns" { dns_lookup() return }
    if cmd == "ping" { ping_host() return }
    if cmd == "banner" { banner_grab() return }
    if cmd == "http" { http_inspect() return }
    if cmd == "headers" { headers_inspect() return }
    if cmd == "whois" { whois_lookup() return }
    if cmd == "subnet" { subnet_info() return }
    if cmd == "subnet-hosts" { subnet_hosts() return }
    if cmd == "subnet-scan" { subnet_scan() return }
    if cmd == "cap-audit" { cap_audit() return }
    if cmd == "cnsl-audit" { cnsl_audit() return }
    if cmd == "fim-audit" { fim_audit() return }

    y.println("Unknown command: " + cmd)
    help()
}

fn help() {
    y.println("ys-sec - Yolish Network & Kernel Security Auditing Toolkit")
    y.println("Author: Rahad Bhuiya / Exploidus Labs")
    y.println("")
    y.println("Network Reconnaissance & Probing:")
    y.println("  ys-sec portscan <host> <start> <end> [--service] [--json] [-o file]")
    y.println("  ys-sec banner <host> <port>")
    y.println("  ys-sec http <url>")
    y.println("  ys-sec headers <url>")
    y.println("  ys-sec dns <host>")
    y.println("  ys-sec whois <domain>")
    y.println("  ys-sec ping <host>")
    y.println("")
    y.println("Subnet Math & Live Sweeps:")
    y.println("  ys-sec subnet <ipv4/cidr> [--json] [-o file]")
    y.println("  ys-sec subnet-hosts <ipv4/cidr>")
    y.println("  ys-sec subnet-scan <ipv4/cidr> [probe_port]")
    y.println("")
    y.println("Exploidus OS Kernel & Subsystem Auditing:")
    y.println("  ys-sec cap-audit [pid]          Audit BLAKE3 capability token boundary")
    y.println("  ys-sec cnsl-audit               Inspect CNSL attack table & blocklist")
    y.println("  ys-sec fim-audit                Verify 13 critical system paths via FIM")
    y.println("")
    y.println("Only scan systems you own or are authorized to test.")
}
