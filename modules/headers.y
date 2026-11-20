-- Pure native Yolish HTTP/HTTPS security header analyzer (Zero PowerShell dependency)
fn parse_url_host(raw_url) {
    var u = raw_url
    if y.starts_with(u, "https://") {
        u = y.substr(u, 8, y.len(u))
    } else if y.starts_with(u, "http://") {
        u = y.substr(u, 7, y.len(u))
    }

    var slash_idx = -1
    var i = 0
    let ulen = y.len(u)
    while i < ulen {
        let ch = y.substr(u, i, 1)
        if ch == "/" {
            slash_idx = i
            break
        }
        i = i + 1
    }

    var host_part = u
    if slash_idx != -1 {
        host_part = y.substr(u, 0, slash_idx)
    }

    return host_part
}

fn parse_url_path(raw_url) {
    var u = raw_url
    if y.starts_with(u, "https://") {
        u = y.substr(u, 8, y.len(u))
    } else if y.starts_with(u, "http://") {
        u = y.substr(u, 7, y.len(u))
    }

    var slash_idx = -1
    var i = 0
    let ulen = y.len(u)
    while i < ulen {
        let ch = y.substr(u, i, 1)
        if ch == "/" {
            slash_idx = i
            break
        }
        i = i + 1
    }

    if slash_idx == -1 {
        return "/"
    }
    return y.substr(u, slash_idx, ulen)
}

fn to_lower_char(ch) {
    if ch == "A" { return "a" }
    if ch == "B" { return "b" }
    if ch == "C" { return "c" }
    if ch == "D" { return "d" }
    if ch == "E" { return "e" }
    if ch == "F" { return "f" }
    if ch == "G" { return "g" }
    if ch == "H" { return "h" }
    if ch == "I" { return "i" }
    if ch == "J" { return "j" }
    if ch == "K" { return "k" }
    if ch == "L" { return "l" }
    if ch == "M" { return "m" }
    if ch == "N" { return "n" }
    if ch == "O" { return "o" }
    if ch == "P" { return "p" }
    if ch == "Q" { return "q" }
    if ch == "R" { return "r" }
    if ch == "S" { return "s" }
    if ch == "T" { return "t" }
    if ch == "U" { return "u" }
    if ch == "V" { return "v" }
    if ch == "W" { return "w" }
    if ch == "X" { return "x" }
    if ch == "Y" { return "y" }
    if ch == "Z" { return "z" }
    return ch
}

fn str_to_lower(s) {
    var out = ""
    let slen = y.len(s)
    var i = 0
    while i < slen {
        let ch = y.substr(s, i, 1)
        out = out + to_lower_char(ch)
        i = i + 1
    }
    return out
}

fn headers_inspect() {
    let raw_url = require_env("YS_SEC_A", "URL")
    if y.is_nil(raw_url) || raw_url == "" { return }

    let host = parse_url_host(raw_url)
    let path = parse_url_path(raw_url)
    var port = 80
    if y.starts_with(raw_url, "https://") {
        port = 443
    }

    -- Check for explicit port in host (e.g. host:8080)
    var clean_host = host
    let parts = y.split(host, ":")
    if y.len(parts) == 2 {
        clean_host = parts[0]
        port = y.int(parts[1])
    }

    y.println("Connecting to " + clean_host + ":" + y.str(port) + path + "...")
    let sock = y.net.connect(clean_host, port)
    if sock == -1 {
        y.println("HTTP request failed: connection error (" + y.net.last_error() + ")")
        return
    }

    y.net.set_timeout(sock, 4000)
    let req = "GET " + path + " HTTP/1.1\r\nHost: " + clean_host + "\r\nUser-Agent: ys-sec/0.3.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    y.net.send(sock, req)

    let raw = y.net.recv(sock, 8192)
    y.net.close(sock)

    if y.is_nil(raw) || y.trim(raw) == "" {
        y.println("HTTP request failed: empty response from server")
        return
    }

    let lines = y.split(raw, "\n")
    if y.len(lines) == 0 {
        y.println("HTTP request failed: invalid response")
        return
    }

    let status_line = y.trim(lines[0])
    y.println("Status: " + status_line)
    y.println("")
    y.println("=== HTTP Security Headers Analysis ===")

    var has_hsts = false
    var has_csp = false
    var has_xfo = false
    var has_xcto = false
    var has_rp = false
    var has_pp = false
    var has_cors = false
    var cors_val = ""
    var server_val = ""

    var i = 1
    let num_lines = y.len(lines)
    while i < num_lines {
        let line = y.trim(lines[i])
        if line == "" { break } -- End of headers

        let colon_idx = y.index_of(line, ":")
        if colon_idx != -1 {
            let h_name = str_to_lower(y.trim(y.substr(line, 0, colon_idx)))
            let h_val = y.trim(y.substr(line, colon_idx + 1, y.len(line)))

            if h_name == "strict-transport-security" { has_hsts = true }
            if h_name == "content-security-policy" { has_csp = true }
            if h_name == "x-frame-options" { has_xfo = true }
            if h_name == "x-content-type-options" { has_xcto = true }
            if h_name == "referrer-policy" { has_rp = true }
            if h_name == "permissions-policy" { has_pp = true }
            if h_name == "access-control-allow-origin" { has_cors = true cors_val = h_val }
            if h_name == "server" { server_val = h_val }
        }
        i = i + 1
    }

    var score = 0

    if has_hsts {
        y.println("[PASS] Strict-Transport-Security (HSTS): Enabled")
        score = score + 1
    } else {
        y.println("[WARN] Strict-Transport-Security (HSTS): Missing (Man-in-the-Middle risk)")
    }

    if has_csp {
        y.println("[PASS] Content-Security-Policy (CSP): Configured")
        score = score + 1
    } else {
        y.println("[FAIL] Content-Security-Policy (CSP): Missing (XSS / Injection risk)")
    }

    if has_xfo {
        y.println("[PASS] X-Frame-Options: Configured (Clickjacking protection)")
        score = score + 1
    } else {
        y.println("[WARN] X-Frame-Options: Missing (Clickjacking exposure)")
    }

    if has_xcto {
        y.println("[PASS] X-Content-Type-Options: nosniff active")
        score = score + 1
    } else {
        y.println("[WARN] X-Content-Type-Options: Missing (MIME sniffing risk)")
    }

    if has_rp {
        y.println("[PASS] Referrer-Policy: Configured")
        score = score + 1
    } else {
        y.println("[INFO] Referrer-Policy: Not set (Referrer token leakage possible)")
    }

    if has_pp {
        y.println("[PASS] Permissions-Policy: Configured")
        score = score + 1
    } else {
        y.println("[INFO] Permissions-Policy: Not set")
    }

    if has_cors {
        if cors_val == "*" {
            y.println("[WARN] CORS Access-Control-Allow-Origin: Wildcard '*' detected")
        } else {
            y.println("[PASS] CORS Access-Control-Allow-Origin: Restrained to " + cors_val)
        }
    }

    if server_val != "" {
        y.println("[INFO] Server Banner: " + server_val)
    }

    y.println("")
    y.println("Security Score: " + y.str(score) + "/6 headers verified.")
}
