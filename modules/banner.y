fn service_name(port) {
    if port == 21 { return "ftp" }
    if port == 22 { return "ssh" }
    if port == 23 { return "telnet" }
    if port == 25 { return "smtp" }
    if port == 53 { return "dns" }
    if port == 80 { return "http" }
    if port == 110 { return "pop3" }
    if port == 135 { return "msrpc" }
    if port == 139 { return "netbios-ssn" }
    if port == 143 { return "imap" }
    if port == 443 { return "https" }
    if port == 445 { return "microsoft-ds" }
    if port == 587 { return "smtp-submission" }
    if port == 3306 { return "mysql" }
    if port == 3389 { return "rdp" }
    if port == 5432 { return "postgresql" }
    if port == 6379 { return "redis" }
    if port == 8080 { return "http-alt" }
    if port == 8443 { return "https-alt" }
    return "unknown"
}

-- Protocol-specific fingerprinting & version extraction
fn extract_service_fingerprint(port, raw) {
    let t = y.trim(raw)

    -- SSH Version Identification
    if port == 22 || y.starts_with(t, "SSH-") {
        let lines = y.split(t, "\n")
        let first = y.trim(lines[0])
        return "[FINGERPRINT] SSH Protocol: " + first
    }

    -- FTP Greeting Identification
    if port == 21 || y.starts_with(t, "220") {
        let lines = y.split(t, "\n")
        let first = y.trim(lines[0])
        return "[FINGERPRINT] FTP Service: " + first
    }

    -- SMTP / ESMTP Greeting
    if port == 25 || port == 587 {
        if y.starts_with(t, "220") {
            let lines = y.split(t, "\n")
            return "[FINGERPRINT] SMTP Server: " + y.trim(lines[0])
        }
    }

    -- HTTP Server Header Extraction
    if port == 80 || port == 8080 || port == 443 || port == 8443 {
        let lines = y.split(t, "\n")
        for line in lines {
            let tl = y.trim(line)
            let colon = y.index_of(tl, ":")
            if colon != -1 {
                let key = str_to_lower(y.trim(y.substr(tl, 0, colon)))
                if key == "server" {
                    return "[FINGERPRINT] Web Server: " + y.trim(y.substr(tl, colon + 1, y.len(tl)))
                }
            }
        }
    }

    -- Redis version extraction
    if port == 6379 {
        let lines = y.split(t, "\n")
        for line in lines {
            let tl = y.trim(line)
            if y.starts_with(tl, "redis_version:") {
                return "[FINGERPRINT] Redis Version: " + y.substr(tl, 14, y.len(tl))
            }
        }
    }

    return ""
}

-- Pure native Yolish active banner grabbing & protocol probes
fn banner_grab() {
    let host = require_env("YS_SEC_A", "host")
    let port_s = require_env("YS_SEC_B", "port")
    if y.is_nil(host) || y.is_nil(port_s) || !valid_host(host) { return }

    let port = y.int(port_s)
    if port < 1 || port > 65535 {
        y.println("Invalid port")
        return
    }

    y.println("Target:   " + host)
    y.println("Port:     " + y.str(port))
    y.println("Service:  " + service_name(port))

    let sock = y.net.connect(host, port)
    if sock == -1 {
        y.println("Banner: connection failed (" + y.net.last_error() + ")")
        return
    }

    -- Set timeout to 3000ms
    y.net.set_timeout(sock, 3000)

    -- Protocol-specific probes
    if port == 80 || port == 8080 {
        y.net.send(sock, "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: ys-sec/0.3.0\r\nConnection: close\r\n\r\n")
    } else if port == 25 || port == 587 {
        -- Read initial greeting then send EHLO
        let greeting = y.net.recv(sock, 512)
        y.net.send(sock, "EHLO exploidus.local\r\n")
    } else if port == 6379 {
        y.net.send(sock, "INFO server\r\n")
    }

    let raw = y.net.recv(sock, 2048)
    y.net.close(sock)

    if y.is_nil(raw) || y.trim(raw) == "" {
        y.println("Banner: unavailable (connected but no initial banner sent)")
        return
    }

    let fp = extract_service_fingerprint(port, raw)
    if fp != "" {
        y.println(fp)
    }

    y.println("")
    y.println("--- Raw Response Banner ---")
    y.println(y.trim(raw))
}
