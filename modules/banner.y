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
    if port == 3306 { return "mysql" }
    if port == 3389 { return "rdp" }
    if port == 5432 { return "postgresql" }
    if port == 6379 { return "redis" }
    if port == 8080 { return "http-alt" }
    if port == 8443 { return "https-alt" }
    return "unknown"
}

-- Pure native Yolish banner grabbing (Zero PowerShell dependency)
fn banner_grab() {
    let host = require_env("YS_SEC_A", "host")
    let port_s = require_env("YS_SEC_B", "port")
    if y.is_nil(host) || y.is_nil(port_s) || !valid_host(host) { return }

    let port = y.int(port_s)
    if port < 1 || port > 65535 {
        y.println("Invalid port")
        return
    }

    y.println("Host: " + host)
    y.println("Port: " + y.str(port))
    y.println("Service: " + service_name(port))

    let sock = y.net.connect(host, port)
    if sock == -1 {
        y.println("Banner: connection failed")
        return
    }

    -- Set timeout to 2000ms so we don't hang on silent services
    y.net.set_timeout(sock, 2000)

    -- Send probe for HTTP if port 80/8080/443
    if port == 80 || port == 8080 {
        y.net.send(sock, "HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n")
    }

    let raw = y.net.recv(sock, 1024)
    y.net.close(sock)

    if y.is_nil(raw) || y.trim(raw) == "" {
        y.println("Banner: unavailable (connected but no initial banner sent)")
        return
    }

    y.println("Banner:")
    y.println(y.trim(raw))
}
