-- Pure native Yolish HTTP Inspector (Zero PowerShell dependency)
fn http_inspect() {
    let raw_url = require_env("YS_SEC_A", "URL")
    if y.is_nil(raw_url) || raw_url == "" { return }

    let host = parse_url_host(raw_url)
    let path = parse_url_path(raw_url)
    var port = 80
    if y.starts_with(raw_url, "https://") {
        port = 443
    }

    var clean_host = host
    let parts = y.split(host, ":")
    if y.len(parts) == 2 {
        clean_host = parts[0]
        port = y.int(parts[1])
    }

    y.println("Connecting to http://" + clean_host + ":" + y.str(port) + path + "...")
    let sock = y.net.connect(clean_host, port)
    if sock == -1 {
        y.println("HTTP request failed: connection refused (" + y.net.last_error() + ")")
        return
    }

    y.net.set_timeout(sock, 4000)
    let req = "GET " + path + " HTTP/1.1\r\nHost: " + clean_host + "\r\nUser-Agent: ys-sec/0.3.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    y.net.send(sock, req)

    let raw = y.net.recv(sock, 16384)
    y.net.close(sock)

    if y.is_nil(raw) || y.trim(raw) == "" {
        y.println("HTTP request failed: empty response")
        return
    }

    let lines = y.split(raw, "\n")
    if y.len(lines) == 0 {
        y.println("HTTP request failed: invalid response")
        return
    }

    let status_line = y.trim(lines[0])
    var content_length = "chunked/unspecified"
    var content_type = "unknown"
    var server = "unknown"
    var date = ""
    var header_count = 0

    var in_headers = true
    var body_len = 0
    var i = 1
    let num_lines = y.len(lines)

    while i < num_lines {
        let line = y.trim(lines[i])
        if in_headers {
            if line == "" {
                in_headers = false
            } else {
                header_count = header_count + 1
                let colon_idx = y.index_of(line, ":")
                if colon_idx != -1 {
                    let h_name = str_to_lower(y.trim(y.substr(line, 0, colon_idx)))
                    let h_val = y.trim(y.substr(line, colon_idx + 1, y.len(line)))
                    if h_name == "content-length" { content_length = h_val }
                    if h_name == "content-type" { content_type = h_val }
                    if h_name == "server" { server = h_val }
                    if h_name == "date" { date = h_val }
                }
            }
        } else {
            body_len = body_len + y.len(lines[i]) + 1
        }
        i = i + 1
    }

    y.println("Status:       " + status_line)
    y.println("Server:       " + server)
    y.println("Content-Type: " + content_type)
    y.println("Content-Len:  " + content_length)
    if date != "" {
        y.println("Server Date:  " + date)
    }
    y.println("Headers:      " + y.str(header_count) + " parsed")
    y.println("Body Bytes:   " + y.str(body_len) + " bytes received")
}
