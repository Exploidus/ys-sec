-- Pure native Yolish WHOIS client (Zero PowerShell dependency)
fn whois_lookup() {
    let domain = require_env("YS_SEC_A", "domain")
    if y.is_nil(domain) || !valid_domain(domain) {
        y.println("Invalid domain")
        return
    }

    y.println("Querying WHOIS for: " + domain + " via whois.iana.org:43...")
    let sock = y.net.connect("whois.iana.org", 43)
    if sock == -1 {
        y.println("WHOIS connection failed (" + y.net.last_error() + ")")
        return
    }

    y.net.set_timeout(sock, 5000)
    y.net.send(sock, domain + "\r\n")

    let response = y.net.recv(sock, 8192)
    y.net.close(sock)

    if y.is_nil(response) || response == "" {
        y.println("WHOIS lookup returned empty response")
        return
    }

    y.println(response)
    save_if_requested(response)
}
