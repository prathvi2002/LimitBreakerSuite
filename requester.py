import socket
import ssl

import socket
import ssl

def raw_http_request(host, port=80, method="GET", path="/", headers=None, body=None,
                     use_https=None, proxy=None, insecure=True):
    """
    Make a raw HTTP/HTTPS request using sockets, with optional proxy and insecure SSL.

    :param host: Target host (string)
    :param port: Port (int), default 80 for HTTP, 443 for HTTPS
    :param method: HTTP method (string), e.g. "GET", "POST"
    :param path: Path on server (string), default "/"
    :param headers: Dict of headers (dict)
    :param body: Request body (string), for POST/PUT/PATCH
    :param use_https: Force HTTPS (True/False). If None, auto-enable for port 443
    :param proxy: Proxy string ("host:port" or "[IPv6]:port") or tuple (host, port)
    :param insecure: Skip SSL verification (like curl --insecure)
    :return: Raw HTTP response as string
    """

    # Auto-enable HTTPS for port 443 if not explicitly set
    if use_https is None:
        use_https = (port == 443)

    if headers is None:
        headers = {}

    # Ensure essential headers
    if "Host" not in headers:
        headers["Host"] = host
    if "User-Agent" not in headers:
        headers["User-Agent"] = "RawPythonClient/1.0"
    if "Connection" not in headers:
        headers["Connection"] = "close"

    method = method.upper()

    # Handle body for POST/PUT/PATCH
    if method in {"POST", "PUT", "PATCH"}:
        if body is None:
            body = ""
        if "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))

    # Build request string
    request = f"{method} {path} HTTP/1.1\r\n"
    for k, v in headers.items():
        request += f"{k}: {v}\r\n"
    request += "\r\n"
    if body:
        request += body

    # Parse proxy if given
    if proxy:
        if isinstance(proxy, str):
            if proxy.startswith("["):  # IPv6: [::1]:port
                host_part, port_part = proxy.rsplit("]:", 1)
                connect_host = host_part.strip("[]")
                connect_port = int(port_part)
            else:  # IPv4: host:port
                connect_host, connect_port = proxy.split(":")
                connect_port = int(connect_port)
        elif isinstance(proxy, tuple):
            connect_host, connect_port = proxy
        else:
            raise ValueError("Proxy must be string 'host:port' or tuple (host, port)")
    else:
        connect_host, connect_port = host, port

    # Detect IPv4 or IPv6
    try:
        addr_info = socket.getaddrinfo(connect_host, connect_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        family, socktype, proto, canonname, sockaddr = addr_info[0]
        sock = socket.socket(family, socktype, proto)
        sock.connect(sockaddr)
    except Exception as e:
        raise Exception(f"Failed to connect to {connect_host}:{connect_port} ({e})")

    # HTTPS through proxy: send CONNECT
    if proxy and use_https:
        connect_cmd = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        sock.sendall(connect_cmd.encode())
        proxy_resp = sock.recv(4096)
        if b"200" not in proxy_resp:
            sock.close()
            raise Exception(f"Proxy CONNECT failed: {proxy_resp.decode(errors='ignore')}")

    # Wrap socket with SSL if HTTPS
    if use_https:
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)

    # Send HTTP request
    sock.sendall(request.encode())

    # Receive response
    response = b""
    while True:
        data = sock.recv(4096)
        if not data:
            break
        response += data

    sock.close()
    return response.decode(errors="ignore")


# Example Usage
# resp = raw_http_request(
#     host="httpbin.org",                     # target host
#     port=443,                               # custom port
#     method="POST",                          # custom method
#     path="/post?debug=true",                # custom path
#     headers={                               # custom headers
#         "Content-Type": "application/json",
#         "X-Debug": "true"
#     },
#     body='{"username":"phoenix","password":"1234"}',  # request body
#     use_https=True,                         # HTTPS
#     proxy=("2001:db8::1", 8080),            # IPv6 proxy
#     insecure=True                           # skip SSL verification (like --insecure)
# )
#
# print(resp[:500])  # print first 500 chars of raw response


def parse_http_response(raw_response: str):
    """
    Parse a raw HTTP response into status_code, headers, and body.

    :param raw_response: Full HTTP response string
    :return: (status_code, headers_dict, body_str)
    """
    # Split head and body
    head, _, body = raw_response.partition("\r\n\r\n")

    # Break head into lines
    lines = head.split("\r\n")
    status_line = lines[0]
    header_lines = lines[1:]

    # Extract status code
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 else None

    # Parse headers
    headers = {}
    for line in header_lines:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.strip()] = v.strip()

    return status_code, headers, body


## Modify from here to suite target.
## Points to remember:
# - The Ip header should be above all HTTP headers.

# ip_headers = ["X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP", "X-Host", "X-Forwared-Host", "X-Forwarded", "Forwarded-For", "Cluster-Client-IP", "Fastly-Client-IP", "X-Cluster-Client-IP", "CACHE_INFO", "CF_CONNECTING_IP", "CF-Connecting-IP", "CLIENT_IP", "Client-IP", "COMING_FROM", "CONNECT_VIA_IP", "FORWARD_FOR", "FORWARD-FOR", "FORWARDED_FOR_IP", "FORWARDED_FOR", "FORWARDED-FOR-IP", "FORWARDED-FOR", "FORWARDED", "HTTP-CLIENT-IP", "HTTP-FORWARDED-FOR-IP", "HTTP-PC-REMOTE-ADDR", "HTTP-PROXY-CONNECTION", "HTTP-VIA", "HTTP-X-FORWARDED-FOR-IP", "HTTP-X-IMFORWARDS", "HTTP-XROXY-CONNECTION", "PC_REMOTE_ADDR", "PRAGMA", "PROXY_AUTHORIZATION", "PROXY_CONNECTION", "Proxy-Client-IP", "PROXY", "REMOTE_ADDR", "Source-IP", "True-Client-IP", "Via", "VIA", "WL-Proxy-Client-IP", "X_CLUSTER_CLIENT_IP", "X_COMING_FROM", "X_DELEGATE_REMOTE_HOST", "X_FORWARDED_FOR_IP", "X_FORWARDED_FOR", "X_FORWARDED", "X_IMFORWARDS", "X_LOCKING", "X_LOOKING", "X_REAL_IP", "X-Backend-Host", "X-BlueCoat-Via", "X-Cache-Info", "X-Forward-For", "X-Forwarded-By", "X-Forwarded-For-Original", "X-Forwarded-For", "X-Forwarded-For", "X-Forwarded-Server", "X-Forwarded-Host", "X-From-IP", "X-From", "X-Gateway-Host", "X-Host", "X-Ip", "X-Original-Host", "X-Original-IP", "X-Original-Remote-Addr", "X-Original-Url", "X-Originally-Forwarded-For", "X-Originating-IP", "X-ProxyMesh-IP", "X-ProxyUser-IP", "X-Real-IP", "X-Remote-Addr", "X-Remote-IP", "X-True-Client-IP", "XONNECTION", "XPROXY", "XROXY_CONNECTION", "Z-Forwarded-For", "ZCACHE_CONTROL"]
ip_header_values = ["127.0.0.1", "23.215.0.136"]

ip_headers = ["X-Forwarder-For\nX-Remote-IP"]

for ip_header in ip_headers:
    for ip_header_value in ip_header_values:
        raw_response = raw_http_request(
            "example.com",
            port=80,
            method="GET",
            path="/nothing",
            headers={
                ip_header: ip_header_value
            },
            proxy="127.0.0.1:9090",
        )

status, headers, body = parse_http_response(raw_response)

print("Status Code:", status)
print("Headers:", headers)
print("Body:", body)
