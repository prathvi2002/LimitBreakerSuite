print("""
Strategic character insertion:

Inserts both raw and percent-encoded special bytes in key positions:
Path end: /admin[char]
After trailing slash: /admin/[char]
Path beginning: /[char]admin
After each segment: /segment1[char]/segment2
Before each segment: /segment1/[char]segment2
After first character: /s[char]egment1
""")


import socket
import ssl

from urllib.parse import urlparse, urlunparse, quote
from ip_spoofer import raw_http_request, parse_raw_http_response, parse_headers, store_http_response


def insert_char_in_url(url: str, char: str):
    """
    Insert both raw and percent-encoded versions of `char` into strategic positions of a URL path, while preserving a trailing slash if present.

    Positions:
    - Path end: /admin[char]
    - After trailing slash: /admin/[char]
    - Path beginning: /[char]admin
    - After each segment: /segment1[char]/segment2
    - Before each segment: /segment1/[char]segment2
    - After first character of each segment: /s[char]egment
    """
    parsed = urlparse(url)
    path = parsed.path
    ends_with_slash = path.endswith("/")  # track if original had a trailing slash
    segments = [seg for seg in path.strip("/").split("/") if seg]

    insertions = []

    # 1. Path end
    insertions.append(path + char)
    insertions.append(path + quote(char))

    # 2. After trailing slash (only if path ends with '/')
    if ends_with_slash:
        insertions.append(path + char)
        insertions.append(path + quote(char))

    # 3. Path beginning
    insertions.append("/" + char + "/".join(segments))
    insertions.append("/" + quote(char) + "/".join(segments))

    # 4. After each segment
    for i in range(len(segments)):
        modified = segments[:]
        modified[i] = modified[i] + char
        insertions.append("/" + "/".join(modified))
        modified[i] = segments[i] + quote(char)
        insertions.append("/" + "/".join(modified))

    # 5. Before each segment
    for i in range(len(segments)):
        modified = segments[:]
        modified[i] = char + modified[i]
        insertions.append("/" + "/".join(modified))
        modified[i] = quote(char) + segments[i]
        insertions.append("/" + "/".join(modified))

    # 6. After first character of each segment
    for i in range(len(segments)):
        if segments[i]:
            modified = segments[:]
            modified[i] = segments[i][0] + char + segments[i][1:]
            insertions.append("/" + "/".join(modified))
            modified[i] = segments[i][0] + quote(char) + segments[i][1:]
            insertions.append("/" + "/".join(modified))

    # Reconstruct full URLs, preserving trailing slash if it existed
    urls = []
    for ins in insertions:
        if ends_with_slash and not ins.endswith("/"):
            ins = ins + "/"
        new_url = urlunparse(parsed._replace(path=ins))
        urls.append(new_url)

    return list(dict.fromkeys(urls))  # dedupe while preserving order


def get_base_url(url):
    """
    Returns the base URL (scheme + domain) from an arbitrary URL.
    Example: http://example.com/admin -> http://example.com
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


print("Doesn't add a real browswer User-Agent header by default!")


characters = [
    "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0A", "\x0B",
    "\x0C", "\x0D", "\x0E", "\x0F", "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17",
    "\x18", "\x19", "\x1A", "\x1B", "\x1C", "\x1D", "\x1E", "\x1F", "\x20", "\x7F", "\xA0", "\xAD"
]


for character in characters:

    ##* Modify from here to suite target.

    #* replace target_url string with target URL
    target_url = "https://example.com/admin/panel/v2/access?isAdmin=True"  
    #* replace required_headers string with headers target requires
    required_headers = """User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"""

    urls = insert_char_in_url(target_url, character)
    for url in urls:
        # print(repr(url))
        url_path = url.replace(get_base_url(url), "")

        headers = parse_headers(required_headers)

        req_b, req_esc, resp_b, resp_esc = raw_http_request(
            "example.com",
            port=443,
            method="GET",
            path=url_path, #* do NOT modify this path!
            # proxy=("127.0.0.1", 9090),  #! Use proxy with caution, as it might reject some requests containing mutated headers sent with the intention of Header Smuggling.
            insecure=True,
            headers=headers,
            timeout=5,
            # body=body_data
        )

        print("")

        print(repr(req_b))

        response_code, response_headers, response_body = parse_raw_http_response(raw_response=resp_b)
        print(response_code)
        print(response_headers)

        store_http_response(response_code, response_headers, response_body, payload=repr(url), table_name="ip_spoofer")