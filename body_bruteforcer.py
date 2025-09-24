import socket
import ssl

from urllib.parse import urlparse, urlunparse, quote
import urllib.parse
from ip_spoofer import raw_http_request, parse_raw_http_response, parse_headers, store_http_response, get_base_url

print("Doesn't add a real browswer User-Agent header by default!")

# --------------------------- characters ------------------------------------------

raw_characters = [
    "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0A", "\x0B",
    "\x0C", "\x0D", "\x0E", "\x0F", "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17",
    "\x18", "\x19", "\x1A", "\x1B", "\x1C", "\x1D", "\x1E", "\x1F", "\x20", "\x7F", "\xA0", "\xAD"
]

url_encoded_characters = []

for char in raw_characters:
    url_encoded_characters.append(urllib.parse.quote())

characters = raw_characters + url_encoded_characters

# ------------------------------------------------------------------------------------


for payload in characters:  #* change this for loop to change payloads

    ##* Modify from here to suite target.

    #* replace target_url string with target full URL
    target_full_url = "https://example.com/admin/panel/v2/access?isAdmin=True"  
    #* replace required_headers string with headers target requires
    required_headers = """User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"""
    #* replace body with target body
    body_data = f'''
{{"email":"test@email.com{payload}"}}'''

    url_path = target_full_url.replace(get_base_url(target_full_url), "")

    headers = parse_headers(required_headers)

    req_b, req_esc, resp_b, resp_esc = raw_http_request(
        "example.com",
        port=443,
        method="POST",
        path=url_path,
        # proxy=("127.0.0.1", 9090),
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

    # *change the payload parameter value with the for loop variable name
    store_http_response(response_code, response_headers, response_body, payload=repr(payload), table_name="body_bruteforcer")