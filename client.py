'''
Author: Neel Patel 
Title: HTTP/1.1 Client 
Filename: client.py
usage: python3 client.py <URL_NAME> 
'''

import logging
import re
import socket
import sys
import ssl
from urllib.parse import urlparse

# Constants
RECV_BYTES = 4096 # The number of bytes to try to read for every call to recv.

# Configure logging
# Comment/Uncomment to chose your desired logging level.  Changing this could
# also be made programmable if needed.
# logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
hw3_logger = logging.getLogger('cs450-hw3')


def parse_url(url):
    """A function to parse a url and return the hostname, port, and path.

    Args:
        url (str): The url to be parsed.

    Returns:
        A tuple of (scheme (str), hostname (str), port (int), path (str)) that
        is parsed from the URL or None if an error is encoutnered.
    """
    # Assign default vaules to the returns
    scheme, hostname, port, path = 'http', None, None, '/'

    # Call into the urlparse library to parse the URL
    parsed = urlparse(url)

    scheme, hostname, port, path = parsed.scheme, parsed.hostname, parsed.port , parsed.path

    # Hostname error checking and getting
    if hostname == None :
        print("Hostname error")
    # Scheme error checking and getting
    if scheme != "https" and scheme != "http" :
        scheme = "https"
    # Port error checking and getting
    if port == None :
        if scheme == "https" :
            port = 443
        else:
            port = 80
    # Note: Reading the port attribute will raise a ValueError if an invalid
    # port is specified in the URL.

    # Default ports:

    # Path getting

    # Logging

    return scheme, hostname, port, path

def open_connection(hostname, port):
    """A function to connect to a hostname on a port and return the
    socket.

    Args:
        hostname (str): The hostname to connect to.
        port (int): The port to connect to.

    Returns:
        An open socket to the server or None if an error is encountered.
    """
    # Initialize the socket to None
    s = None

    # Catch possible exceptions (socket.gaierror, socket.error, socket.herror,
    #   socket.timeout):
    # Get the address to connect to (support both IPv4 and IPv6)
    # (socket.getaddrinfo)
    msg = "getaddrinfo returns an empty list"
    # Try to connect to the returned addresses
    for res in socket.getaddrinfo(hostname, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
            s.connect(sa)
        except socket.gaierror as exc:
            print("Caught exception socket.gaierror : " + exc)
        except socket.herror as exc:
            print("Caught exception socket.herror : " + exc)
        except socket.timeout as exc:
            print("Caught exception socket.timeout : " + exc)
        except socket.error as exc:
            print("Caught exception socket.error : " + exc)
    return s

def wrap_socket_ssl(s, hostname):
    """A function to wrap a socket to use SSL.

    Args:
        s (socket): The socket to wrap.
        hostname (str): The hostname to validate

    Returns:
        A wrapped socket (socket) on success.  None on error.

    """
    # Catch SSL errors
        # Create the SSL context
    ctx = ssl.create_default_context()
        # Set the conext to verify certificates (ssl.CERT_REQUIRED)
    ctx.verify_mode = ssl.CERT_REQUIRED
        # Check the hostname
    ctx.check_hostname = True
        # Use the system's default certs
    ctx.load_default_certs()
        # Wrap the socket
    ssl_sock = ctx.wrap_socket(s, server_hostname=hostname)
    return ssl_sock

def gen_http_req(hostname, port, path):
    """A function to generate an HTTP request

    Args:
        hostname (str): The hostname to connect to.
        port (int): The port to connect to.
        path (str): The path of the HTTP request.

    Returns:
        A valid HTTP 1.1 request (bytes).

    """
    # Create the request
    req = "GET " + path + " HTTP/1.1\r\n" + \
          "Host:" + hostname + ":" +  str(port) +"\r\n\r\n"

    # Encode the message for transmission over the socket (str -> bytes)
    req = req.encode()
    return req

def send_req(s, req):
    """Send a request on a socket

    Args:
        s (socket): The socket to send on
        req (bytes): The request to send

    Returns:
        bool: True on success.  False on error.
    """
    # Catch socket errors
        # Send the entire request
    try:
        sent = s.sendall(req)
        return True
    except:
        return False

def parse_headers(headers):
    """Parses an HTTP Header and gets the field names and value.

    Args:
        headers (bytes): The bytes in the HTTP header

    Returns:
        A list with a first entry of Status-Line (str)
        and following entries of (field_name (str), field_value (str)) pairs.
        None on error.
    """
    parsed_headers = []

    # Split the headers into decoded lines
    try:
        headers_splited = []
        for i in headers.split(b'\r\n'):
            headers_splited.append(i.decode("utf-8"))
        # Get the Status-Line
        parsed_headers.append(headers_splited.pop(0))

        # Get the header field names and values

            # Find the name and value

            # Handle extended header fields

            # Add the parsed field name and value
        for i in headers_splited:
            parsed_headers.append(re.findall('(.+)\:\s(.+)',i)[0])
        return parsed_headers
    except:
        return None

def check_status_line(line):
    """Checks if the status line is good (True) or bad (False).
    """
    # Split the line on whitespace
    lines = re.findall('\S+',line)
    # Check if the status line has enough fields
    if len(lines) < 3:
        return False
    # Check the version
    if lines[0] != 'HTTP/1.1':
        return False
    # Check the status
    if lines[1] != '200' and lines[1] != '301':
        return False
    return True

def validate_headers(headers):
    """Validates the headers in the HTTP response

    Args:
        headers (list): The cleaned headers to validate

    Returns:
        True if the headers pass validation.  False otherwise.
    """
    # Check the Status line
    if not check_status_line(headers[0]):
        return False
    # TODO: More checking
    #headers_list = ['Accept-Features', 'Alternates', 'DNT', 'Negotiate', 'Sec-Websocket-Extensions', 'Sec-Websocket-Key', 'Sec-Websocket-Origin', 'Sec-Websocket-Protocol', 'Sec-Websocket-Version', 'Strict-Transport-Security', 'TCN', 'X-Content-Duration', 'X-Content-Security-Policy', 'X-DNSPrefetch-Control', 'X-Frame-Options', 'X-Requested-With', 'Accept', 'Accept', 'Accept-CH', 'Accept-CH', 'Accept-Charset', 'Accept-Charset', 'Accept-Encoding', 'Accept-Encoding', 'Accept-Language', 'Accept-Language', 'Accept-Ranges', 'Accept-Ranges', 'Access-Control-Allow-Credentials', 'Access-Control-Allow-Credentials', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Headers', 'Access-Control-Max-Age', 'Access-Control-Max-Age', 'Access-Control-Expose-Headers', 'Access-Control-Expose-Headers', 'Access-Control-Request-Method', 'Access-Control-Request-Method', 'Access-Control-Request-Headers', 'Access-Control-Request-Headers', 'Age', 'Age', 'Allow', 'Allow', 'Authorization', 'Authorization', 'Cache-Control', 'Cache-Control', 'Connection', 'Connection', 'Content-Encoding', 'Content-Encoding', 'Content-Language', 'Content-Language', 'Content-Length', 'Content-Length', 'Content-Location', 'Content-Location', 'Content-MD5', 'Content-MD5', 'Content-Range', 'Content-Range', 'Content-Security-Policy', 'Content-Security-Policy', 'Content-Type', 'Content-Type', 'Cookie', 'Cookie', 'Date', 'Date', 'ETag', 'ETag', 'Expect', 'Expect', 'Expires', 'Expires', 'From', 'From', 'Host', 'Host', 'If-Match', 'If-Match', 'If-Modified-Since', 'If-Modified-Since', 'If-None-Match', 'If-None-Match', 'If-Range', 'If-Range', 'If-Unmodified-Since', 'If-Unmodified-Since', 'Last-Event-ID', 'Last-Event-ID', 'Last-Modified', 'Last-Modified', 'Link', 'Link', 'Location', 'Location', 'Max-Forwards', 'Max-Forwards', 'Origin', 'Origin', 'Pragma', 'Pragma', 'Proxy-Authenticate', 'Proxy-Authenticate', 'Proxy-Authorization', 'Proxy-Authorization', 'Range', 'Range', 'Referer', 'Referer', 'Retry-After', 'Retry-After', 'Server', 'Server', 'Set-Cookie', 'Set-Cookie', 'Set-Cookie2', 'Set-Cookie2', 'TE', 'TE', 'Trailer', 'Trailer', 'Transfer-Encoding', 'Transfer-Encoding', 'Upgrade', 'Upgrade', 'User-Agent', 'User-Agent', 'Vary', 'Vary', 'Via', 'Via', 'Warning', 'Warning', 'WWW-Authenticate', 'WWW-Authenticate']
    #for i in headers[1:]:
    #    if i[0] not in headers_list:
    #        return False

    return True


def get_body_len_info(s, headers):
    """Gets information needed to determine the length and format of the HTTP
    response body.

    Args:
        headers (list): The parsed and cleaned headers to search

    Returns:
        A dictionary of {'content_len: (int), chunked: (bool)} based on the
        vaule of the headers.  Returns None if the headers needed to determine
        the content length are not available.  

    """
    content_len = None
    chunked = False



    # Check the headers for either content-length or a chunked
    # transfer-encoding
    for i in headers:
        if 'Content-Length' in i:
            content_len = i[1]
    for i in headers:
        if 'Transfer-Encoding' in i:
            chunked = True
    if content_len == None and chunked == False:
        hw3_logger.warning('Neither Content-Length nor Chunked found!')
        return None

    return {'content_len': content_len, 'chunked': chunked}
    
def get_body_content_len(s, body_start, content_len=0):
    """Gets the body of an HTTP response given a body_start that has already
    been received and a total length of the content to read.

    Args:
        body_start (bytes): The start of the body that has already been
            received 
        content_len (int): The total length of the content to read.

    Returns:
        The complete body (bytes).

    """
    # While recv has not returned enough bytes, continue to call recv
    chunks = []
    bytes_recd = 0
    if int(content_len) > 0:
        while bytes_recd < int(content_len):
            chunk = s.recv(min(int(content_len) - bytes_recd, 2048))
            if chunk == b'':
                break
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        return b''.join(chunks)
    else:
        while True:
            try:
                chunk = s.recv(2)
                if chunk == b'':
                    break
                chunks.append(chunk)
                bytes_recd = bytes_recd + len(chunk)
            except:
                pass

    return b''.join(chunks)

def get_body_chunked(s, body_start):
    """Parses an HTTP Body formatted in the chunked transfer-encoding

    Args:
        s (socket): The socket to read from
        body_start (bytes): The start of the body that has already been
            received

    Returns:
        The complete body (bytes).  
    """
    # Initialize loop variables (if needed)

    # While the last chunk has not been seen
        # Verify and get the next chunk header

        # Verify and get the length of the next chunk

        # Get the chunk.
        # Note: recv must be called as many times as needed to get all of the
        # bytes!

        # Add the chunk to the decoded body

        # Each chunk has a newline at the end.  Verify that it is there

        # Move to the start of the new chunk header
    chunks = []
    bytes_recd = 0
    while True:
        chunk = s.recv(2)
        if not chunk:
            break
        chunks.append(chunk)
    body = b''
    for i in chunks:
        body += i
    print('encoded : ')
    print(body)

    body = body.split(b'\r\n')[1::2]
    final_body = b''

    for sub_con in body:
        final_body += sub_con

    if final_body != b'':
        print(final_body)
        return final_body
    else:
        return None

def read_resp(s):
    """Read an HTTP response from the server

    Args:
        s (socket): The socket to read from.

    Returns:
        The response on success, None on error.
    """
    # Catch relevant socket exceptions

    # Get at least the header of the response.
    # While we have not received the full header, recv more bytes
    data = b''
    while True:
        data += s.recv(1)
        if b'\r\n\r\n' in data:
            break
    if not data:
        return None
    # Find the end of the headers/start of the body and save pointers to
    # them
    raw_headers = data.split(b'\r\n\r\n',1)[0]
    body_start =  data.split(b'\r\n\r\n',1)[1]
    # Parse the headers
    headers = parse_headers(raw_headers)
    if headers == None:
        return None
    hw3_logger.debug('Parsed Headers: {}'.format(headers))

    # Validate the headers
    if not validate_headers(headers):
        hw3_logger.warning('Invalid Headers: {}'.format(headers))
        return None

    # Get information about the both length
    body_info = get_body_len_info(s, headers)
    hw3_logger.debug('Response body_info: {}'.format(body_info))

    # Get the body
    if body_info == None:
        body = get_body_content_len(s, body_start)
    elif body_info['chunked']:
        body = get_body_chunked(s, body_start)
    else:
        body = get_body_content_len(s, body_start, body_info['content_len'])
    #TODO: create a new function for reading from a server that closes
    # the connection to signal the end of the body.
    return body

def retrieve_url(url):
    """Read an HTTP response from the server at URL

    Args:
        url (str): The URL to request

    Returns:
        The response on success, None on error.
    """
    # Log the URL that is being fetched
    hw3_logger.info('Retrieving URL: {}'.format(url))

    # Parse the URL.
    parsed_url = parse_url(url)
    if parsed_url != None:
        scheme, hostname, port, path = parsed_url
    else:
        hw3_logger.warning('Invalid URL: {}'.format(url))
        return None
    hw3_logger.info('Parsed URL, got scheme: {}, hostname: {}, port: {}, '
        'path: {}'.format(scheme, hostname, port, path))

    # Open the connection to the server.
    s = open_connection(hostname, port)
    if s == None:
        hw3_logger.warning('Unable to open connection to: ({}, {})'.format(
            hostname, port))
        return None
    hw3_logger.info('Opened connection to: ({}, {})'.format(hostname, port))

    # Use SSL if requested
    if scheme == 'https':
        s = wrap_socket_ssl(s, hostname)
        if s == None:
            hw3_logger.warning('Unable to wrap socket and validate SSL')
            return None
        hw3_logger.info('Wrapped socket and validated SSL (HTTPS)')

    # Generate the request. Cannot fail.
    req = gen_http_req(hostname, port, path)
    hw3_logger.debug('Generated the following request to send: {}'.format(req))

    # Send the request
    success = send_req(s, req)
    if success != True:
        hw3_logger.warning('Unable to send request')
        return None
    hw3_logger.info('Request sent successfully')

    # Read the response
    resp = read_resp(s)
    if resp == None:
        hw3_logger.warning('Unable to read response')

    # Close the socket for garbage collection
    s.close()

    return resp

if __name__ == "__main__":
    url = 'https://www.google.com/'
    sys.stdout.buffer.write(retrieve_url(url))

    