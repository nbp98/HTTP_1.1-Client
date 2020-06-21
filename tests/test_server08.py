#!/usr/bin/env python3

import argparse
import socket
import sys
import traceback

"""Test Case Write-up:

Behavior:
    This test case generates a chunked http response. 
Tests:
    This server tests whether the client can correctly handle chunked response.

Notes:
    You should copy and modify this test-case to create your own new test cases.
"""


def get_test_response():
    """Create the test response.

    Args:
        None

    Returns:
        The created response (str)
    """
    first_chunk = 'This is first chunk\n'
    response_body =  '%X\r\n%s' % (len(first_chunk), first_chunk) + '\r\n' + '%X' % 0 + '\r\n\r\n'
    response_status_line = b'HTTP/1.1 200 OK'
    response_headers = [
        response_status_line,
        b'Content-Type: text/plain; encoding=utf8',
        b'Transfer-Encoding: chunked',
        b'Connection: close',
        b'\r\n',  # Newline to end headers
     ]

    response = b'\r\n'.join(response_headers) + response_body.encode('utf')
    return response


def send_test_response(client_sock, response):
    """Create the test response.

    Args:
        client_sock (socket): the socket to send the request on
        response (str): the response to send

    Returns:
        None
    """
    client_sock.sendall(response)

def get_listen_sock(port):
    """Create a TCP socket, bind it to the requested port, and listen.

    Args:
        port (int): The port to bind to

    Returns:
        The created socket (socket).

    Raises:
        Socket errors
    """
    # create_server is a nice convenience function that calls socket(), bind(),
    # and listen() for the programmer.  However, since it is only available in
    # Python version 3.8, we won't use it.
    # address = ('', port)
    # s = socket.create_server(address, reuse_port=True, dualstack_ipv6=True)

    address = ('', port)
    # Note: Using AF_INET and not AF_INET6 makes this not IPv4/IPv6 compliant
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    s.bind(address)
    s.listen(100)

    return s


def main():
    """A simple HTTP server that is *not* strictly compliant to the HTTP
    protocol.  In particular, this server entirely ignores the incoming message
    and returns a static response.  This server is primiarly useful for
    experimenting with whether or not a static response is HTTP compliant.

    Args: None

    Returns: None
    """
    # Use argparse to allow for easily changing the port
    parser = argparse.ArgumentParser(description='Simple server to test '
                                                 'edge-cases in the HTTP protocol.')
    parser.add_argument('--port', required=True, type=int,
                        help='The port to listen on.')
    args = parser.parse_args()
    port = args.port

    # Create the listening socket
    server_sock = get_listen_sock(port)

    while True:
        # Accept the connection
        client_sock, client_addr = server_sock.accept()

        # Ignore any request (not protocol compliant)

        # Get the test response
        response = get_test_response()

        # Print sending response for optional debugging
        # print('Sending response:')
        # print(response)

        # Send the rest response
        send_test_response(client_sock, response)

        # Close the connection for garbage collection
        client_sock.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print(traceback.print_exception(exc_type, exc_value, exc_traceback, limit=5, file=sys.stdout))
