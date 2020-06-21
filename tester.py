#!/usr/bin/env python3

import argparse
import importlib.util
import os
import time
import shlex
import subprocess
import sys
import traceback

# All paths must be either absolute or relative to the directory from which you
# are running this script.
TEST_SERVERS = [
    ('tests/test_server.py', 4500),
    ('tests/test_server01.py', 4501),
    ('tests/test_server02.py', 4502),
    ('tests/test_server03.py', 4503),
    ('tests/test_server04.py', 4504),
    ('tests/test_server05.py', 4505),
    ('tests/test_server06.py', 4506),
    ('tests/test_server07.py', 4507),
    ('tests/test_server08.py', 4508)
]

TEST_CASES = [
    # 'http://www.example.com',
    'http://127.0.0.1:4500',
    'http://127.0.0.1:4501',
    'http://127.0.0.1:4502',
    'http://127.0.0.1:4503',
    'http://127.0.0.1:4504',
    'http://127.0.0.1:4505',
    'http://127.0.0.1:4506',
    'http://127.0.0.1:4507',
    'http://127.0.0.1:4508'
]

# Pretty print test passing/failing output
PASS_FMT_STR = 'Case {} -> \033[1m URL: {}\u001b[32m \u25CF  Pass\033[0m'
FAIL_FMT_STR = 'Case {} -> \033[1m URL: {}\u001b[31m \u25CF  Failed\033[0m'


def start_test_servers():
    """A function to start the test servers.

    Args:
        None

    Returns:
        A list of the server processes that need to be terminated later.
    """
    servers = []
    for test_server_path, port in TEST_SERVERS:
        cmd = '{} --port {}'.format(test_server_path, port)
        args = shlex.split(cmd)
        server = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        servers.append(server)
    return servers

def get_url_curl(url):
    """A function to get a URL via curl.

    Args:
        None

    Returns:
        The body returned from curl.
    """
    cmd = 'curl -f {}'.format(url)
    args = shlex.split(cmd)
    process = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    #XXX: Workaround for comparing errors in curl versus errors in the student
    # code because curl returns '' on error, while the student code is required
    # to return None.  Note that this workaround may not be correct in all
    # cases.  For example, this is incorrect if a test server returns an empty
    # body.  As such, it is best for test servers to not return an empty body,
    # or, if desired, then this function needs to be improved.
    if len(stdout) == 0:
        return None
    else:
        return stdout


def load_student_hw(client_path):
    """Load the provided student code as a callable module

    Args:
        client_path (str): The path to the student's code

    Returns:
        The loaded code as a callable module
    """
    try:
        spec = importlib.util.spec_from_file_location('client', str(client_path))
        student_hw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(student_hw)
    except:
        print("Unable to load client.py")
        sys.exit(1)
    return student_hw


def main():
    """Test the student's code against curl for a list of test URLs.  This
    program will also optionally start test servers as well, if requested.

    Args:
        None (sys.argv is documented with the '--help' string)

    Returns:
        None
    """
    # Use argparse to allow for easily changing the port
    parser = argparse.ArgumentParser(description='Simple tester to start '
        'test servers and then compare against curl.')
    parser.add_argument('--client-path', required=True,
        help='The path to the client to be tested.')
    args = parser.parse_args()
    client_path = args.client_path

    # Load the student code
    student_hw = load_student_hw(client_path)

    # Start the servers
    servers = start_test_servers()

    time.sleep(1)

    # Test the URLs
    for index, url in enumerate(TEST_CASES):
        try:

            curl_body = get_url_curl(url)
            # print(curl_body)
            student_body = student_hw.retrieve_url(url)
            # print(student_body)

            if student_body == curl_body:
                print(PASS_FMT_STR.format(index, url))
            else:
                print(FAIL_FMT_STR.format(index, url))
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(traceback.print_exception(exc_type, exc_value, exc_traceback, limit=5, file=sys.stdout))
            print(FAIL_FMT_STR.format(index, url))

    # Garbage collection: Kill all of the started servers
    for server in servers:
        server.terminate()


if __name__ == "__main__":
    main()
