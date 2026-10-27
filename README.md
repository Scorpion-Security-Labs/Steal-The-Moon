# Stealing The Moon

Here, we discuss several vulnerabilities discovered in Davolink's DVW-642 ("Bob") and DVW-632 ("Kevin") routers, themed after the Minions of the same names in the _Despicable Me_ and _Minions_ film franchises. The vulnerabilities are described in detail in both this repository as well as in the "Anatomy of an IoT Exploit" series on our blog at [Scorpion Labs](https://https://www.klogixsecurity.com/scorpion-labs-blog). Each of the following vulnerabilities comes with either a description in Markdown or a complete writeup in the associated Python proof-of-concept:
 - `index-json_information_disclosure.py`: Access to the `/index.json` endpoint allows an unauthenticated user with access to the web interface to read sensitive device information about the device including its MAC address and serial number.
 - `calculate_default_user_password.py`: The default username and password (which the device returns to on factory reset) can be calculated using a static formula and the MAC address and serial number.
 - `calculate_default_admin_password.py`: A hidden maintenance(/"superuser") password for the `admin` user can be calculated using a static formula, the MAC address, serial number, and device model.
 - `admin_dvsh_breakout.py`: A user with SSH access to the device and the `admin` user credentials can escape the restricted `dvsh` shell to get unrestricted access to the device's native `/bin/ash` console. (Note that the `admin` user can enable SSH access through the web interface.)
 - `api_status_image_cmdinjection.py`: There is a command injection in the `/api/status/image` endpoint using the value corresponding to the `bank` key of a JSON payload. This was patched between firmware versions 1.00.04 and 1.00.16.
 - `api_status_account_cmdinjection.py`: There is a command injection in the `/api/system/account` endpoint using the value corresponding to the `chpw` key of a JSON payload. This has not been confirmed in firmware version 1.00.04 but has been confirmed in 1.00.16.

Additional security concerns include:
 - In firmware v1.00.04: a command injection vulnerability exists in the handler for `/api/system/country` almost identical to the one described above for `/api/status/image`. Unlike the latter endpoint, this one requires the signed-in user to be "admin", not the standard user. Like the vulnerability in the latter endpoint, this was patched between firmware v1.00.04 and v1.00.16 through gating by a quote escape.
 - In firmware v1.00.04: the submitted password is encrypted using AES-256-CBC with the IV and key sent from the router to the client. This encryption-by-obfuscation offers no meaningful protection as an attacker that can eavesdrop on the exchange can decrypt the password.
 - In firmware v1.00.16: the credential material used to authenticate is the SHA-256 of the username concatenated with a colon (":") then the user's password. Because there is no challenge/nonce acting as a salt, an attacker who can eavesdrop on this exchange can replay this credential material for login tokens until the password is changed.
 - The public and private keys used to encrypt SSL/TLS appear to be the same across all devices and maintain across firmware updates. Because these are encrypted using RSA, there is no perfect forward secrecy and any attacker who has extracted these keys can decrypt the login exchange when it is made over TLS.
 - Like the `bob` and `admin` passwords, the default Wi-Fi password is also generated using a constant, recoverable formula- this time using only the serial number. `calculate_default_user_password.py` will calculate this when supplied with only the device's serial number.
 - There appears to be a trivial relationship between the MAC address and serial number, meaning technically the default Wi-Fi password can be calculated from its default SSID, which includes the last three bytes of the MAC address. This has been tested on three "Bob" routers and one "Kevin" and found to hold across each instance.
 - Configuration backups appear to be encrypted with the same static key across every device (verified by software reverse analysis and testing on the four exemplars mentioned above). Any device owner who has extracted this key can decrypt any configuration backup.

---

David E. Baker, Principal Cybersecurity Consultant at Scorpion Labs by K logix, 2026
