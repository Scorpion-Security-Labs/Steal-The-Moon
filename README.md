# Steal-The-Moon
Memoizing work on the Davolink "Minion" series of routers (should apply to Kevin and Bob).

Additional vulnerabilities include:
 - In firmware v1.00.04: a command injection vulnerability exists in the handler for `/api/system/country` almost identical to the one described above for `/api/status/image`. Unlike the latter endpoint, this one requires the signed-in user to be "admin", not the standard user. Like the vulnerability in the latter endpoint, this was patched between firmware v1.00.04 and v1.00.16 through gating by a quote escape.
 - In firmware v1.00.04: the submitted password is encrypted using AES-256-CBC with the IV and key sent from the router to the client. This encryption-by-obfuscation offers no meaningful protection as an attacker that can eavesdrop on the exchange can decrypt the password.
 - In firmware v1.00.16: the credential material used to authenticate is the SHA-256 of the username concatenated with a colon (":") then the user's password. Because there is no challenge/nonce acting as a salt, an attacker who can eavesdrop on this exchange can replay this credential material for login tokens until the password is changed.
 - The public and private keys used to encrypt SSL/TLS appear to be the same across all devices and maintain across firmware updates. Because these are encrypted using RSA, there is no perfect forward secrecy and any attacker who has extracted these keys can decrypt the login exchange when it is made over TLS.
 - Like the "bob" and "admin" passwords, the default Wi-Fi password is also generated- this time using only the serial number. `calculate_default_user_password.py` will calculate this when supplied only with the device's serial number. (Additionally, there appears to be a trivial relationship between the MAC address and serial number, meaning technically the default Wi-Fi password can be calculated from its default SSID, which includes the last three bytes of the MAC address. This has been tested on three "Bob" routers and one "Kevin" and found to hold across all.)
 - Configuration backups appear to be encrypted with the same static key across every device (verified by software reverse analysis and testing on the four exemplars mentioned above). Any device owner who has extracted this key can decrypt any configuration backup.

David E. Baker

Principal Cybersecurity Consultant

Scorpion Labs by K logix
