# Steal-The-Moon
Memoizing work on the Davolink "Minion" series of routers (should apply to Kevin and Bob).


Additional vulnerabilities include:
 - Like the "bob" and "admin" passwords, the default Wi-Fi password is also generated; this time using only the serial number. `calculate_default_user_password.py` will calculate this when supplied only with the device's serial number. (Additionally, there appears to be a trivial relationship between the MAC address and serial number, meaning technically the default Wi-Fi password can be calculated from its default SSID, which includes the last three bytes of the MAC address.)
 - Firmware v1.00.04: a command injection vulnerability exists in the handler for /api/system/country almost identical to the one described above for /api/status/image. Unlike the latter endpoint, this one requires the signed-in user to be "admin", not the standard user. Like the vulnerability in the latter endpoint, it no longer exists in firmware v1.00.16 (gated by a quote-escape).
 - Firmware v1.00.04: the submitted password is encrypted using AES-256-CBC with the IV and key sent from the router to the client. This encryption-by-obfuscation offers no meaningful protection as an attacker that can eavesdrop on the exchange can decrypt the password.
 - Firmware v1.00.16: the credential material used to authenticate is the username concatenated with a colon (":") then a password. Because there is no challenge/nonce acting as a salt, an attacker who can eavesdrop on this exchange can replay the credential material for login tokens until the password is changed.
 - The public and private keys used to encrypt SSL/TLS appear to be the same across all devices and maintain across firmware updates. Because these are encrypted using RSA, there is no perfect forward secrecy and any attacker who has extracted these keys can decrypt the login exchange when it is made over TLS.
 - Configuration backups are encrypted with the same static key across any device. Any owner who has extracted this key can decrypt any configuration backup.
