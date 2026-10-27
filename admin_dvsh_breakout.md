An issue was found in the `dvcmd` and `dvmgmt` in the Davolink "Minion"-themed
Wireless Access Points that act as command brokers/dispatchers for the
restricted `/usr/sbin/dvsh` shell that `admin` logs into by default when
accessing the device over SSH. A lack of sanity checks or input validation in
the `cmd_sys_user_passwd_change` function allows a user authenticated to the
device as `admin` to escape the shell and run arbitrary commands on the
device.

This function takes `param1` and `param2` like any other C function: `param1`
is the number of arguments and `param2` is a pointer to a list of arguments.
(`passwd` is `param2[0]`, the username of the user whose password is to be
changed and `*(passwd + 4)` -- 4 words ahead for a 32-bit system -- is the
username of the user whose password is to be changed. An attacker will then be
prompted to enter the new password twice. This is checked to ensure that it is
at least ten characters in length, containing entries from lower-, upper-,
numeric, and "special" character classes. This is the only sanity-checking on
the input, which will eventually be fed into
```
snprintf(acstack_90, 0x80, "echo -e "\%s\n%s\n" | busybox /bin/passwd %s > /dev/null 2>&1",
    acStack_110, acstack_110, local_120);
dv_system(acStack_90);
```
The first two strings formatted into `acStack_90` are enclosed in double-quotes
but the username, a pointer to which is in local_120, is not.

At first this would seem to be a classic command injection, but there is one
significant hurdle: each item placed on the line sent to dvsh is treated as an
individual argument, so spaces are interpreted as delimeters; if an attacker
passes in `admin;touch /tmp/foobar` then `dvsh` will interpret `admin;touch` as
`argv[1] (*(param + 4))` and `/tmp/foobar` will be in `argv[2] (*(param + 8))`,
which does not play a part in this function. The trick is to use `/bin/ash`
string manipulation and pre-set environment variables to circumvent this. The
environment variable `PS4` is set to `> ` (with the trailing space) by default,
so `${PS4:0:1}` is `>` and `${PS4:1:2}` is ` ` (a single whitespace character).
Because, again, there are no sanity checks on the value of the username, once
an attacker is in the `dvsh` session they need only to type `SYSTEM` then
`USER` to get into the right part of the `dvmgmt` console, then type
```c
passwd stealthemoon;/bin/telnetd${PS4:1:2}-l${PS4:1:2}/bin/sh
```
and two of (the same) password that meets the above criteria to launch a
`telnet` server on `23/tcp`. (Do not use quotes around the second argument as
the tokenizer in `dvsh` delivers the needed isolation.) After that just
`telnet` in. Even if the SSH session used the `admin` user, the command is
actually dispatched to the `dvmgmt` process, which runs as `root`, so the device
has been owwned.
