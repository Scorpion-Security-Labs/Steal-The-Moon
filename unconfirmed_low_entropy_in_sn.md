Note in advance that this result is unconfirmed, and there is evidence to
suggest it does not completely hold. However, during testing, there appeared
to be a relationship between the MAC address and serial number of the Minions
routers. Two Bob routers were profiled:

```
Router A
MAC: 60:29:D5:85:AC:C0
S/N: DVW642ID20CDK03135
```
```
Router B
MAC: 60:29:D5:85:57:A0
S/N: DVW642ID20CDK01773
```

Router A was lost in a tragic soldering accident and could not cover from
its injuries. (You will be remembered!) Work here was completed on Router B.

Davolink encourages users of their support forum to include their MAC address
and serial number when making requests (and now I know why) and I have seen
counterexamples to the following analysis posted there, but in our testing -- 
which also included one other Bob and a Kevin -- the serial numbers have differed
only in the last four digits. Davolink reserves two OUIs: `00:08:52` and
`60:29:D5`. All of the Minions routers I have seen use only the latter. Consider
the last three octets of a MAC address as `rs:tu:vx`. In the observed cases,
`rs` always `0x85` and `x` was always `0`. In our cases case we were able to take
the other three digits as one single hexadecimal value `0xtuv` and write:
```
0xacc + 0x173 = 0xc3f = 3135
```
and
```
0x57a + 0x173 = 0x173 = 1773
```
deriving the last four of the serial number from the MAC address. This formula
held true for the four examples studied by Scorpion Labs. The values seen on
Davolink's "Minions" support forum demonstrate that this formula is not true
for every device, or is at best incomplete, but hints strongly that one of
these is generated from the other. If that relationship were to be uncovered
(we have not found it in the firmware) and found to be reversible then it
is possible that the entire default password schema can be derived from the
default SSID alone, which contains the last three octets of the MAC address.
