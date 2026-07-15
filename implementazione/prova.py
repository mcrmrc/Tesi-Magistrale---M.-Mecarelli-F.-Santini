from scapy.all import *

ip = "192.168.56.101"
pkt = IP(dst=ip)/ICMP() / "Hello, world!"
ans = sr1(pkt, timeout=2, verbose=1)

if ans:
    ans.show()
else:
    print("No reply")


