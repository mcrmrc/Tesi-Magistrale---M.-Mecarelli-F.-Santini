from scapy.all import * 

#ip = "192.168.56.101"
destinazioni = ["192.168.56.101", "192.168.56.102"]
file="payload.txt"
stringa=None
with open(file, "r") as f:
    stringa = f.read()
    print(stringa)

if stringa is None:
    pkt = IP(dst=destinazioni)/ICMP() / "Hello, world!"
    ans = sr1(pkt, timeout=2, verbose=1)
else:
    pkt = IP(dst=destinazioni)/ICMP() / stringa
    ans = sr1(pkt, timeout=2, verbose=1)

if ans:
    #print(f"{ip} is alive")
    ans.show()
else:
    #print(f"{ip} is not responding")
    print("No reply")


#send(IP(dst="192.168.56.101")/ICMP(), iface="Ethernet 2")

#See whether the packet is sent and if there's any response. 
# You can also sniff the interface to verify:
# sniff(filter="icmp", timeout=5)

#You should see:
# Who has 192.168.1.X? Tell 192.168.1.Y (Scapy packet)
# And ideally: 192.168.1.X is at ... (ARP reply)