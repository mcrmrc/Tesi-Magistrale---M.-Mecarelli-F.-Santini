#https://www.rfc-editor.org/rfc/rfc792

from scapy.all import IP, ICMP, send, srp, sendp, sr1, arping
import time


def bozza():

    destination="192.168.1.35"
    protocol=1  # ICMP protocol number

    packet= IP(dst=destination) / ICMP()

    #Type 8 for echo message; 0 for echo reply message.
    #packet= packet/ ICMP(type=8) / "Data"

    packet.show()
    #send(packet)
    resp=sr1(packet, timeout=2, verbose=1)
    if resp is not None:
        print("Received response:")
        resp.show()
    else:
        print("No response received.")
    #answered, unanswered  = sendp(packet)
    #print("Answered packets:")
    #print(answered)
    #for p in answered:
        #print(p[1].summary())

    arp_resp = arping("192.168.1.X")


from scapy.all import conf, get_if_list, IP, ICMP, send, srp, sendp, sr1, arping
#conf.iface="Ethernet"
#print(conf.iface)
#print(get_if_list())
print(arping("192.168.1.35"))

packet= IP(dst="192.168.1.35") / ICMP()
resp=sr1(packet, timeout=2, verbose=1)
if resp is not None:
    print("Received response:")
    resp.show()
else:
    print("No response received.")
