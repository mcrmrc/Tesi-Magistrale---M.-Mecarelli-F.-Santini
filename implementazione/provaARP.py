from scapy.all import *

destinazioni = ["192.168.56.101", "192.168.56.102"]
pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=destinazioni)
sendp(pkt, iface="Ethernet 2", verbose=False)

#Per far rispondere la maccchian e l'host abbiamo modificato la VM così:
# aggiunto interfaccia NAT
# aggiunta interfaccia solo host


#Scapy uses ARP to find the MAC address. Try this first:
# arp_resp = arping("192.168.56.101")

#Make sure your host can ARP the VM outside Scapy. In PowerShell:
# ping 192.168.1.X
# arp -a

#Scapy might be trying to use the wrong network interface. 
# You can check and manually set it:
# conf.iface
# To set it manually:
# conf.iface = "Ethernet"  
# To list all interfaces:
# print(get_if_list())
