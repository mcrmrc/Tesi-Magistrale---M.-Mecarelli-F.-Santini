#https://thepythoncode.com/article/sniff-http-packets-scapy-python
#https://www.geeksforgeeks.org/packet-sniffing-using-scapy/
#https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sniffing/index.html
#
#

from scapy.all import *
import string 

redirectIP="192.168.56.102"
def packet_callback(packet):
    if packet.haslayer(ICMP) and packet.haslayer(IP): 
        print("Packet captured:")
        packet.show()
        
        newpacket=IP(id=packet[IP].id, dst=redirectIP)/ICMP(
            id=packet[ICMP].id, seq=packet[ICMP].seq) / packet[Raw].load
        #newpacket=packet[IP]/ packet[ICMP] / packet[Raw].load
        #newpacket[IP].dst=redirectIP
        print("New packet:")
        newpacket.show()
        ans = sr1(newpacket, iface="Ethernet 2", timeout=2, verbose=1) 
        if ans:
            print(f"{newpacket[IP].dst} is alive")
            ans.show()
        else:
            print(f"{newpacket[IP].dst} is not responding")
            print("No reply")


#iface: Specify the network interface to sniff on.
#count: The number of packets to capture. If omitted, sniffing will continue until stopped.
#filter: Apply a BPF (Berkeley Packet Filter) to capture only certain packets.
#prn: Define a callback function to execute with each captured packet.
#store: Whether to store sniffed packets or discard them.
try:
    packets = sniff(
        iface="Ethernet 2", 
        filter="icmp and src host 192.168.56.101",
        timeout=15,
        prn=packet_callback
    )
    #packets.summary()
except KeyboardInterrupt:
    print("Sniffing stopped by user.") 
print("Sniffing finished.") 



#Scapy can also store sniffed packets in a .pcap file, which can be analyzed later with tools like Wireshark. To save packets to a file, use the wrpcap() function:
#   Save captured packets to a file
#   wrpcap('captured.pcap', packets)

#Scapy can read packets from a .pcap file using the rdpcap() function or by setting the offline parameter in the sniff() function:
#   Read packets from a file
#   packets = rdpcap('captured.pcap')


#Try disabling the firewall temporarily on the VM to test:
#   On Windows: 
#   netsh advfirewall set allprofiles state off
#On Linux: 
#   sudo ufw disable (if ufw is used)


