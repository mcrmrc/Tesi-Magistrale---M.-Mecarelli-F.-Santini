#https://thepythoncode.com/article/sniff-http-packets-scapy-python
#https://www.geeksforgeeks.org/packet-sniffing-using-scapy/
#https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sniffing/index.html
#
#

from scapy.all import *
import string

datiTrasmissione=[]

def unisciDati(dati, indexSeg=1, indexDati=2):
    #Si assume che i dati appartengano tutti alla stessa trasmissione
    # leggasi i pacchetti hanno lo stesso ID 
    if len(dati)==0 or len(dati[0])<3:
        print("Dati non validi")
        return []
    seg=-1
    payload=[] 
    while seg<=len(dati):
        #print("Seg: ", seg)
        for i in range(len(dati)): 
            if dati[i][indexSeg]==seg: 
                #print(dati[i][indexDati])
                payload.append(dati[i][indexDati]) 
        seg+=1 
    return payload

def sanitize(data):
    data = ''.join(char if char in string.printable else'' 
            for char in data)
    #data=data.replace('\n', ' ')
    #data=data.replace('\r', ' ')
    #data=data.replace('\t', ' ')
    #data=data.replace(' ', '_')
    return data.strip()

def packet_callback(packet):
    data=None
    if packet.haslayer(Raw):
        # Print the raw payload 
        data=sanitize(
            packet[Raw].load.decode( 'utf-8',errors='ignore')
        )
        #print(f"Raw Payload: {data}" ) 
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        # Print the source and destination IP addresses
        print(f"Source: {packet[IP].src}, Destination: {packet[IP].dst}")
        id=packet[ICMP].id
        seq=packet[ICMP].seq
        #print(f"Payload: {data}") 
        #print(f"Id: {id}") 
        #print(f"Seq: {seq}") 
        datiTrasmissione.append([id, seq, data])  
    # Print the packet summary
    #print(packet.summary())

    # Print the packet details
    #packet.show()


#iface: Specify the network interface to sniff on.
#count: The number of packets to capture. If omitted, sniffing will continue until stopped.
#filter: Apply a BPF (Berkeley Packet Filter) to capture only certain packets.
#prn: Define a callback function to execute with each captured packet.
#store: Whether to store sniffed packets or discard them.
try:
    packets = sniff(
        iface="Ethernet 2", 
        count=10,
        filter="icmp and src host 192.168.56.101",
        timeout=50,
        prn=packet_callback
    )
    #packets.summary()
except KeyboardInterrupt:
    print("Sniffing stopped by user.") 
print("Sniffing finished.") 
payload=unisciDati(datiTrasmissione)
print(payload)


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


