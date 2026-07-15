from scapy.all import *
import threading 

event = threading.Event()
sniffed_data=None 

def send_data():
    print("Data sent after sniffing started.")
    event.wait()  
    print("__CONNECT_ received...\nSending data...")
    

def packet_callback(packet):
    print("Packet received: {}".format(packet.summary()))
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if b'__CONNECT__' in payload:
            print("Found __CONNECT__ in ICMP packet payload.")
            ip_attacker= packet[IP].src
            proxy_ip= payload.decode().replace('__CONNECT__',"").strip().split(",")
            print("Attacker IP: {}".format(ip_attacker))
            print("Payload: {}".format(payload)) 
            print("Proxy IPs: {}".format(proxy_ip))
            #event.set()

def sniff_4_start():
    print("Sniffing for __CONNECT__ in the ICMP packets...")
    try:
        sniffed_packets = sniff( 
            filter="icmp and dst host" #and icmp.type == 8 and icmp.payload.__contains__(b'__CONNECT__') 
            #,count=1
            ,prn=packet_callback
            #,prn=lambda x: True 
            #    if x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(RAW) and b'__CONNECT__' in bytes(x[ICMP].payload) 
            #    else None #b'__CONNECT__' in x.load else False
            ,store=True
            ,iface="Ethernet 2" 
        )
        sniffed_packets.summary()
        if sniffed_packets is None:
            print("No packets sniffed.")
            raise Exception("No packets sniffed.")
        event.set()
    except KeyboardInterrupt:
        print("Sniffing stopped by user.") 
        exit(0)
        #raise SystemExit(0) 

if __name__=="__main__":
    print("Main function")
    #thread = threading.Thread(target=sniff_4_start)
    #thread.start()
    sniff_4_start()
    print("Sniffing started...")
    exit(0)
    send_data()
    