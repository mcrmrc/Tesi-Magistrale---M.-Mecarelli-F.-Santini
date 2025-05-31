from scapy.all import *
import threading 
import argparse
import mymethods

parser = argparse.ArgumentParser()
parser.add_argument('--host_ip',type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
parser.add_argument('--host_iface',type=str, help="Intefaccia di rete dove l'host riceverà i pacchetti ICMP")
#parser.add_argument('--provaFlag',type=int, help="Comando da eseguire")

event = threading.Event()
sniffed_data=None 
host_ip=None
host_iface=None
proxy_ip=None
ip_attacker=None

def conn_attaccante():
    event.wait()  
    sniffer.stop()
    print(f"Si stabilisce una connessione con {ip_attacker}")
    pkt = IP(dst=ip_attacker)/ICMP() / "".join( "__CONNECT__ " )
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{ip_attacker} is alive")
        #ans.show()
        print("Proxy IPs: {}".format(proxy_ip))
    else:
        print(f"No reply: {ip_attacker} is not responding") 

def send_data():
    print("Waiting to start the connection...")
    event.wait()  
    sniffer.stop()
    print("__CONNECT_ received. Sending data...") 
    command=input("Inserisci il comando. Inserisci 'exit' o 'quit' per terminare\n>>>\t")
    while command not in ["exit","quit"]: 
        print(command)
        command=input(">>>\t")
    exit(0)

def packet_callback(packet):
    print("Packet received: {}".format(packet.summary()))
    global ip_attacker, proxy_ip
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if b'__CONNECT__' in payload:
            print("Found __CONNECT__")
            ip_attacker= packet[IP].src
            proxy_ip= payload.decode().replace('__CONNECT__',"").strip().split(",")
            #print("Attacker IP: {}".format(ip_attacker))
            #print("Payload: {}".format(payload)) 
            #print("Proxy IPs: {}".format(proxy_ip))
            event.set()




if __name__=="__main__":
    print("Main function") 
    args=mymethods.check_args()
    if args.host_ip is None or args.host_iface is None:
        print("Devi specificare l'IP e l'interfaccia di rete dell host")
        print(mymethods.supportedArguments)
        exit(0) 
    global sniffer
    try:
        sniffer= AsyncSniffer(
            filter=f"icmp and dst host {args.host_ip}" 
            #,count=1 
            ,prn=packet_callback 
            #,store=True 
            ,iface=args.host_iface 
        ) 
        sniffer.start()
    except Exception as e:
        print("an Exception has occured: {e}") 
        exit(1) 
    #thread = threading.Thread(target=sniff_4_start)
    #thread.start() 
    conn_attaccante()


def sniff_4_start():
    print("Sniffing for __CONNECT__ in the ICMP packets...")
    try:
        sniffed_packets = sniff( 
            filter="icmp and dst host {}".format(host_ip) 
            #,count=1
            ,prn=packet_callback 
            #,store=True
            ,iface="{}".format(host_iface) 
        )
        sniffed_packets.summary()
        if sniffed_packets is None:
            print("No packets sniffed.")
            raise Exception("No packets sniffed.")
        event.set()
        sniffer.stop()
    except KeyboardInterrupt:
        print("Sniffing stopped by user.") 
        exit(1) 