from scapy.all import *
import threading 
import argparse
import mymethods
import time

parser = argparse.ArgumentParser()
parser.add_argument("--ip_host",type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
#parser.add_argument('--provaFlag',type=int, help="Comando da eseguire")

event_conn_pkt = threading.Event()
packet_received_event = threading.Event()
sniffed_data=None 
ip_host=None
host_iface=None
proxy_ip=[] 

def conn_attaccante():
    event_conn_pkt.wait()  
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
    event_conn_pkt.wait()  
    sniffer.stop()
    print("__CONNECT_ received. Sending data...") 
    command=input("Inserisci il comando. Inserisci 'exit' o 'quit' per terminare\n>>>\t")
    while command not in ["exit","quit"]: 
        print(command)
        command=input(">>>\t")
    exit(0) 

def sniffer_timeout():
    global sniffer
    if not packet_received_event.is_set():
        print("Timeout: No packet received within 60 seconds")
        sniffer.stop() 
        event_conn_pkt.set()

def proxy_callback(packet):
    print("Packet received: {}".format(packet.summary()))
    global ip_attacker, proxy_ip, timeout_timer
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        if b'__CONNECT__' in bytes(packet[Raw].load):
            print("Found __CONNECT__")
            print(proxy_ip)
            proxy_ip.append(packet[IP].src) if packet[IP].src not in proxy_ip else None
            print(proxy_ip)
            #num_proxy = packet[Raw].load.replace("__CONNECT__","")
            print("Proxy: {}".format(packet[IP].src))
            print("Payload: {}".format(bytes(packet[Raw].load))) 
            #print(f"Num Proxy: {num_proxy}")
            print("Proxy IPs: {}".format(proxy_ip))
            packet_received_event.set()
            timeout_timer.cancel()
            event_conn_pkt.set()

def conn_proxy():
    global sniffer, gateway, timeout_timer
    num_proxy=len(proxy_ip)
    print(f"Num Proxy: {proxy_ip}")
    print(mymethods.iface_from_IP(gateway)[1])
    sniffer= AsyncSniffer(
        filter=f"icmp and dst {args.ip_host}" 
        #,count=1 
        ,prn=proxy_callback 
        #,store=True 
        ,iface=mymethods.iface_from_IP(gateway)[1] 
    ) 
    timeout_timer = threading.Timer(10, sniffer_timeout)
    sniffer.start() 
    timeout_timer.start()
    event_conn_pkt.wait()
    if not sniffer.running:
        return
    sniffer.stop()
    sniffer.join() 
    #time.sleep(20)
    if len(proxy_ip)<= num_proxy:
        print("Nessun Proxy aggiunto")
        return
    icmp_id=mymethods.calc_checksum(b"__CONNECT__ ")
    pkt = IP(dst=proxy_ip[num_proxy])/ICMP(id=icmp_id) / b"__CONNECT__ "
    print(pkt)
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{proxy_ip[num_proxy]} is alive")
        #ans.show()
        return True
    else:
        print(f"No reply: {proxy_ip[num_proxy]} is not responding")
        return False

if __name__=="__main__":
    print("Main function") 
    global gateway,sniffer
    args=mymethods.check_args(parser)
    if args.ip_host is None or args.ip_host is "":
        print("Devi specificare l'IP e l'interfaccia di rete dell host")
        mymethods.supportedArguments(parser)
        exit(0) 
    gateway=args.ip_host.split(".") 
    gateway[3]="0"
    gateway=".".join(gateway)
    try:
        conn_proxy()
    except Exception as e:
        print(f"An Exception has occured: {e}") 
        exit(1) 
    #thread = threading.Thread(target=sniff_4_start)
    #thread.start() 
    exit(0)
    conn_attaccante()

