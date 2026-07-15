from scapy.all import IP, ICMP, Raw, sr1, AsyncSniffer
from scapy.all import *
import threading 
import argparse
import mymethods
import time
import re

CONNECT="__CONNECT__"
CONFIRM_ATTACKER="__CONFIRM_ATTACKER__"
CONFIRM_VICTIM="__CONFIRM_VICTIM__"
CONFIRM_PROXY="CONFIRM_PROXY"
LAST_PACKET="__END__"
READY="__READY__"

ip_reg_pattern=r"^\d+\.\d+\.\d+\.\d+$"

pkt_conn_received = threading.Event() 
def wait_pkt_conn_received():
    pkt_conn_received.wait() 
    pkt_conn_received.clear()
def set_pkt_conn_received():
    pkt_conn_received.set()

def send_packet(data:bytes=None,ip_dst=None, time=10,icmp_seq=999):
    if type(ip_dst) is not str or re.match(ip_reg_pattern, ip_dst) is None :
        raise Exception("IP non valido")
    if data is None or type(data) is not bytes: 
        print(data)
        print(type(data))
        raise Exception("I dati devono essere bytes")  
    
    icmp_id=mymethods.calc_checksum(data) 

    pkt = IP(dst=ip_dst)/ICMP(id=icmp_id,seq=icmp_seq) / data  
    print(f"Sending...")
    print(f"{pkt.summary()}") #print(f"{pkt.show()}")
    ans = sr1(pkt, timeout=time, verbose=1)
    if ans:
        print(f"Reply: \t{ip_dst} is alive\n")
        #ans.show()
        return True 
    print(f"No reply: \t{ip_dst} is not responding\n")
    return False

def sniffer_timeout():
    global sniffer
    if not pkt_conn_received.is_set():
        print("Timeout: No packet received within 60 seconds")
        sniffer.stop() 
        set_pkt_conn_received()

def nonusable_callback(packet):
    global ip_attacker, proxy_ip, timeout_timer
    print("comunication_callback")
    print("Packet received: \n{}".format(packet.summary()))     
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        if CONNECT.encode() in packet[Raw].load:
            print(f"{packet[IP].src} si vuole collegare") 
            #proxy_ip.append(packet[IP].src) if packet[IP].src not in proxy_ip else None
            #num_proxy = packet[Raw].load.replace(CONNECT,"")
            print("Mittente: \t{}".format(packet[IP].src))
            print("Payload: \t{}".format(bytes(packet[Raw].load)))  
            set_pkt_conn_received()

def sniff_packet(args:dict,timeout_time=60):
    global sniffer, gateway,timeout_timer

    accepted_key_dict=[
        "iface","filter","prn","store","count", "timeout" ,"lfilter", 
        "opened_socket","session","started_callback","offline","quiet" 
    ] 
    if args is None or type(args) is not dict:
        raise Exception("Argomenti non validi") 
    if timeout_time is not None and type(int(timeout_time)) is not int: 
        raise Exception("Tempo non accettato") 
    timeout_time=int(timeout_time) if timeout_time is not None else timeout_time
    invalid_args=[key for key in args if key not in accepted_key_dict]
    if len(invalid_args):
        raise ValueError(f"Invalid keys in dictionary {invalid_args}")
    #if type(ip_host) is not str or re.match(ip_reg_pattern, ip_host) is None:
        #raise Exception("IP non valido") 
    #if type(gateway) is not str or re.match(ip_reg_pattern, gateway) is None:
        #raise Exception("Sniffer non presente") 
    sniffer= AsyncSniffer(
        **args
    ) 
    timeout_timer = threading.Timer(timeout_time, sniffer_timeout)
    sniffer.start()
    timeout_timer.start() 

def set_args_parser():
    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip_host",type=str, help="IP dell'attaccante")
    return mymethods.check_args(parser)

def check_connessione(ip_dst,args=None):
    global sniffer, timeout_timer
    if type(ip_dst) is not str or re.match(ip_reg_pattern, ip_dst) is None:
        raise Exception("IP non valido") 
    if args is None or type(args) is not dict:
        raise Exception("Argomenti non validi") 
    
    print(f"Controllo la connessione con {ip_dst}...")
    sniff_packet(args) 
    wait_pkt_conn_received()
    if sniffer.running:
        sniffer.stop()
        sniffer.join()
    if timeout_timer.is_alive():
        timeout_timer.cancel()
        data=CONNECT.encode()
        if send_packet(data,ip_dst):
            print(f"Stabilita connessione con {ip_dst}")
            return True
    print(f"Nessuna connessione con {ip_dst}")
    return False

def test_connection(ip_dst,args:dict,data=None,timeout_time=60):
    global sniffer, timeout_timer
    if type(ip_dst) is not str or re.match(ip_reg_pattern, ip_dst) is None:
        raise Exception("IP non valido") 
    print(f"Tento la connessione con {ip_dst}...")
    if type(data) is not str or data is None:
        raise Exception("Dati non validi") 
    #data="".join(f"{CONNECT} {ip_vittima}")
    if send_packet(data,ip_dst): 
        if args is None or type(args) is not dict:
            raise Exception("Argomenti non validi")
        sniff_packet(args) 
        wait_pkt_conn_received()
        if sniffer.running:
            sniffer.stop()
            sniffer.join()
            print(f"Connection with {ip_dst} has being succesfull")
            return True
    print(f"{ip_dst} is not responding")
    return False

if __name__=="__main__":
    global ip_host, gateway, ip_proxy

    ip_dst="192.168.56.101"
    args_dict={
        "filter":f"icmp and src {ip_dst}"
        #,"count":1 
        ,"prn":nonusable_callback 
        #,"store":True 
        ,"iface":mymethods.iface_from_IP(ip_dst)[1]
    }
    data=f"{CONNECT} 192.168.56.102"
    test_connection(ip_dst,args_dict,data)
    exit(0)
    args=set_args_parser()
    if args.ip_host is None :
        print("Devi specificare l'IP dell'attaccante")
        mymethods.supported_arguments(parser)
        exit(0)
    if type(args.ip_host) is not str or re.match(ip_reg_pattern, args.ip_host) is None:
        raise Exception("IP host non valido")
    
    ip_host=args.ip_host
    gateway=".".join(
        ip_host.split(".")[index] if index!=3 else "0" 
        for index in range(len(ip_host.split(".")))
    )
    print(f"IP della macchina: {ip_host}")
    print(f"Gateway: {gateway}") 

    args_sniff={
        "filter": f"icmp and dst {ip_host}" 
        #,"count":1 
        ,"prn":nonusable_callback 
        #,store:True 
        ,"iface":mymethods.iface_from_IP(gateway)[1]  
    }
    sniff_packet(args_sniff)
    wait_pkt_conn_received() 
    if sniffer.running:
        sniffer.stop()
        sniffer.join() 
    
    ip_proxy = [
        "192.168.56.101"
        ,"192.168.56.103"
        ,"192.168.56.1"
        #,"192.168.56.xxx"
    ]  
    for proxy in ip_proxy: 
        send_packet(data=CONNECT.encode(), ip_dst=proxy)

def check_proxy_ipaddress(proxy_ip:list):
    not_corrected_ip=[]
    for proxy in proxy_ip:
        if re.match(ip_reg_pattern, proxy) is None:
            not_corrected_ip.append(proxy)
    return not_corrected_ip
