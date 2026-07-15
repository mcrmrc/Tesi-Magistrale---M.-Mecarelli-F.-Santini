from scapy.all import IP, ICMP,Raw, sr1, AsyncSniffer 
from scapy.all import *
import threading 
import argparse
import mymethods
import time 
import comunication_methods as com
import re

sniffed_data=None  

def conn_attaccante():
    com.pkt_conn_received.wait()  
    com.sniffer.stop()
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
    com.pkt_conn_received.wait() 
    com.sniffer.stop()
    print("__CONNECT_ received. Sending data...") 
    command=input("Inserisci il comando. Inserisci 'exit' o 'quit' per terminare\n>>>\t")
    while command not in ["exit","quit"]: 
        print(command)
        command=input(">>>\t")
    exit(0)  

#--Parte 2--# 
def done_waiting_timeout():
    if len(proxy_ip)>= num_proxy: 
        print("Timeout: Enough proxy has arrived")
        com.sniffer.stop() 
        com.pkt_conn_received.set()
    else:
        print("Timeout: Not enough proxy has arrived")
        global timeout_done_waiting
        timeout_done_waiting = threading.Timer(60, done_waiting_timeout)

def proxy_callback(packet):
    print("Packet received: {}".format(packet.summary()))
    global ip_attacker, proxy_ip, timeout_timer
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        if b'__CONNECT__' in bytes(packet[Raw].load):  
            if com.send_packet(packet[Raw].load,packet[IP].src):
                proxy_ip.append(packet[IP].src) if packet[IP].src not in proxy_ip else None
                print("Proxy: {}".format(packet[IP].src)) 
                print(f"Proxy IPs: {proxy_ip}") 
            else: 
                print(f"No reply: {packet[IP].src} is not responding")
            print(f"Necessari ancora {num_proxy-len(proxy_ip)} proxy")
        if len(proxy_ip)>= num_proxy:
            com.timeout_timer.cancel() 
            com.pkt_conn_received.set() 

def wait_conn_proxy(): 
    args={
        "filter":f"icmp and dst {ip_host}" 
        #,"count":1 
        ,"prn":proxy_callback 
        #,"store":True 
        ,"iface":mymethods.iface_from_IP(gateway_host)[1] 
    }
    com.sniff_packet(args,None) 
    global timeout_done_waiting
    timeout_done_waiting = threading.Timer(60, done_waiting_timeout)
    timeout_done_waiting.start()
    com.pkt_conn_received.wait() 
    if com.sniffer.running: 
        com.sniffer.stop() 
        com.sniffer.join() 
    if timeout_done_waiting.is_alive(): 
        timeout_done_waiting.cancel()
    if com.timeout_timer.is_alive(): 
        com.timeout_timer.cancel() 
    print(f"I proxy utilzzabili sono: {len(proxy_ip)}\n\t{proxy_ip}") 

#--Parte 1--#
def get_value_of_parser(args):
    print(args) 
    if not isinstance(args, argparse.Namespace) or args is None:
        print("Nessun argomento passato") 
        return False 
    global ip_host, gateway_host
    ip_host=args.ip_host
    gateway_host=mymethods.calc_gateway(ip_host)

    global num_proxy
    num_proxy=args.num_proxy

def check_value_in_parser(args): 
    if not isinstance(args, argparse.Namespace) or args is None:
        print("Nessun argomento passato") 
        return False
    if type(args.ip_host) is not str or re.match(com.ip_reg_pattern, args.ip_host) is None:
        print("Devi specificare l'IP del host con --ip_host")
        mymethods.supported_arguments(parser)
        return False
    if args.num_proxy is None or type(int(args.num_proxy)) is not int:
        print("Il numero di proxy non è un intero")
        return False
    return True

def get_args_from_parser():
    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip_host",type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
    parser.add_argument("--num_proxy",type=int, help="Numero dei proxy possibili")
    #parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")
    return mymethods.check_args(parser)

def def_global_variables():
    global proxy_ip
    proxy_ip=[]

#-- Main --#
if __name__=="__main__":
    #1) Definizione degli argomenti
    try:
        def_global_variables()
        args=get_args_from_parser()
        if not check_value_in_parser(args): 
            exit(0) 
        get_value_of_parser(args)
    except Exception as e: 
        print(f"Eccezione: {e}")
        exit(1)
    #2) Connessione con tutti i proxy
    try:
        wait_conn_proxy()
    except Exception as e:
        print(f"An Exception has occured: {e}") 
        exit(1)  
    exit(0) 
    #thread = threading.Thread(target=sniff_4_start)
    #thread.start()
    conn_attaccante()

