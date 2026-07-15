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

def callback_attacker_wait_proxy_update(ip_vittima, thread_lock, thread_proxy_response, event_proxy_update): 
    def callback(packet):
        print(f"callback attacker_wait_proxy_update received:\n\t{packet.summary()}")
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
            try:
                confirm_text=com.CONFIRM_VICTIM+ip_vittima+ipaddress.ip_address(packet[IP].src).compressed
            except Exception as e:
                print(f"callback attacker_wait_proxy_update: {e}", file=sys.stderr)
                com.update_thread_response(
                    packet[IP].src
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
                    packet[IP].src
                    ,thread_lock
                    ,thread_proxy_response
                    ,response=True
                )
                if not event_proxy_update.get(packet[IP].src).is_set():
                    com.set_threading_Event(event_proxy_update.get(packet[IP].src))
    return callback

#-----------------------------------------
def reset_event_update_foreach_proxy(proxy_list:list=None,event_proxy_update:dict=None):
    try:
        if not com.is_list(proxy_list) or len(proxy_list)<=0:
            raise ValueError(f"proxy_list non è una lista o è vuota: {proxy_list}")
        if not com.is_dictionary(event_proxy_update):
            raise ValueError(f"La lista degli eventi non è un dizionmario: {event_proxy_update}")
    except Exception as e:
        raise Exception(f"reset_event_update_foreach_proxy: {e}") 
    for proxy in proxy_list:
        event_proxy_update.get(proxy).clear() 

def create_event_update_foreach_proxy(proxy_list:list=None):
    try:
        if not com.is_list(proxy_list) or len(proxy_list)<=0:
            raise ValueError(f"proxy_list non è una lista o è vuota: {proxy_list}")
    except Exception as e:
        raise Exception(f"create_event_update_foreach_proxy: {e}")
    event_proxy_update={}
    for proxy in proxy_list:
        event_proxy_update.update({proxy:com.get_threading_Event()})    
    reset_event_update_foreach_proxy(proxy_list, event_proxy_update)
    #print(f"Eventi creati:\t{event_proxy_update}")
    print("Per ogni proxy creato il proprio evento di aggiornamento 'proxy_update'")
    return event_proxy_update 

def sanifica_lista_proxy(proxy_list:list=None):
    try: 
        com.is_list(proxy_list)
    except Exception as e:
        raise Exception(f"sanifica_lista_proxy: {e}") 
    new_proxy_list=[address for proxy in proxy_list if (address:=com.is_valid_ipaddress(proxy)) is not None]
    print(f"Lista proxy sanificata: {new_proxy_list}")
    return new_proxy_list

#-----------------------------------------
def get_value_of_parser(args):
    if args is None: 
        raise Exception("get_value_of_parser: Nessun argomento passato") 
    return (args.file_path) 

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
    return mymethods.check_args(parser)

#-----------------------------------------
class Attacker:
    default_file_path:str = "./attack_file.json"

    def __init__(self):
        try: 
            args=get_args_from_parser()
            if not check_value_in_parser(args): 
                raise ValueError("Argomenti nel parser non corretti") 
            file_path=get_value_of_parser(args) 
        except Exception as e: 
            print(f"__init__ define args: {e}", file=sys.stderr)
            exit(1)  
        try:  
            #print(f"\tFile non presente {not os.path.exists(file_path)}\n\tFormato sbagliato: {not str(file_path).endswith(".json")}")
            if not os.path.exists(file_path) or not str(file_path).endswith(".json"):
                if os.path.exists(self.default_file_path):
                    #print(f"\tFile di configurazione {file_path}  non trovato, si usa quello di default")
                    file_path=self.default_file_path
                else:
                    print("\tConfigurazionedi default non trovata")
                    raise FileNotFoundError(f"I file {file_path} e {self.default_file_path} non sono presenti")
        except Exception as e: 
            print(f"__init__ file exist: {e}", file=sys.stderr)
            exit(1)  
        try: 
            with open(file_path, 'r') as file:
                attack_file = json.load(file)
                print(f"File di configurazione {file_path} caricato correttamente")
        except Exception as e: 
            print(f"__init__ json load: {e}", file=sys.stderr) 
            exit(1)  
        try:
            self.attack_function = singleton.AttackType().get_attack_function(attack_file.get("attack_function"))
            if not isinstance(self.attack_function, dict) or len(self.attack_function.items())!=1:
                print(f"Funzione di attacco non definita ",
                      f"non è un dizionario ma {type(self.attack_function)}" if not isinstance(self.attack_function, dict) 
                      else f"funzioni ricavate {len(self.attack_function.items())}" if len(self.attack_function.items())!=1
                      else None
                )
                self.attack_function=singleton.AttackType().choose_attack_function() 
            print(f"Attacco selezionato: {self.attack_function}")
        except Exception as e:
            print(f"__init__ attack type: {e}", file=sys.stderr)
            exit(1) 
        
        try:
            self.ip_vittima = com.is_valid_ipaddress(attack_file.get("ip_vittima", None))  
            self.ip_host = com.is_valid_ipaddress(attack_file.get("ip_host", None))
            if self.ip_vittima is None or self.ip_host is None:
                raise ValueError("L'indirizzo IP della vittima o del host non è valido")
            print(f"IP vittima valido: {self.ip_vittima }")
            print(f"IP host valido: {self.ip_host }")
        except Exception as e:
            print(f"__init__ ip address: {e}", file=sys.stderr)
            exit(1) 
        try:  
            self.proxy_list = [
                addr 
                for x in attack_file.get("proxy_list", []) 
                for value in x.values() 
                if (addr:=com.is_valid_ipaddress(value)) is not None
            ] 
            print(f"Lista proxy sanificata")
            self.event_proxy_update=create_event_update_foreach_proxy(self.proxy_list) 
        except Exception as e:
            print(f"__init__ proxy list: {e}", file=sys.stderr)
            exit(1) 
        try:
            #self.check_available_proxies() 
            result=com.setup_thread_foreach_proxy(self.proxy_list,self.attacker_wait_proxy_update)
            self.thread_lock,self.thread_proxy_response,self.thread_list=result
            for proxy in self.proxy_list: 
                try:
                    thread=self.thread_list.get(proxy)
                    if not isinstance(thread, threading.Thread):
                        raise Exception(f"thread non valido {thread}")
                    if thread.ident is None: 
                        thread.start() 
                        print(f"\tProxy:{proxy.compressed}\tThread ID: {thread.ident}") 
                except Exception as e:
                    print(f"check_available_proxies: {e}")
                    continue
                if self.confirm_connection_to_proxy(proxy) and self.wait_conn_from_proxy(proxy):
                    print(f"Connessione stabilita con {proxy}") 
                    com.update_thread_response(proxy, self.thread_lock, self.thread_proxy_response, True)
                else: 
                    print(f"Connessione fallita con {proxy}") 
        except Exception as e:
            print(f"__init__ setup thread: {e}") 
            exit(0)
        
        
        
    def check_available_proxies(self): 
        try:
            if not com.is_list(self.proxy_list) or len(self.proxy_list)<=0: 
                raise ValueError("check_available_proxies: lista proxy non valida")
            com.is_valid_ipaddress_v4(self.ip_vittima) 
        except Exception as e:
            raise Exception(f"check_available_proxies: {e}")
        print(f"Controllo connessione per i proxy\t{self.proxy_list}") 
        result=com.setup_thread_foreach_proxy(self.proxy_list,self.attacker_wait_proxy_update)
        self.thread_lock,self.thread_proxy_response,self.thread_list=result
        for proxy in self.proxy_list.copy():
            try:
                if com.is_valid_ipaddress(proxy) is None:
                    raise ValueError(f" Indirizzo IP {proxy} non valido")
            except Exception as e:
                print(f"check_available_proxies: {e}")
                continue
            try:
                thread=self.thread_list.get(proxy)
                if not isinstance(thread, threading.Thread):
                    raise Exception(f"thread non valido {thread}")
                thread.start() 
                print(f"Thread started ID: {thread.ident} \t Proxy:{proxy}")
            except Exception as e:
                print(f"check_available_proxies: {e}")
                continue 
            if self.confirm_connection_to_proxy(proxy) and self.wait_conn_from_proxy(proxy):
                print(f"Connessione stabilita con {proxy}") 
                com.update_thread_response(proxy, self.thread_lock, self.thread_proxy_response, True)
            else: 
                print(f"Connessione fallita con {proxy}") 
        for proxy,thread in self.thread_list.items():
            if thread.is_alive(): 
                print(f"{thread} è ancora vivo")
                com.set_threading_Event(self.event_proxy_update.get(proxy))
                thread.join() 
        elimina_proxy_nonconnessi(self.thread_lock, self.thread_proxy_response, self.proxy_list) 
        print(f"Proxy disponibili dopo eliminazione\t{self.proxy_list}")
    
    def attacker_wait_proxy_update(self,proxy): 
        #print("\n\t(＾▽＾)\tattacker_wait_proxy_update\n") 
        confirm_text=com.CONFIRM_VICTIM 
        if isinstance(self.ip_vittima, ipaddress.IPv4Address) or isinstance(self.ip_vittima, ipaddress.IPv6Address):
            confirm_text+=self.ip_vittima.exploded 
        else:
            raise ValueError(f"Indirizzo IP vittima non valido {str(self.ip_vittima)}")
        confirm_text+="_" 
        if isinstance(proxy, ipaddress.IPv4Address)or isinstance(proxy, ipaddress.IPv6Address):
            confirm_text+=proxy.compressed 
        else:
            raise ValueError(f"Indirizzo IP proxy non valido {str(proxy)}") 
        #print ("Confirm_text: ",confirm_text)
        if len(confirm_text.split("_"))!=7:
            raise ValueError(f"Testo di conferma non valido") 
        print("Testo di conferma impostato correttamente")
        checksum=mymethods.calc_checksum(confirm_text.encode()) 
        try:
            interface_4_proxy= mymethods.iface_from_IP(proxy)
        except Exception as e:
            raise Exception(f"attacker_wait_proxy_update: {e}")
        if interface_4_proxy is None:
            raise ValueError("Interfaccia non valida")
        print(f"Interfaccia per {proxy} -> {interface_4_proxy}")
        args={
            "filter":f"icmp and icmp[0]==8 and src {proxy} and icmp[4:2]={checksum}"
            #,"count":"1" 
            ,"prn":callback_attacker_wait_proxy_update
            #,"store":True 
            ,"iface":interface_4_proxy
        } 
        try:
            event_thread=self.event_proxy_update.get(proxy)
            thread_sniffer,thread_timer=com.sniff_packet(args,event=event_thread) 
            com.wait_threading_Event(event_thread) 
        except Exception as e:
            raise Exception(f"attacker_wait_conn_from_proxy: {e}") 
        if thread_sniffer.running: 
            thread_sniffer.stop()  
        if thread_timer.is_alive():
            thread_timer.cancel()  
        thread_response=com.get_thread_response(proxy,self.thread_lock,self.thread_proxy_response)
        #print(f"Risposta del proxy: {thread_response}")
        if thread_response==True: 
            print(f"attacker_wait_proxy_update: Il proxy {proxy} è connesso a {self.ip_vittima}")
        else:
            print(f"attacker_wait_proxy_update: Il proxy {proxy} non è connesso a {self.ip_vittima}",file=sys.stderr)  
        return thread_response  
    
    def confirm_connection_to_proxy(self,proxy): 
        #print("\n\t(＾▽＾)\tconfirm_connection_to_proxy\n")
        try:
            com.is_valid_ipaddress(proxy.compressed)
            com.is_valid_ipaddress(self.ip_vittima.compressed)
            com.is_valid_ipaddress(self.ip_host.compressed)
        except Exception as e:
            raise Exception(f"confirm_connection_to_proxy: {e}") 
        data=com.CONFIRM_ATTACKER+self.ip_vittima.compressed
        if com.send_packet(data.encode() ,proxy.compressed):  
            print(f"\tconfirm_connection_to_proxy: {proxy} ha risposto")
            return True 
        print(f"\tconfirm_connection_to_proxy: {proxy} non ha risposto")
        return False
    
    def wait_conn_from_proxy(self,proxy:ipaddress.IPv4Address|ipaddress.IPv6Address=None): 
        #print("\n\t(＾▽＾)\twait_conn_from_proxy\n")
        try:
            if proxy is None or (not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address)):
                raise Exception(f"Il proxy non è un indirizzo IP: {type(proxy)}")
        except Exception as e:
            print(f"Exception: {e}")
            return False
        confirm_text=com.CONFIRM_PROXY+self.ip_vittima.compressed+proxy.compressed
        checksum=mymethods.calc_checksum(confirm_text.encode())
        try:
            interface_4_proxy= mymethods.iface_from_IP(proxy)
        except Exception as e:
            raise Exception(f"attacker_wait_proxy_update: {e}")
        if interface_4_proxy is None:
            raise ValueError(f"Interfaccia non valida: {interface_4_proxy}")
        print(f"wait_conn_from_proxy: {singleton.AttackType().get_filter_from_function(next(iter(self.attack_function)))}")
        args={
            "filter":f"icmp and icmp[0]==8 and src {proxy} and icmp[4:2]={checksum}" 
            #,"count":1 
            ,"prn":callback_wait_conn_from_proxy
            #,"store":True 
            ,"iface":interface_4_proxy
        }
        try:
            self.event_pktconn=com.get_threading_Event()
            self.sniffer,self.pkt_timer,=com.sniff_packet(args,event=self.event_pktconn) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_proxy: {e}") 
        print("verranno fermati lo sniffer e il timer")
        com.stop_sinffer(self.sniffer)
        if com.stop_timer(self.pkt_timer): 
            print(f"\twait_conn_from_proxy: Connessione confermata da {proxy}")
            return True
        print(f"\twait_conn_from_proxy: Connessione non confermata da {proxy}")
        return False 
    
    
    

if __name__=="__main__":
    print("Ciao")
    attacker=Attacker()