import ipaddress
import re
import sys
import subprocess
import threading 
import socket 
import urllib
import json
import os
import argparse
from utils_methods import sanitize_str, check_sniffer_args
from scapy.all import AsyncSniffer, ARP, Ether, conf, srp 
from check_type import *
from ..custom_enum import ATTACK_TYPE, ENTITY, EXIT_CASES
from ..classes import PARSER

class ARGS_FROM_FILE_CONFIG: 
    def __init__(self,config_file_path:str="./attack_file.json"): 
        if not is_string(config_file_path):
            raise TypeError("Percorso del file non è una stringa valida:",config_file_path)
        if not config_file_path.endswith(".json"):
            raise TypeError(f"File non è un JSON:",config_file_path)
        if not os.path.exists(config_file_path):
            raise FileNotFoundError(f"File non presente:",config_file_path)
        self.config_file_path=config_file_path 
        with open(self.config_file_path, 'r') as file: 
            print(f"File di configurazione {self.config_file_path} caricato correttamente") 
            self.json_file = json.load(file) 
        return {
            "ip_victim": self.ip_victim(), 
            "proxy_list": self.proxy_list(), 
            "attack_type": self.attack_type(), 
            "proxy_port": self.proxy_port(), 
            "num_proxy": self.num_proxy(), 
            "ip_attaccante": self.ip_attaccante(),
        }
    
    def ip_victim(self): 
        try:  
            return ipaddress.ip_address(
                self.json_file.get("ip_vittima", None) 
            )
        except Exception as e: 
            print(e) 
        return None
    
    def proxy_list(self):
        proxy_list:list[ipaddress._IPAddressBase]=[]
        for ip_proxy in self.json_file.get("proxy_list", []): 
            try: 
                proxy_list.append(
                    ipaddress.ip_address(ip_proxy)
                ) 
            except ValueError as v: 
                print(f"IP non valido: {v}")
            except Exception as e:
                print(f"{e}") 
        return proxy_list if len(proxy_list)>0 else None 
    
    def attack_type(self): 
        try:
            attack_type=ATTACK_TYPE.get_attack_method(
                self.json_file.get("attack_function", None)
                ) 
            if is_enum_member(attack_type,ATTACK_TYPE): 
                return attack_type 
        except Exception as e:
            print(f"{e}") 
        return None 
    
    def proxy_port(self): 
        try:
            proxy_port=int(self.config_file.get("proxy_port", None))
            if is_integer(proxy_port) and 0<proxy_port<65536: 
                return proxy_port 
        except Exception as e:
            print(f"{e}")  
            print(f"Porta {proxy_port} non valida") 
        return None 
    
    def num_proxy(self):
        try:
            num_proxy=int(self.config_file.get("num_proxy", None) )
            if is_integer(num_proxy): 
                return num_proxy 
        except Exception as e:
            print(f"{e}")
        return None

    def ip_attaccante(self): 
        try:
            ip_attaccante=ipaddress.ip_address(
                self.json_file.get("ip_attaccante", None) 
            )
            if is_ipaddress(ip_attaccante): 
                return ip_attaccante 
        except Exception as e: 
            print(f"{e}") 
        return None

class ARGS_FROM_COMMAND_LINE:
    def __init__(self, entita:ENTITY=None)->argparse.Namespace: 
        if not is_enum_member(entita, ENTITY): 
            raise TypeError("Entità non valida:",entita) 
        parser = argparse.ArgumentParser() 
        match entita:
            case ENTITY.ATTACKER:
                parser.add_argument(
                    "--file_path",
                    type=str, 
                    help="File di configurazione"
                )  
            case ENTITY.PROXY: 
                parser.add_argument(
                    "--ip_attaccante",
                    type=str, 
                    help="IP dell'attaccante"
                ) 
            case ENTITY.VICTIM:
                parser.add_argument(
                    "--num_proxy",
                    type=int, 
                    help="Numero dei proxy necessari"
                )
            case _: 
                raise ValueError("Entità non valida:",entita)
        args,unknown =PARSER.check_arguments(parser) 
        if not is_namespace(args):   
            raise TypeError(f"Namespace non valido: {args}") 
        if is_list(unknown) and len(unknown)>0: 
            raise ValueError(f"Argomenti sconosciuti: {unknown}") 
        try:
            match entita:
                case ENTITY.ATTACKER:
                    if not args.file_path or not is_string(args.file_path): 
                        raise ValueError(f"--file_path non specificato") 
                case ENTITY.PROXY: 
                    if not args.ip_attaccante or not is_string(args.ip_attaccante): 
                        raise ValueError(f"--ip_attaccante non specificato") 
                case ENTITY.VICTIM:
                    if not args.num_proxy or not is_integer(args.num_proxy): 
                        raise ValueError(f"--num_proxy non specificato") 
                case _: 
                    raise ValueError("Entità non valida:",entita)
        except ValueError as e:
            print(e) 
            #parser.print_help() 
            PARSER.print_supported_arguments(parser) 
            args=None 
        return args


def get_threading_Event()->threading.Event: 
    return threading.Event() 

def get_threading_Lock()->threading.Lock: 
    return threading.Lock()

def get_AsyncSniffer(args:dict=None): 
    if not is_dictionary(args): 
        raise Exception(f"GET:AsyncSniffer\targs is not a dictionary") 
    if check_sniffer_args(args):
        return AsyncSniffer( **args ) 
    return None

def get_timer(timeout_time=60, callback_function=None): 
    if is_callable_function(callback_function) and (timeout_time is None or is_time(timeout_time)): 
        return threading.Timer(timeout_time, callback_function)
    return None 

def get_shellProcess(command:str=""):
    def _shell(args:list=None, input_data=None, output_data=None, error_data=None): 
        return subprocess.Popen(
            args, 
            stdin=input_data,
            stdout=output_data,
            stderr=error_data,
            text=True,
            bufsize=1,
        ) 
    if not is_string(command): 
        raise TypeError("Il comando non è una stringa")
    if sys.platform == "win32":
        print("Il sistema è Windows...")
        return _shell(
            ["cmd.exe"] if command=="" else ["cmd.exe", "/c", command], 
            input=subprocess.PIPE, 
            output=subprocess.PIPE,
            error=subprocess.PIPE
        )
    elif sys.platform=="linux":
        print("Il sistema è Linux...")
        return _shell(
            ["bash"] if command=="" else ["bash", "-c", command], 
            input=subprocess.PIPE, 
            output=subprocess.PIPE,
            error=subprocess.PIPE
        )
    else: 
        raise Exception("Sistema operativo non supportato per l'apertura della shell.")


def get_local_IP(): 
    ip_address=None
    error=None
    try:
        s= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80)) 
        ip_address=ipaddress.ip_address(
            s.getsockname()[0]
        )
    except Exception as e: 
        error=e 
    finally:
        s.close()
    return ip_address, error

def ask_ip_address():
    input_ip=""
    while input_ip not in EXIT_CASES: 
        try: 
            input_ip=input(
                """Inserire indirizzo IP dell'host. 
                exit o quit per uscire:\n\t#
                """
            )
            return ipaddress.ip_address(input_ip.strip()) 
        except Exception as e: 
            print(e) 
    return None

def ask_proxy_port():
    try: 
        msg="Inserire porta proxy (0-65535):\n\t#"
        proxy_port=int(input(msg)) 
        if is_integer(proxy_port) and 0<proxy_port<65536: 
            return proxy_port
    except Exception as e:
        print(f"{e}")  
        print(f"Porta {proxy_port} non valida") 

def ask_num_proxy(): 
    try:
        print("Numero proxy non valido")
        msg="Inserire numero proxy (1-100):\n\t#"
        num_proxy=int(input(msg)) 
        if is_integer(num_proxy) and 0<num_proxy<100: 
            return num_proxy 
    except Exception as e:
        print(f"{e}") 
        print("Numero proxy non valido")
    return None 

def ask_attack_type(): 
    try: 
        attack_type=ATTACK_TYPE.choose_attack_function() 
        if is_enum_member(attack_type,ATTACK_TYPE): 
            return attack_type 
    except Exception as e:
        print(f"{e}") 
    return None 
        

def get_public_IP():
    return urllib.request.urlopen('https://api.ipify.org').read().decode('utf8') 

def get_hosts_attivi(): 
    def windows_get_network(self, ip_addr:ipaddress=None)->tuple[str,str]:
        if not is_ipaddress(ip_addr): 
            try:
                ip_addr=ipaddress.ip_address(ip_addr)
            except Exception as e: 
                raise Exception("windows_get_network: indirizzo non valido: ",e)
        comando='$info=Get-NetIPAddress| Where-Object {$_.IPAddress -eq "'+ip_addr.compressed+'"} | Select-Object IPAddress, PrefixLength; "$($info.IPAddress)/$($info.PrefixLength)"'
        print("COMANDO: ",comando)
        process= subprocess.Popen(
            ["powershell", "-Command",comando],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Communicate with the process to get the output and error
        stdout, stderr = process.communicate() 
        #print("Output:", stdout.decode())
        #print("Error:", stderr.decode())

        ip=stdout.decode().split("/",1)[0].strip()
        subnet=stdout.decode().split("/",1)[1].strip() 
        print("Indirizzo: ", ip)
        print("Subnet: ", subnet) 
        
        int_subnet=int(subnet) 
        extended_subnet="1"*int_subnet+"0"*(32-int_subnet) 
        print("extended_subnet: ", extended_subnet) 
        #negated_extended_subnet="0"*int_subnet+"1"*(32-int_subnet) 
        #print("negated_extended_subnet: ", negated_extended_subnet) 
        
        ip_bin="".join([f"{int(octet):08b}" for octet in ip.split(".")])
        #print("Int indirizzo: ",ip_bin)  
        network_bin="".join("1" if ip_b=="1" and msk_b=="1" else "0" for ip_b, msk_b in zip(ip_bin, extended_subnet))
        network=".".join(str(int(network_bin [i:i+8], 2)) for i in range(0, 32, 8)) 
        #print("AAAAAAA:", network)
        return network, subnet
    def linux_get_network(ip_addr:ipaddress=None)->tuple[str,str]:
        if not is_ipaddress(ip_addr): 
            try:
                ip_addr=ipaddress.ip_address(ip_addr)
            except Exception as e: 
                raise Exception("linux_get_network: indirizzo non valido: ",e) 
        command="ip route | awk '/"+str(ip_addr.compressed)+"/ {print $1}'"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate() 
        for voce in stdout.split("\n"): 
            if len(voce.split("/"))==2: 
                return voce.split("/") 
    #----------------------------------------
    #interface, ip, gateway=conf.route.route("0.0.0.0") 
    ip_addr=get_local_IP()[0]
    if sys.platform == "win32": 
        network,subnet=windows_get_network(ip_addr) 
    elif sys.platform=="linux": 
        network,subnet=linux_get_network(ip_addr) 
    else: raise Exception("OS non supportato: ",sys.version) 

    #print(f"Scanning: {network}/{subnet}")
    arp_request=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network+"/"+subnet) 
    result = srp(arp_request, timeout=3) 
    answer, noanswer= result 
    
    active_host=[]
    for res in answer.res: 
        active_host.append(res.answer.psrc) 
    inactive_host=[]
    for index in range(1,255):
        if f"192.168.1.{index}" in active_host: 
            #print(f"Host attivo: 192.168.1.{index}") 
            continue
        inactive_host.append(f"192.168.1.{index}")        
    return active_host, inactive_host 
    
def get_IPv6_scopeID(ip_addr:ipaddress.IPv6Address=None): 
    def _win_platform(): 
        #command_scopeID="(Get-NetIPAddress -AddressFamily IPv6 | Where-Object {$_.IPAddress -like "+f"'{ip_dst.compressed}*'"+"}).InterfaceIndex"
        command_scopeID=f"(Find-NetRoute -RemoteIPAddress '{ip_addr.compressed}' | Select-Object -First 1).InterfaceIndex" 
        process=subprocess.run(
            ["powershell","-Command", command_scopeID]
            ,capture_output=True
            ,text=True
        )
        scope_id=process.stdout.strip() 
        if not scope_id: 
            print("Scope ID non ricavato")
    def _linux_platform(): 
        if ip_addr.version==4:
            command=f"arp -n {ip_addr.compressed} | grep {ip_addr.compressed} | awk 'NR>1 {{print $5}}'"
        elif ip_addr.version==6:
            command=f"ip -6 neigh show {ip_addr.compressed} | grep {ip_addr.compressed} | awk '{{print $3}}'"
        else: raise Exception("Versione internet protocol non implementata")
        #command_scopeID= ip -{ip_addr.version} route get {ip_addr.compressed} | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1)}}}'
        command_scopeID=f"ip -{ip_addr.version} route get {ip_addr.compressed} | grep -o 'dev [^ ]*' |awk '{{print $2}}'" 
        process_shell= subprocess.Popen(
            ["bash", "-c", command_scopeID] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        scope_id=process_shell.stdout.strip() 
        if not scope_id or scope_id=="" or scope_id.lower()=="incomplete":
            process_shell= subprocess.Popen( ["ping", "-c 1", ip_addr.compressed]) 
            print("Scope ID non ricavato")
    #------------------------------
    if not is_ipaddress(ip_addr) or ip_addr.version!=6:
        raise Exception("Indirizzo non valido o non IPv6")
        return None
    scope_id=ip_addr.scope_id 
    while not scope_id: 
        if sys.platform == "win32": 
            _win_platform()
        elif sys.platform=="linux": 
            _linux_platform()
        else: 
            print("Sistema operativo non supportato per il recupero dello scope ID") 
            return None
    return scope_id

def get_default_gateway(ip_addr:ipaddress=None): 
    def _windows_default_gateway(self, ip:ipaddress=None)->tuple[str,str]:
        if not is_ipaddress(ip): 
            try:
                ip=ipaddress.ip_address(ip)
            except Exception as e: 
                raise Exception("windows_default_gateway: IP address non valido: ",e)
        comando='Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty "NextHop"' 
        process= subprocess.Popen(
            ["powershell", "-Command",comando],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Communicate with the process to get the output and error
        stdout, stderr = process.communicate() 
        #print("Output:", stdout.decode())
        #print("Error:", stderr.decode())
        return stdout.decode()
    def _linux_default_gateway(self, ip:ipaddress=None)->tuple[str,str]:
        if not is_ipaddress(ip): 
            try:
                ip=ipaddress.ip_address(ip)
            except Exception as e: 
                raise Exception("linux_default_gateway: IP address non valido: ",e)
        command="ip route | awk '/default/ {print $3}'"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        return stdout 
    #----------------------
    if not is_ipaddress(ip_addr):
        raise Exception("Indirizzo IP non valido") 
    if sys.platform == "win32": 
        return _windows_default_gateway(ip_addr) 
    elif sys.platform=="linux": 
        return _linux_default_gateway(ip_addr) 
    else: raise Exception("OS non supportato: ",sys.version)  

def get_default_interface(): 
    def _general_default_iface(): 
        try:
            return conf.iface  # Automatically detects default iface 
            #ip_src = conf.route.route("0.0.0.0")[1]  
        except Exception as e:
            print(f"_general_default_iface: {e}")
        return None 
    def _windows_default_iface():
        try:
            process = subprocess.Popen(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                print(f"_windows_default_iface: {stderr.strip()}") 
            lines = stdout.splitlines()
            for line in lines:
                if "Connected" in line:
                    parts = re.split(r"\s{2,}", line.strip())
                    if len(parts) >= 4:
                        iface_name = parts[-1]
                        return iface_name
        except Exception as e:
            print(f"_windows_default_iface: {e}") 
        return None 
    def _linux_default_iface():
        try: 
            process=subprocess.Popen(
                ["ip", "route"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True 
            )
            stdout, stderr = process.communicate()
            #print(f"Codice di ritorno {process.returncode}", flush=True)  
            if process.returncode != 0: 
                raise Exception(f"Errore nel codice: {stderr.strip()}") 
                return None
            result_output = stdout.strip()
            if result_output: 
                match_dev = re.search(r"dev (\S+)", result_output)
                if not match_dev:
                    raise Exception(f"Impossibile estrarre sorgente o interfaccia da output") 
                #print("match_dev: ",match_dev) 
                for interface in match_dev: 
                    if "linkdown" not in interface: 
                        iface=interface.replace("dev ","").strip() 
                        #print(f"Interfaccia trovata: {iface}")
                        return iface
        except Exception as e:
            print(f"_linux_default_iface: {e}") 
        return None
    #--------------------------
    return conf.iface  
    if sys.platform == "win32":
        self.default_iface=_windows_default_iface()
    elif sys.platform=="linux":
        self.default_iface=_linux_default_iface() 
    else: self.default_iface=_general_default_iface()

def get_ip_interface(ip_address:ipaddress.IPv4Address=None): 
    def _windows_iface_from_IP(): 
        if not is_ipaddress(ip_address): 
            return None
        #route_info = conf.route6.route(str(ip_address)) 
        #route_info = conf.route.route(str(ip_address)) 
        #iface, ip_src = conf.route.route(str(ip_address))[:2] 
        iface=None 
        try:
            iface_command= f"Get-NetIPInterface -InterfaceIndex (Find-NetRoute -RemoteIPAddress {ip_address.exploded} | Select-Object -First 1 -ExpandProperty InterfaceIndex) | Select-Object -First 1 -ExpandProperty InterfaceAlias" 
            #print("Comando interface: ", iface_command)
            process=subprocess.run(
                ["powershell","-Command", iface_command]
                ,capture_output=True
                ,text=True
            ) 
            iface=process.stdout.strip() 
            if not iface or len(iface)<1: 
                raise Exception("Interfaccia non ricavata") 
        except Exception as e:
            print(f"_windows_iface_from_IP: {e}") 
        return iface if len(iface)>0 else  None  
    def _linux_iface_from_IP(): 
        if not is_ipaddress(ip_address): 
            return None  
        try:
            #print(f"Indirizzo IPv{ip_address.version}: {ip_address.compressed}")
            process=subprocess.Popen(
                ["ip", f"-{ip_address.version}", "route", "get", ip_address.exploded],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True 
            )
            stdout, stderr = process.communicate()
            #print(f"Codice di ritorno {process.returncode}", flush=True)
            if process.returncode != 0: 
                raise Exception(f"Errore nel comando: {stderr.strip()}") #Codice di ritorno {process.returncode}
            result_output = stdout.strip()
            #print(f"Output della route: {result_output}",flush=True) 
            if result_output:  
                match_src = re.search(r"\bsrc\s+([\da-fA-F\.:]+)\b", result_output)  
                match_dev = re.search(r"dev (\S+)", result_output)
                if not match_src and not match_dev:
                    raise Exception(f"Impossibile estrarre sorgente o interfaccia da output") 
                #print("match_src: ",match_src)
                #print("match_dev: ",match_dev)
                ip_src=match_src.group(0).replace("src ","").strip()
                iface=match_dev.group(0).replace("dev ","").strip()
                #print(f"Sorgente trovata: {ip_src}")
                #print(f"Interfaccia trovata: {iface}")
                return iface  
        except Exception as e:
            print(f"_linux_iface_from_IP: {e}") 
        return None  
    #------------------------
    if not is_ipaddress(ip_address): 
        raise Exception("INTERFACE_FROM_IP: indirizzo IP non valido")  
    if sys.platform == "win32":
        return _windows_iface_from_IP()
    elif sys.platform=="linux": 
        return _linux_iface_from_IP() 

def get_MAC_address(ip_address:ipaddress.IPv4Address=None): 
    def _windows_macAddr(self): 
        if not is_ipaddress(self.ip_address):
            return None 
        #command_dst2="arp -a | getstr '192.168.1.17'"
        #restituisce 192.168.1.17  24-77-03-18-7b-74   dinamico
        comando_mac=f"Get-NetNeighbor -IPAddress {self.ip_address.compressed} "\
            "| Where-Object {$_.State -eq 'Reachable' -or $_.State -eq 'Stale'} "\
            "| Select-Object -First 1 -ExpandProperty LinkLayerAddress " #\ "| Format-Table State, LinkLayerAddress"
        print(f"_windows_macAddr: {comando_mac}")
        process=subprocess.run(
            ["powershell","-Command", comando_mac]
            ,capture_output=True
            ,text=True
        )
        mac_address=process.stdout.strip()
        stderr=process.stderr.strip()
        if not mac_address: 
            print(f"Tabella di routing non contiene  MAC address per {self.ip_address.compressed}") 
            #print("Provo a ricavarlo tramite l'interfaccia di rete...")
            #print("MAC: ",mac_address) 
        if stderr: 
            print(f"!!! _windows_macAddr: {stderr}") 
        if stderr or mac_address=="":
            if self.ip_address.version==6:
                scope_id=self.ip_address.scope_id 
                while not scope_id: 
                    scope_id=get_IPv6_scopeID(self.ip_address) 
                    if not scope_id: 
                        raise Exception(f"get_mac_address: Scope ID non ricavato per l'IP {self.ip_address.compressed}") 
                comando_interfaccia=f"(Get-NetIPAddress -IPAddress '{self.ip_address.compressed}%{scope_id}').InterfaceIndex"
            elif self.ip_address.version==4:
                comando_interfaccia=f"(Get-NetIPAddress -IPAddress '{self.ip_address.compressed}').InterfaceIndex"
            else:
                raise Exception(f"_windows_macAddr: veriosne IP non valida")
            comando_mac=f"(Get-NetAdapter -InterfaceIndex {comando_interfaccia}).MacAddress"
            print("_windows_macAddr",comando_mac) 
            process=subprocess.run(
                ["powershell","-Command", comando_mac]
                ,capture_output=True
                ,text=True
            )
            mac_address=process.stdout.strip() 
            stderr=process.stderr.strip() 
            if stderr or mac_address=="":
                #print(f"Errore nell'esecuzione  del comando: {stderr}") 
                raise Exception(f"get_mac_address: Impossibile ricavare MAC address per l'IP {self.ip_address.compressed}")
        #print(f"MAC for {self.ip_address}:{mac_address}")
        return mac_address 
    def _linux_macAddr(self): 
        if not is_ipaddress(self.ip_address): 
            return None 
        command_gateway=f"ip -{self.ip_address.version} route get {self.ip_address.compressed} | grep -o 'via [^ ]*' |awk '{{print $2}}'" #IP src gateway che raggiunge la destinazione
        process=subprocess.run(
            ["bash","-c", command_gateway]
            ,capture_output=True
            ,text=True
        )
        ip_gateway=process.stdout.strip() 
        stderr=process.stderr.strip() 
        #print("IP source gateway:", ip_gateway)
        if not ip_gateway or ip_gateway.strip()=="":
            ip_gateway=self.ip_address.compressed
        command_mac=f"ip -{self.ip_address.version} neigh show $({ip_gateway}) | grep -o 'lladr [^ ]*' | awk '{{print $2}}'" #MAC gateway che raggiunge la destinazione
        process=subprocess.run(
            ["bash","-c", command_mac]
            ,capture_output=True
            ,text=True
        )
        mac_address=process.stdout.strip() 
        stderr=process.stderr.strip() 
        if not mac_address: 
            print("MAC address della sorgente non ricavato")   
        if stderr or mac_address=="":
            print(f"Errore nell'esecuzione  del comando: {stderr}") 
        print(f"MAC for {self.ip_address}:{mac_address}")
        return mac_address   
    #------------------------------
    if not is_ipaddress(ip_address):  
        raise Exception("GET_MAC_ADDRESS: IP address non valido")  
    if sys.platform == "win32":
        return (_windows_macAddr()).lower().strip().replace("-",":") 
    elif sys.platform=="linux": 
        return (_linux_macAddr()).lower().strip().replace("-",":") 

def get_MAC_inCache(ip_addr:ipaddress.IPv6Address=None): 
    def _windows_mac_cache(): 
        command=f"Get-NetNeighbor -IPAddress {ip_addr.compressed}| Select-Object -ExpandProperty LinkLayerAddress" #ifIndex,IPAddress,LinkLayerAddress
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        ) 
        stdout, stderr = process_shell.communicate() 
        return sanitize_str(stdout) if stdout else print("stdout vuota: ",stderr)
    def _linux_mac_cache():
        #"ip neigh show dev enp0s3"
        #"ip neigh show 10.0.2.2" 
        #command="res=$(ip route get | awk '/10.0.2.15/ && !/default/ {print $3}'); ip -"+str(ip_addr.version)+" neigh show dev $res| awk '{print $3}'"
        command="res=$(ip route get "+str(ip_addr.compressed)+"| grep -oP '(?<=dev )[^ ]*'); ip link show dev $res| grep -oP '(?<=link/ether )[^ ]*|(?<=link/loopback )[^ ]*'"
        print("COMMAND: ",command)
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate() 
        return sanitize_str(stdout) if stdout else print("stdout vuota: ",stderr) 
    #----------------------------------
    if not is_ipaddress(ip_addr): 
        raise Exception("Indirizzo IP non valido")  
    if sys.platform=="linux": 
        return _linux_mac_cache() 
        #print("MAC address: ",mac_address)  
    elif sys.platform=="win32": 
        return _windows_mac_cache()
        #print("MAC address: ",mac_address)  
