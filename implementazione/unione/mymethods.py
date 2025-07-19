#from scapy.all import conf 

import string
import re
import argparse
import socket
import urllib.request
import sys
import subprocess
import ipaddress

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

def print_parser_supported_arguments(parser:argparse.ArgumentParser=None):
    if not isinstance(parser,argparse.ArgumentParser):
        raise Exception(f"Parser nullo: {parser}")
    print("Controlla di inserire due volte - per gli argomenti")
    print("Argomenti supportati:") 
    for action in parser._actions:
        print("\t{arg}: {help}".format(
            arg=action.option_strings[0],
            help=action.help
        )) 

def check_for_unknown_args(parser: argparse.ArgumentParser = None): 
    if not isinstance(parser, argparse.ArgumentParser):
        raise ValueError("Parser non istanza di argparse.ArgumentParser") 
    try: 
        args, unknown = parser.parse_known_args()  
        return args, unknown
    except Exception as e:
        print("check_args: {e}") 
        return None, None

def calc_checksum(data: bytes) -> int:
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

def calc_gateway(ip_dst=None):
    ip_reg_pattern=r"\d+\.\d+\.\d+\.\d+" 
    if type(ip_dst) is not str or re.match(ip_reg_pattern, ip_dst) is None :
        raise Exception("IP non valido")
    return ".".join(
        ip_dst.split(".")[index] if index!=3 else "0" 
        for index in range(len(ip_dst.split(".")))
    )

def calc_gateway_ipv6(ip_dst=None):
    try:
        addr=ipaddress.IPv6Address(ip_dst)
        return addr.exploded[0:4]+"::1"
    except ValueError:
        raise Exception("calc_gateway_ipv6: Indirizzo IPv6 non valido") 

def iface_src_from_IP(addr_target:ipaddress.IPv4Address|ipaddress.IPv6Address=None):
    if not isinstance(addr_target, ipaddress.IPv4Address) and not isinstance(addr_target, ipaddress.IPv6Address):
        raise Exception(f"L'indirizzo è una {type(addr_target)}. Richiesto o un 'ipaddress.IPv4Address' o un 'ipaddress.IPv6Address': ",file=sys.stderr)
    result_output = None
    try:
        #print(f"Indirizzo IPv{addr_target.version}: {addr_target.compressed}")
        process=subprocess.Popen(
            ["ip", f"-{addr_target.version}", "route", "get", addr_target.compressed],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True 
        )
        stdout, stderr = process.communicate()
        #print(f"Codice di ritorno {process.returncode}", flush=True)
        if process.returncode == 0:  
            result_output = stdout.strip()
            #print(f"Output della route: {result_output}",flush=True)
        else:
            #print(f"Codice di ritorno {process.returncode}", file=sys.stderr)
            #print(f"Errore: {stderr.strip()}", file=sys.stderr)  
            return None, None 
    except subprocess.CalledProcessError as e:
        #print(f"Errore durante l'esecuzione del comando: {e}", file=sys.stderr)
        return None, None 
    except ValueError as e:
        #print(f"Errore di valore: {e}", file=sys.stderr)
        return None, None 
    if result_output is not None:  
        match_src = re.search(r"\bsrc\s+([\da-fA-F\.:]+)\b", result_output)  
        match_dev = re.search(r"dev (\S+)", result_output)
        if not match_src and not match_dev:
            print(f"Impossibile estrarre sorgente o interfaccia da output",file=sys.stderr)
            return None, None 
        #print("match_src: ",match_src)
        #print("match_dev: ",match_dev)
        ip_src=match_src.group(0).replace("src ","").strip()
        iface=match_dev.group(0).replace("dev ","").strip()
        #print(f"Sorgente trovata: {ip_src}")
        #print(f"Interfaccia trovata: {iface}")
        return iface, ip_src
    return None, None 

def default_iface(): 
    try: 
        process=subprocess.Popen(
            ["ip", "route"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True 
        )
        stdout, stderr = process.communicate()
        #print(f"Codice di ritorno {process.returncode}", flush=True)
    except subprocess.CalledProcessError as e:
        print(f"Errore durante l'esecuzione del comando: {e}", file=sys.stderr)
        return None
    except ValueError as e:
        print(f"Errore di valore: {e}", file=sys.stderr)
        return None  
    result_output = None
    if process.returncode == 0:  
        result_output = stdout.strip()
        #print(f"Output della route: {result_output}",flush=True)
    else:
        #print(f"Codice di ritorno {process.returncode}", file=sys.stderr)
        #print(f"Errore: {stderr.strip()}", file=sys.stderr)  
        return None
    if result_output is not None: 
        match_dev = re.search(r"dev (\S+)", result_output)
        if not match_dev:
            print(f"Impossibile estrarre sorgente o interfaccia da output",file=sys.stderr)
            return None 
        #print("match_dev: ",match_dev) 
        iface=match_dev.group(0).replace("dev ","").strip() 
        #print(f"Interfaccia trovata: {iface}")
        return iface
    return None 



def sanitize(stringa):
    if type(stringa) is not str or string is None:
        raise Exception("Stringa non valida")
    stringa = ''.join(
        char if char in string.printable 
        else'' 
        for char in stringa
    ) 
    return stringa.strip() 

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

def getShellProcess():
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
    raise Exception(
        "Sistema operativo non supportato per l'apertura della shell"
    )


