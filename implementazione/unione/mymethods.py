from scapy.all import conf 
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

def supported_arguments(parser=None):
    if parser is None:
        raise Exception("Parser nullo")
    print("Controlla di inserire due volte - per gli argomenti")
    print("Argomenti supportati:") 
    for action in parser._actions:
        print("\t{arg}: {help}".format(
            arg=action.option_strings[0],
            help=action.help
        )) 

def check_args(parser: argparse.ArgumentParser = None): 
    if parser is None:
        raise ValueError("Parser nullo")
    try:
        args, unknown = parser.parse_known_args()
        #args= parser.parse_args()
        print("Argomenti passati: {}".format(args))
        if len(unknown) > 0:
            print(f"Argomenti sconosciuti: {unknown}")
            supported_arguments(parser)
            exit(1) 
        return args
    except Exception as e:
        print("Errore: {}".format(e)) 
        exit(1) 

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
    print(f"The checksum of {data} is {checksum}")
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
    
def iface_from_IPv4(target_ip=None):
    if target_ip is None:
        raise Exception("Indirizzo IP uguale a None")
    iface_name = conf.route.route(target_ip)[0]
    iface_ip = conf.route.route(target_ip)[1] 
    return iface_ip,iface_name  

def iface_from_IPv6(target_ip=None):
    try:
        addr=ipaddress.IPv6Address(target_ip)
        result=subprocess.run(
            ["ip", "-6", "route", "get", addr.compressed],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        output = result.stdout.strip() 
        #match = re.search(r'src ([\da-f:]+).* dev (\S+)', output)
        #if not match:
        #    raise RuntimeError(f"Impossibile estrarre interfaccia da:\n{output}")
        #ip_src = match.group(1)
        #iface = match.group(2)
        return output.split(" ")[0], output.split(" ")[4]
    except ValueError:
        raise Exception("Indirizzo IPv6 non valido") 
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Nessuna route trovata per {target_ip}") 
    ## Usa una regex per trovare src e dev
    #match = re.search(r'src ([\da-f:]+).* dev (\S+)', output)
    #if not match:
    #    raise RuntimeError(f"Impossibile estrarre interfaccia da:\n{output}")


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
    s= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8",80))
        local_ip=s.getsockname()[0]
    except Exception as e:
        print(f"find_local_IP: {e}")
    finally:
        s.close()
    return local_ip

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

