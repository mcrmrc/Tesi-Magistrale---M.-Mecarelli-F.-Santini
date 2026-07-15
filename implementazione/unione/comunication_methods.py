#from scapy.all import *
from scapy.all import IP, ICMP, Raw,  Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr
from scapy.all import sr1, sendp, AsyncSniffer, get_if_hwaddr, in6_getnsma, in6_getnsmac, srp1

import threading 
import argparse
import mymethods
import time
import re 
import subprocess 
import ipaddress
import sys
import socket
import os

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

#------------------------
def is_callback_function(callback_function=None):
    #the type of a function can be 'function' or 'method'
    if callable(callback_function): 
        return True
    print(f"is_callback_function: Callback function invalida {callback_function}") 
    return False 

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

def is_valid_time(timeout_time:int|float=None):    
    if isinstance(timeout_time, (int, float)): 
        return True
    print(f"is_valid_time: Tempo non accettato {timeout_time}")  
    return False 

def is_threading_Event(event:threading.Event=None):
    if isinstance(event, threading.Event): 
        return True
    print(f"is_threading_Event: event non è un threading.Event {type(event)}") 
    return False 

def is_dictionary(args:dict=None):
    if isinstance(args, dict):
        return True
    print(f"is_dictionary: Argomenti non validi {args}") 
    return False
    
def is_AsyncSniffer(sniffer:AsyncSniffer=None):
    if isinstance(sniffer,AsyncSniffer): 
        return True
    print(f"is_AsyncSniffer: lo sniffer non è valido {sniffer}") 
    return False 

def is_threading_Timer(timer:threading.Timer=None):
    if isinstance(timer, threading.Timer): 
        return True
    print(f"is_threading_Timer: timer non è un threading.Timer {type(timer)}")
    return False 

def is_list(lista:list=None):
    if isinstance(lista,list): 
        return True  
    print(f"is_list: lista non è una lista {lista}") 
    return False
    
def is_string(stringa:str=None):
    if isinstance(stringa,str):
        return True
    print(f"is_string: stringa non valida {stringa}")
    return False 

def is_bytes(byte:bytes=None):
    if isinstance(byte,bytes): 
        return True
    print(f"is_bytes: byte non valido {byte}") 
    return False 

def is_integer(integer:int=None):
    if isinstance(integer,int): 
        return True
    print(f"is_integer: int non valido {integer}")
    return False 

def is_boolean(booleano:bool=None):
    if isinstance(booleano,bool): 
        return True
    print(f"is_boolean: booleano non valido {booleano}")
    return False 

def is_threading_lock(lock:threading.Lock=None):
    if isinstance(lock,type(threading.Lock())): 
        return True
    print(f"is_threading_lock: lock non valido {lock}")
    return False 

def is_valid_shell(shell:subprocess.Popen[str]=None):
    if isinstance(shell, subprocess.Popen): 
        return True
    print(f"is_valid_shell: shell non valida {shell}")
    return False 

def is_IPAddress(ip_address:ipaddress.IPv4Address|ipaddress.IPv6Address):
    if isinstance(ip_address, ipaddress.IPv4Address) or isinstance(ip_address, ipaddress.IPv6Address): 
        return True
    print(f"is_IPAddress: Non è istanza ne di IPv4Address ne di IPv6Address: {type(ip_address)}")
    return False 

#------------------------
def check_args_sniffer(args:dict=None): 
    try:
        is_dictionary(args)
    except Exception as e:
        raise Exception(f"check_args_sniffer: {e}")
    accepted_key_dict=[
        "iface","filter","prn","store","count", "timeout" ,"lfilter", 
        "opened_socket","session","started_callback","offline","quiet" 
    ]  
    invalid_args=[key for key in args if key not in accepted_key_dict]
    if len(invalid_args):
        raise ValueError(f"check_args_sniffer: Invalid keys in dictionary {invalid_args}")
    return True

def get_wrong_ipaddress(proxy_list:list):
    wrong_ips=[]
    for proxy in proxy_list:
        try:  
            if is_valid_ipaddress(proxy) is None: 
                wrong_ips.append(proxy)
        except Exception as e: 
            print(f"\tcheck_proxy_ipaddress: {e}") 
            wrong_ips.append(proxy)
    return wrong_ips  

#-------------------- 
def get_threading_Event()->threading.Event: 
    event = threading.Event()
    try:
        is_threading_Event(event)
    except Exception as e:
        raise Exception(f"get_threading_Event: {e}") 
    return event

def get_AsyncSniffer(args:dict=None):
    try: 
        check_args_sniffer(args)
    except Exception as e:
        print(f"get_AsyncSniffer: {e}")
    return AsyncSniffer( **args )

def get_timeout_timer(timeout_time=60, callback_function=None):
    try:
        is_callback_function(callback_function) 
        if timeout_time is not None:
            is_valid_time(timeout_time)
    except Exception as e:
        raise Exception(f"get_timeout_timer: {e}")
    return threading.Timer(timeout_time, callback_function)

def get_thread_response(proxy:ipaddress.IPv4Address|ipaddress.IPv6Address=None,thread_lock:threading.Lock=None,thread_response:dict=None,response:bool=True):
    try:
        if not isinstance(proxy, ipaddress.IPv4Address) and not not isinstance(proxy, ipaddress.IPv6Address):
            raise Exception("IP proxy non istanza di IPv4Address o IPv6Address: {proxy}")
        is_threading_lock(thread_lock)
        is_dictionary(thread_response)
        is_boolean(response)
    except Exception as e:
        raise Exception(f"get_thread_response: {e}")
    response=None
    thread_lock.acquire()
    response=thread_response.get(proxy.compressed)
    thread_lock.release()
    return response 

def update_thread_response(proxy:ipaddress.IPv4Address|ipaddress.IPv6Address=None,thread_lock:threading.Lock=None,thread_response:dict=None,response:bool=False):
    try:
        if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
            raise Exception(f"Proxy not instnace of IPv4Address nor IPv6Address : {type(proxy)}") 
        if not is_threading_lock(thread_lock):
            raise Exception(f"update_thread_response: lock {thread_lock}") 
        if not is_dictionary(thread_response):
            raise Exception(f"update_thread_response: dict {thread_response}") 
        if not is_boolean(response):
            raise Exception(f"update_thread_response: bollean {response}") 
    except Exception as e:
        raise Exception(f"update_thread_response: is_boolean {e}")
    thread_lock.acquire()
    thread_response.update({proxy.compressed:response}) 
    thread_lock.release()

#-------------------- 
def wait_threading_Event(event:threading.Event=None):
    try:
        is_threading_Event(event)
    except Exception as e:
        raise Exception(f"wait_threading_Event: {e}") 
    event.wait() 
    event.clear()

def set_threading_Event(event:threading.Event=None):
    try:
        is_threading_Event(event)
    except Exception as e:
        raise Exception(f"set_pkt_threading_Event: {e}") 
    event.set()

#------------------------
def start_sniffer(sniffer:AsyncSniffer=None, timer:threading.Timer=None):
    if not isinstance(sniffer, AsyncSniffer):
        raise Exception(f"Sniffer non istanza di AsyncSniffer: {type(sniffer)}")
    if not isinstance(timer, threading.Timer):
        raise Exception(f"Timer non istanza di threading.Timer: {type(timer)}")
    sniffer.start()
    timer.start()

def stop_sinffer(sniffer:AsyncSniffer=None): 
    if not is_AsyncSniffer(sniffer):
        raise Exception(f"Sniffer non istanza di AsyncSniffer: {type(sniffer)}") 
    if sniffer.running: 
        sniffer.stop() 
        print("Sniffer Stopped")
        if sniffer.running:
            print("\t***sniffer still alive")
        return True
    return False 

def stop_timer(timer:threading.Timer=None):
    if not is_threading_Timer(timer):
        print(f"stop_timer: timer non valido") 
        return False
    if timer.is_alive():
        timer.cancel() 
        print("Timer Stopped")
        if timer.is_alive():
            print("\t***Timer still alive")
        return True
    return False

def sniffer_timeout(sniffer:AsyncSniffer=None,threading_event:threading.Event=None): 
    if not is_AsyncSniffer(sniffer) or not is_threading_Event(threading_event): 
        raise ValueError("sniffer_timeout: Valori passati non corretti") 
    if not threading_event.is_set():
        print("Timeout: No packet received within 60 seconds")
        if sniffer.running:
            sniffer.stop() 
        set_threading_Event(threading_event) 



#------------------------
def send_packet(data:bytes=None,ip_dst:ipaddress.IPv4Address|ipaddress.IPv6Address=None, time=10,icmp_seq:int=0,icmp_id:int=None,interface=""):
    try:
        if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
            raise Exception("iip_dst non è ne istanza di IPv4Address ne IPv6Address")
        if not isinstance(data,bytes): 
            raise Exception(f"I dati non sono bytes: {type(data)}")
    except Exception as e:
        raise Exception(f"send_packet: {e}") 
    if icmp_id is None:
        icmp_id=mymethods.calc_checksum(data) 
    pkt = IP(dst=ip_dst.compressed)/ICMP(id=icmp_id,seq=icmp_seq) / data  
    print(f"\tSending {pkt.summary()}") 
    if isinstance(interface,str) and interface !="":
        ans=sendp(pkt, verbose=1, iface=interface)
    else:
        ans = sr1(pkt, timeout=time, verbose=1)
    if ans:
        #print(f"Reply: \t{ip_dst} is alive\n") 
        return True 
    #print(f"No reply: \t{ip_dst} is not responding\n")
    return False

def sniff_packet_w_callbak(args:dict=None,timeout_time=60, callback_function=sniffer_timeout):
    try:
        check_args_sniffer(args) 
        if timeout_time is not None:
            is_valid_time(timeout_time)
        is_callback_function(callback_function) 
    except Exception as e: 
        raise Exception(f"sniff_packet_w_callbak: {e}")
    timeout_time=int(timeout_time) if timeout_time is not None else timeout_time
    sniffer= get_AsyncSniffer(args)  
    timer = get_timeout_timer(timeout_time, callback_function) 
    start_sniffer(sniffer, timer) 
    return sniffer, timer 

def sniff_packet(args:dict=None,timeout_time=60, event:threading.Event=None):
    try:
        check_args_sniffer(args) 
        if timeout_time is not None:
            is_valid_time(timeout_time)
        is_threading_Event(event) 
    except Exception as e: 
        raise Exception(f"sniff_packet: {e}")  
    sniffer= get_AsyncSniffer(args)  
    callback_function=lambda: sniffer_timeout(sniffer, event) 
    timeout_time=int(timeout_time) if timeout_time is not None else timeout_time 
    timer = get_timeout_timer(timeout_time, callback_function)  
    start_sniffer(sniffer, timer)  
    return sniffer, timer 

#------------------------
def setup_thread_foreach_address(address_list:list[ipaddress.IPv4Address|ipaddress.IPv6Address]=None,callback_function=None): 
    try: 
        if not is_callback_function(callback_function):
            raise Exception(f"callback_function non valida {callback_function}")
        if not is_list(address_list) or len(address_list)<=0:
            raise Exception(f"lista non valida")
    except Exception as e:
        raise Exception(f"setup_thread_4_foreach_proxy: {e}")
    thread_lock=threading.Lock()
    thread_response={}
    thread_list={}
    for proxy in address_list:
        if not isinstance(proxy, ipaddress.IPv4Address) and not isinstance(proxy, ipaddress.IPv6Address):
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

def get_mac_by_ipv6(ipv6_dst: str, ipv6_src: str, iface_name: str):
    try:
        # Validate and convert
        dst_ip = ipaddress.IPv6Address(ipv6_dst) 
        src_ip = ipaddress.IPv6Address(ipv6_src)
        src_mac = get_if_hwaddr(iface_name)
        print(f"Source MAC: {src_mac}")
        print(f"Source IPv6: {src_ip.compressed}")
        print(f"Destination IPv6: {dst_ip.compressed}")

        # Create solicited-node multicast address (ff02::1:ffXX:XXXX)
        ns_multicast_ip = in6_getnsma(dst_ip.packed)
        dst_multicast_mac = in6_getnsmac(dst_ip.packed)
        print(f"Solicited Node Multicast IP: {ns_multicast_ip}")
        print(f"Destination Multicast MAC: {dst_multicast_mac}")
        ns_multicast_ip_str = socket.inet_ntop(socket.AF_INET6, ns_multicast_ip)

        # Build NDP Neighbor Solicitation
        ndp_pkt = (
            Ether(dst=dst_multicast_mac, src=src_mac) /
            IPv6(src=f"{src_ip.compressed }%{iface_name}", dst=f"{ns_multicast_ip_str}%{iface_name}") /
            ICMPv6ND_NS(tgt=str(dst_ip)) /
            ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
        )

        print(f"Sending NDP to {ns_multicast_ip} via iface {iface_name}")
        resp = srp1(ndp_pkt, timeout=2, iface=iface_name, verbose=False)

        if resp and ICMPv6NDOptDstLLAddr in resp:
            resolved_mac = resp[ICMPv6NDOptDstLLAddr].lladdr
            print(f"Resolved MAC: {resolved_mac}")
            return resolved_mac
        else: 
            cached_mac=check_mac_in_cache(dst_ip, iface_name)
            if cached_mac:
                print(f"(Fallback) Resolved MAC from cache: {cached_mac}")
                return cached_mac
            raise Exception("MAC resolution failed: No NDP response and no cache entry.") 
    except Exception as e:
        raise Exception(f"get_mac_by_ipv6: {e}")

def check_mac_in_cache(ipv6_addr:str=None, iface_name: str=None):
    try: 
        is_string(iface_name)
        ipv6_addr = is_valid_ipaddress_v6(ipv6_addr)

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
    except Exception as e:
        raise Exception(f"check_mac_in_cache: {e}") 



def ping_once(ip_dst:ipaddress.IPv4Address|ipaddress.IPv6Address=None, iface:str=None, timeout=1):
    try:
        is_string(iface)
        if isinstance(ip_dst, ipaddress.IPv4Address) or isinstance(ip_dst, ipaddress.IPv6Address):
            os.system(f"ping6 -c 1 {ip_dst.compressed}%{iface}")
        else: raise Exception("L'indirizzo non è ne un 'ipaddress.IPv4Address' ne un 'ipaddress.IPv6Address'")
    except Exception as e:
        raise Exception(f"ping_once: {e}")