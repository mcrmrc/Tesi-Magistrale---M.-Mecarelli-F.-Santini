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

#------------------------

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