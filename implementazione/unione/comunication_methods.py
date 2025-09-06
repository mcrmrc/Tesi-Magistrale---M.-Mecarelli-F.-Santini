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
 



def ping_once(ip_dst:ipaddress.IPv4Address|ipaddress.IPv6Address=None, iface:str=None, timeout=1):
    try:
        is_string(iface)
        if isinstance(ip_dst, ipaddress.IPv4Address) or isinstance(ip_dst, ipaddress.IPv6Address):
            os.system(f"ping6 -c 1 {ip_dst.compressed}%{iface}")
        else: raise Exception("L'indirizzo non è ne un 'ipaddress.IPv4Address' ne un 'ipaddress.IPv6Address'")
    except Exception as e:
        raise Exception(f"ping_once: {e}")