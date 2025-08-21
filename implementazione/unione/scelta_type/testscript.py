from scapy.all import * 
from scapy.all import IP, ICMP, Raw 

import ipaddress
import sys 
import os 
import argparse  
import threading 
import json 
import socket

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

attack_function=attacksingleton.AttackType().get_attack_function("ipv4_1")
data="ls -l"
ip_dst=ipaddress.ip_address("192.168.1.20")
interface,_=mymethods.iface_src_from_IP(ip_dst)
print("interface: ",interface)

pkt=IP(dst="192.168.1.20")/ICMP() 
print(pkt.summary())
print(pkt.show())
ans=sr1(pkt, verbose=1, timeout=3, iface=interface)
if ans:
    print(ans.summary())

#attacksingleton.send_data(attack_function, data.encode(), ip_dst)