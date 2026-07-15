from scapy.all import * 
from scapy.all import IP, ICMP, Raw 

import ipaddress
import sys 
import os 
import argparse  
import threading 
import json 
import socket 

file_path = "../mymethods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import mymethods 

file_path = "./attacksingleton.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import attacksingleton 

data="echo 'Ciao'".encode()

print(f"Data Byte: {data}")

bit_data=[]
for piece_data in data: #BIG ENDIAN
    bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB 
print(f"Bin extracetd: {bit_data}") 

print("Bin normali")
data="echo 'Ciao'".encode()
for byte in data: 
    #print(f"Byte: {bin(byte)}")
    for bit in bin(byte): 
        print(f"{bit}",end=" ")
    print()

timing_data=[]
for bit in bit_data:
    timing_data.append(bit)    
print(f"Bit ricevuti: {timing_data}") 

str_data=""
for integer in timing_data:
    str_data+=format(integer, f'0{2}b') 
raw_data="" 
for index in range(0, len(str_data), 8):
    int_data=0
    for bit in str_data[index:index+8][::-1]:
        int_data=int_data<<1|int(bit)
    raw_data+=chr(int_data) 