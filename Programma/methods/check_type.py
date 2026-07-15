import argparse
import socket
import subprocess
import ipaddress
import threading  
from enum import Enum   
from scapy.all import AsyncSniffer

def is_callable_function(var_ToCheck=None):
    #the type of a function can be 'function' or 'method' 
    return callable(var_ToCheck)

def is_ipaddress(var_ToCheck=None): 
    return isinstance(
        var_ToCheck, 
        (ipaddress.IPv4Address,ipaddress.IPv6Address)
    )

def is_time(var_ToCheck=None):    
    return isinstance(var_ToCheck, (int, float))

def is_threading_Event(var_ToCheck=None):
    return isinstance(var_ToCheck, threading.Event)

def is_dictionary(var_ToCheck=None):
    return isinstance(var_ToCheck, dict) 

def is_AsyncSniffer(var_ToCheck=None):
    return isinstance(var_ToCheck,AsyncSniffer) 

def is_threading_Timer(var_ToCheck=None):
    return isinstance(
        var_ToCheck, 
        threading.Timer
    ) 

def is_list(var_ToCheck=None):
    return isinstance(var_ToCheck,list) 

def is_string(var_ToCheck=None):
    return isinstance(var_ToCheck,str) 

def is_bytes(var_ToCheck=None):
    return isinstance(var_ToCheck,bytes) 

def is_integer(var_ToCheck=None):
    return type(var_ToCheck) is int

def is_boolean(var_ToCheck=None):
    return isinstance(var_ToCheck,bool)

def is_threading_Lock(var_ToCheck=None):
    return isinstance(
        var_ToCheck, 
        threading.Lock
    ) 

def is_subprocess_Popen(var_ToCheck=None): #is_valid_shell
    return isinstance(
        var_ToCheck, 
        subprocess.Popen
    ) 

def is_ArgumentParser(var_ToCheck=None): 
    return isinstance(
        var_ToCheck, 
        argparse.ArgumentParser
    ) 

def is_enum_member(var_ToCheck=None, enum_type:Enum=None): 
    return issubclass(enum_type, Enum) and isinstance(var_ToCheck, enum_type)

    if enum_type is None or not issubclass(enum_type, Enum): 
        return False 
    if isinstance(var_ToCheck, enum_type): 
        return True
    #print(f"enum non valido {type(var_ToCheck)}")
    return False 

def is_namespace(var_ToCheck=None): 
    return isinstance(
        var_ToCheck, 
        argparse.Namespace
    ) 

def is_threading_Thread(var_ToCheck=None): 
    return isinstance(
        var_ToCheck,
        threading.Thread
    ) 

def is_socket(var_ToCheck=None): 
    return isinstance(
        var_ToCheck, 
        socket.socket
    ) 
