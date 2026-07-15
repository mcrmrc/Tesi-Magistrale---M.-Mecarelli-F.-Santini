import argparse
import socket
import subprocess
import ipaddress
import threading  
from enum import Enum   
from scapy.all import AsyncSniffer

def is_callable_function(var_ToCheck=None):
    #the type of a function can be 'function' or 'method' 
<<<<<<< HEAD
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

=======
    if callable(var_ToCheck): 
        return True
    #print(f"callback function non valida {var_ToCheck}") 
    return False  

def is_ipaddress(var_ToCheck=None): 
    if isinstance(var_ToCheck, (ipaddress.IPv4Address,ipaddress.IPv6Address)): 
        return True 
    #print(f"non è un ipaddress {var_ToCheck}") 
    return False

def is_time(var_ToCheck=None):    
    if isinstance(var_ToCheck, (int, float)): 
        return True
    #print(f"Tempo non valido {var_ToCheck}") 
    return False 

def is_threading_Event(var_ToCheck=None):
    if isinstance(var_ToCheck, threading.Event): 
        return True
    #print(f"non è un threading.Event {type(var_ToCheck)}") 
    return False 

def is_dictionary(var_ToCheck=None):
    if isinstance(var_ToCheck, dict):
        return True
    #print(f"non è un dizionario {var_ToCheck}") 
    return False

def is_AsyncSniffer(var_ToCheck=None):
    if isinstance(var_ToCheck,AsyncSniffer): 
        return True
    #print(f"sniffer non è valido {var_ToCheck}") 
    return False 

def is_threading_Timer(var_ToCheck=None):
    if isinstance(var_ToCheck, threading.Timer): 
        return True
    #print(f"timer non è un threading.Timer {type(var_ToCheck)}")
    return False 

def is_list(var_ToCheck=None):
    if isinstance(var_ToCheck,list): 
        return True  
    #print(f"non è una lista {var_ToCheck}") 
    return False

def is_string(var_ToCheck=None):
    if isinstance(var_ToCheck,str):
        return True
    #print(f"stringa non valida {var_ToCheck}")
    return False 

def is_bytes(var_ToCheck=None):
    if isinstance(var_ToCheck,bytes): 
        return True
    #print(f"byte non valido {var_ToCheck}") 
    return False 

def is_integer(var_ToCheck=None):
    if isinstance(var_ToCheck,int): 
        return True
    #print(f"integer non valido {var_ToCheck}")
    return False 

def is_boolean(var_ToCheck=None):
    if isinstance(var_ToCheck,bool): 
        return True
    #print(f"booleano non valido {var_ToCheck}")
    return False 

def is_threading_Lock(var_ToCheck=None):
    if isinstance(var_ToCheck, threading.Lock): 
        return True
    #print(f"lock non valido {var_ToCheck}")
    return False 

def is_subprocess_Popen(var_ToCheck=None): #is_valid_shell
    if isinstance(var_ToCheck, subprocess.Popen): 
        return True
    #print(f"shell non valida {var_ToCheck}")
    return False 

def is_ArgumentParser(var_ToCheck=None): 
    if isinstance(var_ToCheck, argparse.ArgumentParser): 
        return True
    #print(f"ArgumentParser: parser non valido {var_ToCheck}")
    return False 

def is_enum_member(var_ToCheck=None, enum_type:Enum=None): 
>>>>>>> 9ea1dd5 (modified methods)
    if enum_type is None or not issubclass(enum_type, Enum): 
        return False 
    if isinstance(var_ToCheck, enum_type): 
        return True
    #print(f"enum non valido {type(var_ToCheck)}")
    return False 

def is_namespace(var_ToCheck=None): 
<<<<<<< HEAD
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
=======
    if isinstance(var_ToCheck, argparse.Namespace): 
        return True 
    #print(f"namespace: namespace non valido {var_ToCheck}")
    return False 

def is_threading_Thread(var_ToCheck=None): 
    if isinstance(var_ToCheck,threading.Thread): 
        return True 
    #print(f"thread non valido {var_ToCheck}")
    return False 

def is_socket(var_ToCheck=None): 
    if isinstance(var_ToCheck, socket.socket): 
        return True 
    #print(f"socket non valido {var_ToCheck}")
    return False
>>>>>>> 9ea1dd5 (modified methods)
