import sys, subprocess, threading 
from network.network_methods import check_sniffer_args
from scapy.all import AsyncSniffer
from type.check_type import is_dictionary, is_string, is_callable_function, is_time

#class GET: 
def get_threading_Event()->threading.Event: 
    return threading.Event() 

def get_threading_Lock()->threading.Lock: 
    return threading.Lock()

def get_AsyncSniffer(args:dict=None): 
    if not is_dictionary(args): 
        raise Exception(f"GET:AsyncSniffer\targs is not a dictionary") 
    if check_sniffer_args(args):
        return AsyncSniffer( **args ) 
    return None

def get_timer(timeout_time=60, callback_function=None): 
    if is_callable_function(callback_function) and (timeout_time is None or is_time(timeout_time)): 
        return threading.Timer(timeout_time, callback_function)
    return None 

def get_shellProcess():
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

def get_shellProcess_command(command:str): 
    if not is_string(command): 
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
