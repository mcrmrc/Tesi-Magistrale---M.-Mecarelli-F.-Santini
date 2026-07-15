import sys
import subprocess
import threading   
from check_type import * 
from mymethods import SNIFFER

#class GET: 
def threading_Event()->threading.Event: 
    return threading.Event() 

def threading_Lock()->threading.Lock: 
    return threading.Lock()

def AsyncSniffer(args:dict=None): 
    if not is_dictionary(args): 
        raise Exception(f"GET:AsyncSniffer\targs is not a dictionary") 
    if SNIFFER.check_args(args):
        return AsyncSniffer( **args ) 
    print("AHAHAHAH")
    return None

def timer(timeout_time=60, callback_function=None): 
    if is_callable_function(callback_function) and (timeout_time is None or is_time(timeout_time)): 
        return threading.Timer(timeout_time, callback_function)
    return None 

def shellProcess():
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

def shellProcess_command(command:str): 
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
