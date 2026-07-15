
import ipaddress
import random
import threading
from Programma.methods.get_methods import get_threading_Event, get_threading_Lock


class HOST_CONNESSI: 
    def __init__(self): 
        self.host_list:list[ipaddress._IPAddressBase]=[]
        self.lock:threading.Lock=get_threading_Lock() 
        self.enough_event:threading.Event=get_threading_Event() 
        self.type_attack:dict[str:str]={} 
    
    def choose_host(self): 
        print(f"I proxy utilzzabili sono: {len(self.host_list)}\n\t{self.host_list}")  
        if len(self.host_list)<=0:
            print("Lista host vuota")  
        with self.lock: 
            if len(self.host_list)<=0: 
                chosen_host=None
            else: chosen_host=random.choice(self.host_list)
        return chosen_host 