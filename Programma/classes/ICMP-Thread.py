import ipaddress
import threading
from Programma.methods.check_type import is_callable_function, is_dictionary, is_ipaddress, is_list
from Programma.methods.get_methods import get_threading_Lock


class ICMP_THREAD: 
    thread_lock=None 
    thread_response={} 
    thread_list={} 

    def __init__(self, proxy_list:list[ipaddress._IPAddressBase], callback_function):  
        if not is_list(proxy_list) or len(proxy_list)<=0: 
            raise TypeError("proxy_list non valida") 
        if any(not is_ipaddress(ip) for ip in proxy_list): 
            raise ValueError("proxy_list non valida") 
        if not is_callable_function(callback_function): 
            raise TypeError("callback_function not callable")
        self.thread_lock=get_threading_Lock() 
        for proxy in proxy_list: 
            if not is_ipaddress(proxy): 
                print(f"***\t{proxy} non è un indirizzo valido")
                continue 
            thread=threading.Thread(
                target=callback_function, 
                args=[proxy]
            ) 
            thread.name=f"Thread-{proxy.compressed}" 
            self.thread_list[proxy.compressed]=thread 
            self.thread_response[proxy.compressed]=False 
        print("Definito il dizionario dei thread") 
        print("Definiti il dizionario delle risposte") 
    
    def reset(self): 
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        for thread in self.thread_list.values():
            thread.clear() 
        print("Thread ICMP reimpostati") 

    def start(self): 
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        self.reset()
        for thread in self.thread_list.values():
            thread.start() 
        print("Thread ICMP avviati")
    
    def wait(self):  
        if not is_dictionary(self.thread_list) or len(self.thread_list)<=0: 
            raise TypeError("thread_list non valido")  
        for thread in self.thread_list.values():
            #thread.wait()  
            thread.join()  
        print("Thread ICMP terminati") 
