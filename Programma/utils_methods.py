import string, time, threading, ipaddress
from type.check_type import is_ipaddress, is_threading_Lock, is_dictionary, is_boolean, is_callable_function, is_list

systemsDictionary={
    'aix':"AIX",
    'android':"Android",
    'emscripten':"Emscripten",
    'ios':"iOS", 
    'linux':"Linux", 
    'darwin':"macOS", 
    'win32':"Windows", 
    'cygwin':"Windows/Cygwin", 
    'wasi':"WASI" 
} 

def non_blocking_sleep(secondi:int=None): 
    if not isinstance(secondi, int) or secondi<0:
        raise Exception("aspetta_tempo: Argomenti non validi") 
    if secondi>=60: 
        print(f"Attesa di {secondi//60} minuti e {secondi%60} secondi in corso...")
    else:
        print(f"Attesa di {secondi} secondi in corso...")
    while secondi>0:
        time.sleep(1)
        secondi-=1  


def sanitize_str(stringa):
    if not stringa or not isinstance(stringa, str):
        raise Exception("Stringa non valida")
    stringa = ''.join(
        char if char in string.printable 
        else'' 
        for char in stringa
    ) 
    #stringa=stringa.replace("\t","")
    #stringa=stringa.replace("\n","")
    return stringa.strip() 

def print_dictionary(dictionary:dict=None):
    if not isinstance(dictionary,dict):
        raise Exception("print_dictionary: Dizionario passato non valido") 
    elif len(dictionary)<=0:
        print("Il dizionario è vuoto")
        return
    print("Valori presenti:")
    for key, value in dictionary.items():
        print(f"\t{key}\t\t{value}") 

def ask_bool_choice(msg:str):
    def is_scelta_SI_NO(scelta:str=None):
        if not scelta or not isinstance(scelta, str): 
            return False 
        whitebox=["yes","si","yeah"]
        for x in whitebox:
            if sanitize_str(scelta)!="" and (x.startswith(scelta) or x in scelta):
                return True 
        return False
    if not isinstance(msg, str):
        raise Exception("ask_bool_choice: Il messaggio non è una stringa")
    return is_scelta_SI_NO(input(f"{msg}"))

def proxy_update_data_received(data, data_lock:threading.Lock, data_received):
    data_lock.acquire()
    data_received.append(data)
    data_lock.release() 

def threadEvent_wait(event:threading.Event=None): 
        if not isinstance(event, threading.Event): 
            raise Exception(f"Impossibile aspettare su una variabile non Event") 
        event.wait() 
        event.clear() 
    
def threadEvent_set(event:threading.Event=None): 
    if not isinstance(event, threading.Event): 
        raise Exception(f"Impossibile settare una variabile non Event") 
    event.set() 


def get_thread_response(proxy:ipaddress.IPv4Address=None,thread_lock:threading.Lock=None,thread_response:dict=None,response:bool=True):
    if is_ipaddress(proxy) and is_threading_Lock(thread_lock) and is_dictionary(thread_response) and is_boolean(response):
        with thread_lock: 
            response=thread_response.get(proxy.compressed)
        return response 
    return None 

def update_thread_response(proxy:ipaddress.IPv4Address=None, thread_lock:threading.Lock=None, thread_response:dict=None, response:bool=False):
    if not (is_ipaddress(proxy) and is_threading_Lock(thread_lock) and is_dictionary(thread_response) and is_boolean(response)):  
        raise Exception(f"update_thread_response: argomenti non validi")
    with thread_lock:
        thread_response.update({proxy.compressed:response}) 
    
def setup_thread_foreach_address(address_list:list[ipaddress.IPv4Address]=None,callback_function=None): 
    if not is_callable_function(callback_function): 
        raise Exception(f"callback_function non valida") 
    if not is_list(address_list) or len(address_list)<=0: 
        raise Exception(f"address_list non valida") 
    thread_lock=threading.Lock()
    thread_response={}
    thread_list={}
    for proxy in address_list:
        if not is_ipaddress(proxy): 
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
