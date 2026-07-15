import ipaddress
from socket import socket
import threading
from Programma.classes.Data import DATA
from Programma.custom_enum import ATTACK_TYPE, MSG
from Programma.methods.check_type import is_enum_member, is_ipaddress, is_socket
from Programma.methods.get_methods import get_threading_Lock


class THREAD_ATTACCANTE:
    class PROXIES_CONECTION: 
        def __init__(self, proxy_list:dict[str,DATA.PROXY]):
            if not isinstance(proxy_list, DATA.PROXY) or not len(proxy_list.values())>0: 
                raise ValueError("Lista dei proxy non valida") 
            self.thread_lock=get_threading_Lock() 
            self.thread_list:dict[str:threading.Thread]=dict()
            for proxy in proxy_list.values(): 
                self.thread_list[proxy.ipaddress.compressed]=None  
            self.unusable_proxy:list[DATA.PROXY]=[] 

        def start(self, ip_vittima:ipaddress._IPAddressBase,attack_function:ATTACK_TYPE, proxy_list:dict[str,DATA.PROXY]): 
            def callback(proxy_data:DATA.PROXY=None): 
                try: 
                    set_connessione(proxy_data) 
                    if not is_socket(proxy_data.socket): 
                        raise ValueError(f"Proxy {proxy_data.ipaddress} socket non inizializzato")
                    send_conferma(proxy_data) 
                    print(f"Messaggio di conferma valido per {proxy_data.ipaddress}")
                    wait_risposta(proxy_data) 
                    print(f"Proxy {proxy_data.ipaddress} connesso alla vittima") 
                except Exception as e: 
                    print(f"PROXIES_CONECTION.callback: {e}") 
                    print(f"Connessione con {proxy_data.ipaddress} fallita") 
                    with self.thread_lock: 
                        self.unusable_proxy.append(proxy_data)  
            def set_connessione(proxy:DATA.PROXY=None): 
                socket_proxy=None 
                socket_proxy=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_proxy.settimeout(15) #15 secondi 
                socket_proxy.connect((proxy.ipaddress.compressed, proxy.port)) 
                with self.thread_lock: 
                    proxy.socket=socket_proxy 
                print(f"Connessione con {proxy.ipaddress} stabilita") 
            def send_conferma(proxy:DATA.PROXY): 
                confirm_msg=( 
                    MSG.CONFIRM_ATTACKER.value+"|"+ 
                    proxy.ipaddress.compressed+"|"+
                    ip_vittima.compressed+"|"+ 
                    MSG.ATTACK_FUNCTION.value+"|"+
                    attack_function.name 
                ) 
                #TODO implementare metodi per riprovare in caso di fallimento
                proxy.socket.settimeout(10) 
                proxy.socket.sendall(confirm_msg.encode()) 
                print(f"Messaggio di conferma inviato a {proxy}") 
                data=""
                while True:
                    proxy.socket.settimeout(10) 
                    chunk=proxy.socket.recv(1024).decode() 
                    if not chunk: break
                    data+=chunk
                    if MSG.END_SOCKETSEND.value in data: 
                        data=data.replace(MSG.END_SOCKETSEND.value,"")
                        break 
                confirm_msg=( 
                    MSG.CONFIRM_PROXY.value+"|"+ 
                    proxy.ipaddress.compressed+"|"+
                    ip_vittima.compressed+"|"+ 
                    MSG.ATTACK_FUNCTION.value+"|"+
                    attack_function.name 
                ) 
                if not data or data!=confirm_msg:  
                    raise ValueError(f"Messaggio di conferma non valido per {proxy}") 
            def wait_risposta(proxy:DATA.PROXY): 
                confirm_text=( 
                    MSG.CONFIRM_VICTIM.value+"|"+ 
                    ip_vittima.compressed+"|"+ 
                    proxy.ipaddress.compressed 
                ) 
                data=""
                while True:
                    proxy.socket.settimeout(10) 
                    chunk=proxy.socket.recv(1024).decode()  
                    if not chunk: break
                    data+=chunk
                    if MSG.END_SOCKETSEND.value in data: 
                        data=data.replace(MSG.END_SOCKETSEND.value,"")
                        break
                result=data.replace(confirm_text,"") 
                #print(f"{proxy} è connesso alla vittima? {type(result)} {result}") 
                if result!="True": 
                    raise ValueError(f"Proxy {proxy} non connesso alla vittima") 
            def pop_proxy_inutilizzati(): 
                for proxy in self.unusable_proxy: 
                    try: 
                        proxy.socket.sendall(MSG.END_COMMUNICATION.value.encode()) 
                        proxy.socket.close() 
                        print(f"Connessione con {proxy.ipaddress} chiusa")
                    except Exception as e: 
                        print("PROXIES_CONECTION.start-> ",e) 
                        print(f"Errore durante la chiusura della connessione con {proxy.ipaddress}") 
                    with self.thread_lock:  
                        if proxy_list.get(proxy.ipaddress.compressed):
                            proxy_list.pop(proxy.ipaddress.compressed)
                            print(f"{proxy.ipaddress} rimosso...") 
                        else: print(f"{proxy.ipaddress} non rimosso...") 
            #----------------------- 
            if not isinstance(proxy_list, DATA.PROXY) or not len(proxy_list.values())>0: 
                raise ValueError("Lista dei proxy non valida") 
            if not is_ipaddress(ip_vittima): 
                raise TypeError("IP vittima non valido") 
            if not is_enum_member(attack_function, ATTACK_TYPE): 
                raise TypeError("Metodo attacco non valido") 
            for key in self.thread_list.keys(): 
                with self.thread_lock:
                    self.thread_list[key]=threading.Thread( 
                        #La callback controlla la connesisone fra l'attaccante ed il proxy
                        target=callback 
                        ,args=[proxy_list[key]] 
                    ) 
                    self.thread_list[key].name=f"Thread-Connect-{key}" 
                self.thread_list[key].start() 
            for thread in self.thread_list.values(): 
                thread.join() 
            print("Chiusura della connessione con proxy inutilizzabili")
            pop_proxy_inutilizzati()

    class WAIT_DATA:
        def __init__(self, proxy_list:dict[str,DATA.PROXY]): 
            if not isinstance(proxy_list, DATA.PROXY) or not len(proxy_list.values())>0: 
                raise ValueError("Lista dei proxy non valida") 
            self.thread_lock=get_threading_Lock() 
            self.thread_list:dict[str:threading.Thread]=dict() 
            self.thread_response:dict[str:threading.Thread]=dict() 
            for proxy in proxy_list.values(): 
                self.thread_list[proxy.ipaddress.compressed]=None  
                self.thread_response[proxy.ipaddress.compressed]=False  
        
        def start(self, proxy_list:dict[str,DATA.PROXY]): 
            def callback(proxy_data:DATA.PROXY):  
                if not isinstance(proxy_data, DATA.PROXY):
                    print(f"THREAD.WAIT_DATA: proxy {proxy_data} non valido")
                    return 
                data=""
                while True:  
                    chunk=proxy_data.socket.recv(1024) 
                    print(f"Received from {proxy_data.ipaddress}:\t{chunk.decode()}")
                    if not chunk:
                        break
                    data+=chunk.decode() 
                    if MSG.END_SOCKETSEND.value in data: 
                        data=data.replace(MSG.END_SOCKETSEND.value,"")
                        with proxy_data.data_lock: 
                            proxy_data.data_received.append(data) 
                        if MSG.LAST_PACKET.value not in data: 
                            data="" 
                    if MSG.LAST_PACKET.value in data: 
                        data=data.replace(MSG.LAST_PACKET.value,"") 
                        with proxy_data.data_lock: 
                            proxy_data.data_received.append(data)
                        break 
            #-------------------------------
            if not isinstance(proxy_list, DATA.PROXY) or not len(proxy_list.values())>0: 
                raise ValueError("Lista dei proxy non valida") 
            for key in self.thread_list.keys(): 
                with self.thread_lock:
                    self.thread_list[key]=threading.Thread(
                        target=callback, 
                        args=[proxy_list[key]]
                    ) 
                    self.thread_list[key].name=f"Thread-WaitData-{proxy_list[key].ipaddress.compressed}" 
                    self.thread_list[key].start()  
            print("Definiti e avviati i thread che aspettano i dati dai proxy") 
