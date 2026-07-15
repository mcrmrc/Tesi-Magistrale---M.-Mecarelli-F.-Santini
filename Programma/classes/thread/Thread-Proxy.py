import ipaddress
import threading
from Programma.custom_enum import MSG
from Programma.classes import CALC, INTERFACE_FROM_IP
from Programma.methods.check_type import is_ipaddress
from scapy.all import AsyncSniffer, Raw, IP, ICMP
from Programma.config import DEBUG, timeout_time
from Programma.methods.get_methods import get_AsyncSniffer, get_threading_Event, get_threading_Lock, get_timer
from Programma.methods.utils_methods import threadEvent_set, threadEvent_wait


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
