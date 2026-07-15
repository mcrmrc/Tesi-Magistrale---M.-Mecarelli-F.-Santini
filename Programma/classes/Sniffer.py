
import ipaddress
import threading
from Programma.classes import CALC
from Programma.methods.utils_methods import check_sniffer_args
from scapy.all import AsyncSniffer, Ether, IP, ICMP, sendp 
from Programma.methods.check_type import is_AsyncSniffer, is_bytes, is_callable_function, is_callable_function, is_integer, is_integer, is_ipaddress, is_threading_Event, is_threading_Timer, is_time
from Programma.methods.get_methods import get_AsyncSniffer, get_timer, get_timer
from Programma.methods.utils_methods import threadEvent_set
from Programma.classes import GET_MAC_ADDRESS, INTERFACE_FROM_IP


class SNIFFER: 
    def start(sniffer:AsyncSniffer=None, timer:threading.Timer=None): 
        if not (is_AsyncSniffer(sniffer) and is_threading_Timer(timer)): 
            raise Exception(f"SNIFFER.start: Argomenti in input non validi")
        sniffer.start()
        timer.start() 

    def stop(sniffer:AsyncSniffer=None): 
        if is_AsyncSniffer(sniffer): 
            if sniffer.running: 
                print("Fermo lo sniffer.",end=" ") 
                sniffer.stop() 
                if not sniffer.running:
                    print("Sniffer fermato correttamente.") 
                    return True
                print("Sniffer ancora vivo")
            else: 
                print("Lo sniffer non era in esecuzione")
            return False  
        raise Exception(f"Sniffer non istanza di AsyncSniffer: {type(sniffer)}") 

    def template_timeout(event:threading.Event=None):  
        if not is_threading_Event(event): 
            raise Exception("template_timeout: Argomenti non validi")  
        if not event.is_set():
            print("Timeout: No packet received within 60 seconds") 
            #SNIFFER.stop(sniffer) if sniffer.running else print("Sniffer non in esecuzione")  
            threadEvent_set(event)

    def sniff_packet(args:dict=None,timeout_time=60, callback_func_timer=None): 
        if  check_sniffer_args(args) and (timeout_time is None or is_time(timeout_time)): 
            sniffer= get_AsyncSniffer(args) 
            timeout_time=int(timeout_time) if timeout_time is not None else timeout_time  
            if not is_callable_function(callback_func_timer): 
                print("Considera l'utilizzo di 'template_timeout'")
                raise Exception(f"sniff_packet: callback non definita {callback_func_timer}")
            timer = get_timer(timeout_time, callback_func_timer) 
            SNIFFER.start(sniffer, timer)  
            if sniffer.running:
                print("Lo sniffer è partito")
            else: raise Exception("Lo sniffer non è partito")
            return sniffer, timer 
        raise Exception(f"sniff_packet: Argomenti non validi") 

    def send_packet(data:bytes=None,ip_dst:ipaddress.IPv4Address=None, icmp_seq:int=0,icmp_id:int=0): 
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(ip_dst): 
            raise TypeError("ip_dst non valido") 
        if not is_integer(icmp_seq): 
            #raise TypeError("icmp_seq non valido") 
            icmp_seq=0
        if not is_integer(icmp_id): 
            raise TypeError("icmp_id non valido") 
        icmp_id=CALC.checksum(data) 
        target_mac=GET_MAC_ADDRESS(ip_dst).mac_address 
        if not target_mac: 
            raise TypeError("target_mac non valido") 
        interface=INTERFACE_FROM_IP(ip_dst).interface 
        if not interface: 
            raise TypeError("interface non valido") 
        print("MAC",target_mac) 
        print("INTERFACE",interface) 
        pkt = Ether(dst=target_mac)/\
            IP(dst=ip_dst.compressed)/\
            ICMP(id=icmp_id,seq=icmp_seq)/\
            data 
        print(f"send_packet {pkt.summary()}") 
        sendp(pkt, verbose=1, iface=interface) 
