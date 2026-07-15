from enum import Enum
from Programma.methods.check_type import is_enum_member, is_ipaddress, is_list
from custom_enum import SENDER_TYPE, ATTACK_TYPE
from Programma.methods.network_methods import get_local_IP, get_hosts_attivi 
from attack.attack_classes import IPV4_DESTINATION_UNRECHABLE, IPV4_TIME_EXCEEDED, IPV4_PARAMETER_PROBLEM, IPV4_SOURCE_QUENCH, IPV4_REDIRECT, IPV4_ECHO, IPV4_TIMESTAMP, IPV4_INFORMATION, IPV4_TIMING_8BIT, IPV4_TIMING_8BIT_NOISE
from attack.attack_classes import IPV6_ECHO, IPV6_PARAMETER_PROBLEM, IPV6_TIME_EXCEEDED, IPV6_PACKET_BIG, IPV6_DESTINTION_UNREACHABLE, IPV6_TIMING
import ipaddress

def set_host_list(type_sender:Enum=None): 
    if not is_enum_member(type_sender, SENDER_TYPE): 
        raise Exception("type_sender non SENDER_TYPE") 
    lista_host = []
    match type_sender: 
        case SENDER_TYPE.TRUE_SENDER: 
            ip,err=get_local_IP()
            if err:
                raise Exception("Impossibile trovare l'IP locale: ", err)
            return [ip]
        case SENDER_TYPE.FAKE_SENDER_ACTIVE: 
            active_host,_= get_hosts_attivi() 
            for host in active_host: 
                try:  
                    lista_host.append(ipaddress.ip_address(host))
                except ValueError as value_err: 
                    print(f"Errore {host} non valido:",value_err) 
            print("ATTIVI:",lista_host) 
            return lista_host
        case SENDER_TYPE.FAKE_SENDER_INACTIVE: 
            _,inactive_host= get_hosts_attivi()
            for host in inactive_host: 
                try: 
                    lista_host.append(ipaddress.ip_address(host))
                except ValueError as value_err: 
                    print(f"Errore {host} non valido:",value_err) 
            print("INATTIVI:",lista_host)
            return lista_host
        case SENDER_TYPE.FAKE_SENDER_BOTH: 
            active_host,inactive_host= get_hosts_attivi()
            for host in active_host: 
                try: 
                    lista_host.append(ipaddress.ip_address(host))
                except ValueError as value_err: 
                    print(f"Errore {host} non valido:",value_err) 
            for host in inactive_host: 
                try: 
                    lista_host.append(ipaddress.ip_address(host))
                except ValueError as value_err: 
                    print(f"Errore {host} non valido:",value_err) 
            print("ATTIVI/INATTIVI:",lista_host)
            return lista_host
        case _: raise Exception("Tipo di sender non valido: ", type_sender) 

def get_typeAtacco(type_attacco:Enum=None, ip_dst:ipaddress.IPv4Address=None, host_list:list[ipaddress._IPAddressBase]=None): 
    def ipv4_match(): 
        match type_attacco:
            case ATTACK_TYPE.ipv4_destination_unreachable|ATTACK_TYPE.ipv4_destination_unreachable_unused: 
                return IPV4_DESTINATION_UNRECHABLE(ip_dst, host_list) 
            case ATTACK_TYPE.ipv4_time_exceeded|ATTACK_TYPE.ipv4_time_exceeded_unused: 
                return IPV4_TIME_EXCEEDED(ip_dst, host_list) 
            case ATTACK_TYPE.ipv4_parameter_problem|ATTACK_TYPE.ipv4_parameter_problem_unused: 
                return IPV4_PARAMETER_PROBLEM(ip_dst, host_list) 
            case ATTACK_TYPE.ipv4_source_quench|ATTACK_TYPE.ipv4_source_quench_unused: 
                return IPV4_SOURCE_QUENCH(ip_dst, host_list) 
            case ATTACK_TYPE.ipv4_redirect: 
                return IPV4_REDIRECT(ip_dst, host_list)
            case ATTACK_TYPE.ipv4_echo_campi|ATTACK_TYPE.ipv4_echo_payload|ATTACK_TYPE.ipv4_echo_campi_payload|ATTACK_TYPE.ipv4_echo_random_payload: 
                return IPV4_ECHO(ip_dst, host_list, type_attacco) 
            case ATTACK_TYPE.ipv4_timestamp: 
                return IPV4_TIMESTAMP(ip_dst, host_list)
            case ATTACK_TYPE.ipv4_information: 
                return IPV4_INFORMATION(ip_dst, host_list)
            case ATTACK_TYPE.ipv4_timing_channel_8bit: 
                return IPV4_TIMING_8BIT(ip_dst, host_list)
            case ATTACK_TYPE.ipv4_timing_channel_8bit_noise: 
                return IPV4_TIMING_8BIT_NOISE(
                    ip_dst, host_list, {"min_delay":1, "max_delay":30, "rumore":2, "seed":4582}
                )
            case _: raise Exception(f"Tipologia non conosciuta: {type_attacco}") 
    def ipv6_match():
        match type_attacco: 
            case ATTACK_TYPE.ipv6_echo: 
                return IPV6_ECHO(ip_dst, host_list)
            case ATTACK_TYPE.ipv6_parameter_problem: 
                return IPV6_PARAMETER_PROBLEM(ip_dst, host_list)
            case ATTACK_TYPE.ipv6_time_exceeded: 
                return IPV6_TIME_EXCEEDED(ip_dst, host_list)
            case ATTACK_TYPE.ipv6_packet_to_big: 
                return IPV6_PACKET_BIG(ip_dst, host_list)
            case ATTACK_TYPE.ipv6_destination_unreachable: 
                return IPV6_DESTINTION_UNREACHABLE(ip_dst, host_list)
            case ATTACK_TYPE.ipv6_timing_cc:  
                return IPV6_TIMING(ip_dst, host_list) 
            case _: raise Exception(f"Tipologia non conosciuta: {type_attacco}") 
    #------------------------
    if not is_enum_member(type_attacco, ATTACK_TYPE): 
        raise Exception("type_attacco non ATTACK_TYPE: ") 
    if not is_ipaddress(ip_dst): 
        raise TypeError("ip_dst non valido")
    if not is_list(host_list) or len(host_list)<=0 or any(not is_ipaddress(ip) for ip in host_list): 
        raise ValueError("host_list non valida")  
    if is_ipaddress(ip_dst) and ip_dst.version==4: 
        return ipv4_match()
    elif is_ipaddress(ip_dst) and ip_dst.version==6: 
        return ipv6_match()
    else: raise Exception("Indirizzo destinazione non valido: ",ip_dst)

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






