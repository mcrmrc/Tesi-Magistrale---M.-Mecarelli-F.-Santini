from Programma.methods.check_type import is_ipaddress, is_list, is_integer, is_dictionary, is_boolean, is_enum_member, is_callable_function, is_bytes
from Programma.classes import GET_MAC_ADDRESS, INTERFACE_FROM_IP, SNIFFER
from Programma.methods.utils_methods import ping_once
from Programma.methods.get_methods import get_local_IP
from custom_enum import ICMP_TYPE, ATTACK_TYPE
from enum import Enum 
from scapy.all import sendp, sniff, ICMP, Ether, IP, ICMPerror, IPerror, Raw, random, get_if_hwaddr, IPv6, IPerror6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded, ICMPv6ParamProblem
from thread_methods import TIMER
from classes import checksum
from classes import POWER_SLEEP
from Programma.methods.get_methods import get_timer
from datetime import timezone
from abc import ABC, abstractmethod
from Programma.methods.utils_methods import threadEvent_wait, threadEvent_set
import ipaddress, string, datetime, time, threading, struct

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
        default_interface=default_interface()
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
        #threadEvent_set(self.event_pktconn) 
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
            threadEvent_wait(self.event_pktconn) 
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
                    #threadEvent_set(self.event_pktconn)
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
                    #threadEvent_set(self.event_pktconn)
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
                    #threadEvent_set(self.event_pktconn)
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
                    #threadEvent_set(self.event_pktconn) 
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
        if not is_enum_member(type_attacco, ATTACK_TYPE): 
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
                    #threadEvent_set(self.event_pktconn)
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
        if not is_enum_member(type_attacco, ATTACK_TYPE): 
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
                    #threadEvent_set(self.event_pktconn)
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
        if not is_enum_member(type_attacco, ATTACK_TYPE): 
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
                    #threadEvent_set(self.event_pktconn) 
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
        if not is_enum_member(type_attacco, ATTACK_TYPE): 
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
        if not is_enum_member(type_attacco, ATTACK_TYPE): 
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
                    #threadEvent_set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return 
                if self.type_attacco.name in [ATTACK_TYPE.ipv4_echo_campi.name, ATTACK_TYPE.ipv4_echo_campi_payload.name,ATTACK_TYPE.ipv4_echo_random_payload.name]: 
                    #print("ICMP ID")
                    icmp_id=packet[ICMP].id
                    byte1 = (icmp_id >> 8) & 0xFF 
                    byte2 = icmp_id & 0xFF 
                    #print("ICMP ID:",icmp_id,chr(byte1),chr(byte2))
                    self.data.append(chr(byte1)+chr(byte2)) 
                if self.type_attacco.name in [ATTACK_TYPE.ipv4_echo_payload.name, ATTACK_TYPE.ipv4_echo_campi_payload.name,ATTACK_TYPE.ipv4_echo_random_payload.name]: 
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
        if not is_enum_member(type_attacco, ATTACK_TYPE): 
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
            threadEvent_wait(self.event_pktconn) 
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
                #threadEvent_set(self.event_pktconn) 
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
        ip_src=get_local_IP() 
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
                #threadEvent_set(self.event_pktconn) 
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
        #ip_src=get_local_IP()  
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
        ip_src=get_local_IP() 
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
                #threadEvent_set(self.event_pktconn) 
                self.stop_flag["value"]=True 
                return 
            self.data.append(ptr.to_bytes(2,"big").decode()) 
            if icmp_layer:=(packet.getlayer(ICMPv6EchoRequest) or packet.getlayer(ICMPv6EchoReply)): 
                id=icmp_layer.getfieldval("id")
                if id==self.stop_integer and icmp_layer.getfieldval("seq")==self.stop_integer: 
                    #threadEvent_set(self.event_pktconn) 
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
        ip_src=get_local_IP() 
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
                    #threadEvent_set(self.event_pktconn) 
                    self.stop_flag["value"]=True 
                    return
                self.data.append(plen.to_bytes(2,"big"))#.decode()) 
                icmp_layer=(packet.getlayer(ICMPv6EchoRequest) or packet.getlayer(ICMPv6EchoReply)) 
                id=icmp_layer.getfieldval("id")
                if id==self.stop_integer and icmp_layer.getfieldval("seq")==self.stop_integer: 
                    #threadEvent_set(self.event_pktconn) 
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
        ip_src=get_local_IP() 
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
                #threadEvent_set(self.event_pktconn) 
                self.stop_flag["value"]=True 
                return
            self.data.append(plen.to_bytes(2,"big"))#.decode()) 
            icmp_layer=(packet.getlayer(ICMPv6EchoRequest) or packet.getlayer(ICMPv6EchoReply))
            if icmp_layer: 
                id=icmp_layer.getfieldval("id") 
                if id==0 and icmp_layer.getfieldval("seq")==1: 
                    #threadEvent_set(self.event_pktconn) 
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
        ip_src=get_local_IP() 
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
