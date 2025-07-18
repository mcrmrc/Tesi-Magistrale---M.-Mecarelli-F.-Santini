import sys
import os

file_path = "../comunication_methods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import comunication_methods as com

file_path = "../mymethods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import mymethods 

#from scapy.all import * 
from scapy.all import get_if_hwaddr, Ether, IPv6, ICMPv6EchoReply, Raw, sendp, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ParamProblem, IPerror6, ICMPv6TimeExceeded, ICMPv6PacketTooBig, ICMPv6DestUnreach

import datetime 
import time
import ipaddress
import os

def ping_once(ip_dst:ipaddress.IPv4Address|ipaddress.IPv6Address=None, iface:str=None, timeout=1):
    try:
        com.is_string(iface)
        if isinstance(ip_dst, ipaddress.IPv4Address) or isinstance(ip_dst, ipaddress.IPv6Address):
            os.system(f"ping6 -c 1 {ip_dst.compressed}%{iface}")
        else: raise Exception("L'indirizzo non è ne un 'ipaddress.IPv4Address' ne un 'ipaddress.IPv6Address'")
    except Exception as e:
        raise Exception(f"ping_once: {e}")
    

class Attacker:
    def __init__(self):
        data="Hello_World".encode()
        data="cd /home/marco;ls -l".encode()
        data="Ciao".encode() 
        ip_src="fe80::e274:33a8:a3ca:46ff" #attaccante
        ip_src="fe80::d612:a36a:59a1:f465" #proxy1
        ip_dst="fe80::43cc:4881:32d7:a33e"#vittima
        #DONE
        #self.send_information_reply(data, ip_dst,ip_src) 
        #self.send_parameter_problem(data, ip_dst, ip_src) 
        #self.send_time_exceeded(data, ip_dst, ip_src)
        #self.send_packet_to_big(data, ip_dst, ip_src) 
        #self.send_destination_unreachable(data, ip_dst, ip_src)          
        
        # Equazione retta Timing CC y=1.17667x^{2}-4.66x+11.81333
        self.send_timing_channel_1bit(data, ip_dst, ip_src) 
        #self.send_timing_channel_2bit(data, ip_dst, ip_src) 
        #self.send_timing_channel_4bit(data, ip_dst, ip_src) 

    def send_information_reply(self,data:bytes=None,ip_dst=None,ip_src=None): 
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        try: 
            addr_src=ipaddress.IPv6Address(ip_src) 
            addr_dst=ipaddress.IPv6Address(ip_dst) 
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}")   
        try:
            interface= mymethods.iface_from_IP(addr_dst)
            if interface is None: 
                print(f"L'interfaccia è {interface}")
                interface=mymethods.default_iface()
                ping_once(addr_dst,interface)
            if mymethods.iface_from_IP(addr_dst.compressed) is None:
                print("Problema con l'interfaccia non risolto") 
        except Exception as e:
            print(f"Excepion: {e}") 
            interface=mymethods.default_iface() 
        dst_mac=com.get_mac_by_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface)
        #pkt= (
        #     Ether(dst=dst_mac, src=src_mac)
        #    /IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)
        #    /ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=0) 
        #    / Raw(load="Hello Neighbour".encode())
        #) 
        #print(f"Sending {pkt.summary()} through interface {interface}")  
        #ans = sendp(pkt, verbose=1,iface=interface) 
        #if ans:  
        #    print(ans.show())
        #    return True  
        #return False  
        print("DATA:", data)
        for index in range(0, len(data), 2): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
                #print("Data: ",data[index],chr(data[index]),type(data[index])) 
            else:
                icmp_id=(data[index]<<8)+data[index+1]
                #print("Data: ",data[index],chr(data[index]),type(data[index])) 
                #print("Data: ",data[index+1],chr(data[index+1]),type(data[index+1]))  
            #print("ICMP ID: ",icmp_id, type(icmp_id), sys.getsizeof(icmp_id))
                #print(f"{data[index]} {data[index+1]} => icmp_id: {icmp_id}")
            pkt= (
                 Ether(dst=dst_mac, src=src_mac)
                /IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)
                /ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=icmp_id)
            )
            print(f"Sending {pkt.summary()}") 
            ans = sendp(pkt, verbose=1,iface=interface) 
            #if ans: 
                #print(ans.show())
                #return True  
            #return False
        pkt= (
            Ether(dst=dst_mac, src=src_mac)
            /IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed)
            /ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY,id=0, seq=1)
            / Raw(load="Hello Neighbour".encode())
        )
        print(f"Sending {pkt.summary()}") 
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            print(ans.show())
            return True  
        return False 
    
    def send_parameter_problem(self,data:bytes=None,ip_dst=None,ip_src=None): 
        TYPE_PARAMETER_PROBLEM=4  
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        try: 
            addr_src=ipaddress.IPv6Address(ip_src) 
            addr_dst=ipaddress.IPv6Address(ip_dst) 
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}")   
        try:
            interface= mymethods.iface_from_IP(addr_dst) 
            if interface is None: 
                print(f"L'interfaccia è {interface}")
                interface=mymethods.default_iface()
                ping_once(addr_dst,interface)
            if mymethods.iface_from_IP(addr_dst.compressed) is None:
                print("Problema con l'interfaccia non risolto") 
        except Exception as e:
            print(f"Excepion: {e}")  
            interface=mymethods.default_iface() 
        dst_mac=com.get_mac_by_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        print("DATA: ",len(data)," : ",data)  
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
            print(pkt.show2()) 
            print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface) 
            if ans: 
                print(ans.show())
                #return True  
            #return False 

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
        print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            print(ans.show())
        #   #return True  
        #return False  

    def send_time_exceeded(self, data:bytes=None, ip_dst=None, ip_src=None): 
        TYPE_TIME_EXCEEDED= 3
        TYPE_INFORMATION_REPLY=129
        try: 
            addr_src=ipaddress.IPv6Address(ip_src) 
            addr_dst=ipaddress.IPv6Address(ip_dst) 
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}")   
        try:
            interface= mymethods.iface_from_IP(addr_dst) 
            if interface is None: 
                print(f"L'interfaccia è {interface}")
                interface=mymethods.default_iface()
                ping_once(addr_dst,interface)
            if mymethods.iface_from_IP(addr_dst.compressed) is None:
                print("Problema con l'interfaccia non risolto") 
        except Exception as e:
            print(f"Excepion: {e}")  
            interface=mymethods.default_iface() 
        dst_mac=com.get_mac_by_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 

        print("DATA: ",data)  
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
            print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface) 
            if ans: 
                print(ans.show())
                #return True  
            #return False 
        
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
        print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            print("ans: ",ans.show())
            #return True  
        #return False
    
    def send_packet_to_big(self, data:bytes=None, ip_dst=None, ip_src=None):
        TYPE_PKT_BIG= 2
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        try: 
            addr_src=ipaddress.IPv6Address(ip_src) 
            addr_dst=ipaddress.IPv6Address(ip_dst) 
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}")   
        try:
            interface= mymethods.iface_from_IP(addr_dst) 
            if interface is None: 
                print(f"L'interfaccia è {interface}")
                interface=mymethods.default_iface()
                ping_once(addr_dst,interface)
            if mymethods.iface_from_IP(addr_dst.compressed) is None:
                print("Problema con l'interfaccia non risolto") 
        except Exception as e:
            print(f"Excepion: {e}")  
            interface=mymethods.default_iface() 
        dst_mac=com.get_mac_by_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface)  

        print("DATA: ",data)  
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
            print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface) 
            if ans: 
                print(ans.show())
                #return True  
            #return False 

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
        print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            print("ans: ",ans.show())
            #return True  
        #return False
    
    def send_destination_unreachable(self, data:bytes=None, ip_dst=None, ip_src=None):
        TYPE_DESTINATION_UNREACHABLE=1 
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        try: 
            addr_src=ipaddress.IPv6Address(ip_src) 
            addr_dst=ipaddress.IPv6Address(ip_dst) 
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}")   
        try:
            interface= mymethods.iface_from_IP(addr_dst) 
            if interface is None: 
                print(f"L'interfaccia è {interface}")
                interface=mymethods.default_iface()
                ping_once(addr_dst,interface)
            if mymethods.iface_from_IP(addr_dst.compressed) is None:
                print("Problema con l'interfaccia non risolto") 
        except Exception as e:
            print(f"Excepion: {e}")  
            interface=mymethods.default_iface() 
        dst_mac=com.get_mac_by_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface)   

        print("DATA: ",data)  
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
            print(f"Sending {pkt.summary()} through interface {interface}")  
            ans = sendp(pkt, verbose=1,iface=interface) 
            if ans: 
                print(ans.show())
                #return True  
            #return False  
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
        print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface) 
        if ans: 
            print("ans: ",ans.show())
            #return True  
        #return False

    def send_timing_channel_1bit(self, data:bytes=None, ip_dst=None, ip_src=None): #Exec Time 0:14:46
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        TEMPO_0=3 #sec
        DISTANZA_TEMPI=2 #sec
        TEMPO_1=8 #sec
        if TEMPO_0+DISTANZA_TEMPI*2>=TEMPO_1: 
            raise ValueError("send_timing_channel: TEMPO_1 non valido")
        TEMPO_BYTE=0*60 #minuti

        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129

        try: 
            addr_src=ipaddress.IPv6Address(ip_src) 
            addr_dst=ipaddress.IPv6Address(ip_dst) 
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        try:
            interface= mymethods.iface_from_IP(addr_dst) 
            if interface is None: 
                print(f"L'interfaccia è {interface}")
                interface=mymethods.default_iface()
                ping_once(addr_dst,interface)
            if mymethods.iface_from_IP(addr_dst.compressed) is None:
                print("Problema con l'interfaccia non risolto") 
        except Exception as e:
            print(f"Excepion: {e}")  
            interface=mymethods.default_iface() 
        dst_mac=com.get_mac_by_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        print("DATA: ",data) 
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) 
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
            print(chr(piece_data),piece_data, bit_piece_data) 
        print(bit_data)

        start_time=datetime.datetime.now(datetime.timezone.utc) 
        pkt= (
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
            ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
            Raw(load="Hello Neighbour".encode())
        ) 
        print(f"Sending {pkt.summary()} through interface {interface}")  
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
                print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface) 
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc)
        #print("Exec Time",int((end_time-start_time).total_seconds() * 1000))
        print("Exec Time", str(end_time-start_time))
    
    def send_timing_channel_2bit(self, data:bytes=None, ip_dst=None, ip_src=None): #Exec Time 12:08
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        DISTANZA_TEMPI=2 #sec
        TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(2**2)] #00, 01, 10, 11
        #TEMPO_00=3, TEMPO_01=TEMPO_00+2*DISTANZA_TEMPI, TEMPO_10=TEMPO_01+2*DISTANZA_TEMPI, TEMPO_11=TEMPO_10+2*DISTANZA_TEMPI
        TEMPO_BYTE=0*60 #minuti  
        print(TEMPI_CODICI)
        
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129

        try: 
            addr_src=ipaddress.IPv6Address(ip_src) 
            addr_dst=ipaddress.IPv6Address(ip_dst) 
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}")   
        try:
            interface= mymethods.iface_from_IP(addr_dst) 
            if interface is None: 
                print(f"L'interfaccia è {interface}")
                interface=mymethods.default_iface()
                ping_once(addr_dst,interface)
            if mymethods.iface_from_IP(addr_dst.compressed) is None:
                print("Problema con l'interfaccia non risolto") 
        except Exception as e:
            print(f"Excepion: {e}")  
            interface=mymethods.default_iface() 
        dst_mac=com.get_mac_by_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)  
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
            print(chr(piece_data),piece_data, bit_piece_data)  
        
        start_time=datetime.datetime.now(datetime.timezone.utc)
        pkt= (
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
            ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
            Raw()
        ) 
        print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface)  
        for piece_bit_data in bit_data:
            for bit1, bit2 in zip(piece_bit_data[0::2], piece_bit_data[1::2]):
                #print(bit1,bit2,"|", (bit1<<1)+bit2,"|", TEMPI_CODICI[(bit1<<1)+bit2])  
                time.sleep(TEMPI_CODICI[(bit1<<1)+bit2]) 
                current_time=datetime.datetime.now(datetime.timezone.utc)
                pkt= (
                    Ether(dst=dst_mac, src=src_mac) /
                    IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
                    ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                    Raw()
                ) 
                print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface)  
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc)
        #print("Exec Time",int((end_time-start_time).total_seconds() * 1000))
        print("Exec Time", str(end_time-start_time))
    
    def send_timing_channel_4bit(self, data:bytes=None, ip_dst=None, ip_src=None): #Exec Time 0:22:20.745110 
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        DISTANZA_TEMPI=2 #sec
        TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(4**2)] #0000, 0001, 0010, 0011,...,1111
        TEMPO_BYTE=0*60 #minuti  
        print(TEMPI_CODICI)
        
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        try: 
            addr_src=ipaddress.IPv6Address(ip_src) 
            addr_dst=ipaddress.IPv6Address(ip_dst) 
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}")   
        
        try:
            interface= mymethods.iface_from_IP(addr_dst) 
            if interface is None: 
                print(f"L'interfaccia è {interface}")
                interface=mymethods.default_iface()
                ping_once(addr_dst,interface)
            if mymethods.iface_from_IP(addr_dst.compressed) is None:
                print("Problema con l'interfaccia non risolto") 
        except Exception as e:
            print(f"Excepion: {e}")  
            interface=mymethods.default_iface() 
        dst_mac=com.get_mac_by_ipv6(addr_dst.compressed, addr_src.compressed, interface)  
        src_mac = get_if_hwaddr(interface) 
        
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)  
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
            print(chr(piece_data),piece_data, bit_piece_data)  
        
        start_time=datetime.datetime.now(datetime.timezone.utc)
        pkt= (
            Ether(dst=dst_mac, src=src_mac) /
            IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
            ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
            Raw()
        ) 
        print(f"Sending {pkt.summary()} through interface {interface}")  
        ans = sendp(pkt, verbose=1,iface=interface)  
        for piece_bit_data in bit_data:
            for bit1, bit2,bit3,bit4 in zip(piece_bit_data[0::4], piece_bit_data[1::4],piece_bit_data[2::4], piece_bit_data[3::4]):
                index=bit1<<3 | bit2<<2 |  bit3<<1 | bit4 
                print(bit1, bit2,bit3,bit4,"|", index,"|", TEMPI_CODICI[index])  
                time.sleep(TEMPI_CODICI[index])  
                pkt= (
                    Ether(dst=dst_mac, src=src_mac) /
                    IPv6(dst=f"{addr_dst.compressed}%{interface}",src=addr_src.compressed) /
                    ICMPv6EchoReply(type=TYPE_INFORMATION_REPLY) /
                    Raw()
                ) 
                print(f"Sending {pkt.summary()} through interface {interface}")  
                ans = sendp(pkt, verbose=1,iface=interface)
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc)
        #print("Exec Time",int((end_time-start_time).total_seconds() * 1000))
        print("Exec Time", str(end_time-start_time))
    
    def send_timing_channel_8bit(self,data:bytes=None,ip_dst=None):
        raise Exception("Tempo di esecuzione stimato: 50 minuti per inviare 11 byte")
    
if __name__=="__main__":
    print("Ciao")
    attacker=Attacker()