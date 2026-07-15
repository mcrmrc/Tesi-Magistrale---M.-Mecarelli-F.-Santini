#from scapy.all import * 
from scapy.all import IP, ICMP, IPerror, ICMPerror

import sys
import os
import ipaddress

file_path = "../comunication_methods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import comunication_methods as com

file_path = "../mymethods.py"
directory = os.path.dirname(file_path)
sys.path.insert(0, directory)
import mymethods 


def timeout_timing_covertchannel(event_pktconn):
    print("Dati non ricevuti in tempo. La comunicazione è terminata")
    com.set_threading_Event(event_pktconn)
    return

def callback_get_timing_cc(event_pktconn,timer,timing_data=[],previous_time=None, numero_bit=0): 
    if numero_bit<=0:
        return None  
    callback_function=lambda: timeout_timing_covertchannel(event_pktconn)  

    DISTANZA_TEMPI=2 #sec
    dict_tempi={}
    dict_tempi.update( [("TEMPO_"+str(index), 3+index*2*DISTANZA_TEMPI)  for index in range(2**numero_bit)])
    dict_bit={ }
    dict_bit.update([ ("TEMPO_"+str(index), index)  for index in range(2**numero_bit) ]) 
    #print(dict_tempi)
    #print(dict_bit) 

    MINUTE_TIME=0*60+30 #minuti
    MAX_TIME=max([value for _,value in dict_tempi.items()])+5 
    
    def callback(packet):
        nonlocal previous_time, timer,timing_data, event_pktconn, callback_function
        nonlocal MAX_TIME, MINUTE_TIME
        print(f"callback get_timing_cc received:\n\t{packet.summary()}") 
        #print("previous_time",previous_time, type(previous_time))
        if previous_time is None:
            print(f"No previous time {previous_time}")
            previous_time=packet.time
            print(f"The new one is {previous_time}")
            timer.cancel()
            timer=com.get_timeout_timer(MAX_TIME,callback_function) 
            timer.start()
            print(f"Timer started")
            return  
        if packet.time is not None: 
            delta_time=packet.time-previous_time   
            arr=arr=[(key, abs(delta_time-value)) for key,value in dict_tempi.items()] 
            min_value=min([y for _,y in arr]) 
            min_indices = [i for i, v in enumerate(arr) if v[1] == min_value]
            if len(min_indices)!=1:
                print(f"Più minimi combaciano {min_indices}: {arr}") 
            timing_data.append(dict_bit.get(arr[min_indices[0]][0]))
            previous_time=packet.time
            timer.cancel()
            #print("timing_data: ",len(timing_data)," - ",timing_data)
            if len(timing_data)%8==0:
                #print("Received a byte. ") 
                timer=com.get_timeout_timer(MINUTE_TIME,callback_function) 
            else:
                timer=com.get_timeout_timer(MAX_TIME,callback_function) 
            timer.start()
    return callback

def callback_get_destination_unreachable(event_pktconn,data):
    TYPE_DESTINATION_UNREACHABLE=3 
    def callback(packet):
        print(f"callback get_destination_unreachable received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            if packet[ICMP].haslayer(IPerror) and packet[ICMP].haslayer(ICMPerror): 
                data.append(packet[ICMP].unused.decode())  
                data.append(packet[ICMP][IPerror].len.to_bytes(2,"big").decode())  
                data.append(packet[ICMP][ICMPerror].id.to_bytes(2,"big").decode()) 
                if packet[ICMP][ICMPerror].id==0 and packet[ICMP][ICMPerror].seq==1:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_DESTINATION_UNREACHABLE and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(event_pktconn)
                return
    return callback

def callback_get_time_exceeded(event_pktconn,data):
    TYPE_TIME_EXCEEDED=11  
    def callback(packet):
        print(f"callback get_time_exceeded received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            if packet[ICMP].haslayer(IPerror) and packet[ICMP].haslayer(ICMPerror): 
                data.append(packet[ICMP].unused.to_bytes(2,"big").decode())  
                data.append(packet[ICMP][IPerror].len.to_bytes(2,"big").decode())  
                data.append(packet[ICMP][ICMPerror].id.to_bytes(2,"big").decode()) 
                if packet[ICMP][ICMPerror].id==0 and packet[ICMP][ICMPerror].seq==1:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_TIME_EXCEEDED and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(event_pktconn)
                return
    return callback

def callback_get_parameter_problem(event_pktconn,data):
    TYPE_SOURCE_QUENCH=4  
    def callback(packet):
        print(f"callback get_parameter_problem received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            if packet[ICMP].haslayer(IPerror) and packet[ICMP].haslayer(ICMPerror): 
                data.append(packet[ICMP].ptr.to_bytes(1,"big").decode())
                data.append(packet[ICMP].unused.to_bytes(2,"big").decode())  
                data.append(packet[ICMP][IPerror].len.to_bytes(2,"big").decode())  
                data.append(packet[ICMP][ICMPerror].id.to_bytes(2,"big").decode()) 
                if packet[ICMP][ICMPerror].id==0 and packet[ICMP][ICMPerror].seq==1:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_SOURCE_QUENCH and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(event_pktconn)
                return
    return callback

def callback_get_source_quench(event_pktconn,data):
    TYPE_SOURCE_QUENCH=4  
    def callback(packet):
        print(f"callback get_source_quench received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            if packet[ICMP].haslayer(IPerror) and packet[ICMP].haslayer(ICMPerror): 
                data.append(packet[ICMP].unused.to_bytes(4,"big").decode())  
                data.append(packet[ICMP][IPerror].len.to_bytes(2,"big").decode())  
                data.append(packet[ICMP][ICMPerror].id .to_bytes(2,"big").decode()) 
                if packet[ICMP][ICMPerror].id==0 and packet[ICMP][ICMPerror].seq==1:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_SOURCE_QUENCH and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(event_pktconn)
                return
    return callback

def callback_get_redirect_message(event_pktconn,data):
    TYPE_REDIRECT=5
    def callback(packet):
        print(f"callback get_redirect_message received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) :
            if packet[ICMP].haslayer(IPerror) and packet[ICMP].haslayer(ICMPerror):
                print(type(packet[ICMP].payload), packet[ICMP].summary())
                icmp_ip_length=packet[ICMP][IPerror].len
                data.append(icmp_ip_length.to_bytes(2,"big").decode()) 

                icmp_icmp_id=packet[ICMP][ICMPerror].id 
                data.append(icmp_icmp_id.to_bytes(2,"big").decode()) 
                if packet[ICMP][ICMPerror].id==0 and packet[ICMP][ICMPerror].seq==1:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_REDIRECT and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(event_pktconn)
                return
    return callback

def callback_get_timestamp_request(event_pktconn,data):
    def callback(packet):
        print(f"callback get_timestamp_request received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            print(f"Ricevuto pacchetto da {packet[IP].src}...")
            if packet[ICMP].id==0 and packet[ICMP].seq==1:
                print("END OF TRANSMISSION")
                com.set_threading_Event(event_pktconn)
                return
            icmp_id=packet[ICMP].id
            byte1 = (icmp_id >> 8) & 0xFF 
            byte2 = icmp_id & 0xFF 
            print(icmp_id,type(icmp_id))  
            print(byte1,byte2)
            print(chr(byte1),chr(byte2))
            data.extend([chr(byte1),chr(byte2)]) 
            
            icmp_ts_ori=str(packet[ICMP].ts_ori)[-3:]
            print("icmp_ts_ori",packet[ICMP].ts_ori) 
            print("icmp_ts_ori",icmp_ts_ori, chr(int(icmp_ts_ori)))

            icmp_ts_rx=str(packet[ICMP].ts_rx)[-3:]
            print("icmp_ts_rx",packet[ICMP].ts_rx) 
            print("icmp_ts_rx",icmp_ts_rx, chr(int(icmp_ts_rx)))

            icmp_ts_tx=str(packet[ICMP].ts_tx)[-3:]
            print("icmp_ts_tx",packet[ICMP].ts_tx) 
            print("icmp_ts_tx",icmp_ts_tx, chr(int(icmp_ts_tx)))

            data.extend([chr(int(icmp_ts_ori)),chr(int(icmp_ts_rx)), chr(int(icmp_ts_tx))]) 
    return callback

def callback_get_information_request(event_pktconn,data):
    def callback(packet):
        print(f"callback get_information_request received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            print(f"Ricevuto pacchetto da {packet[IP].src}...")
            if packet[ICMP].id==0 and packet[ICMP].seq==1:
                print("END OF TRANSMISSION")
                com.set_threading_Event(event_pktconn)
                return
            icmp_id=packet[ICMP].id
            byte1 = (icmp_id >> 8) & 0xFF 
            byte2 = icmp_id & 0xFF 
            #print(icmp_id,type(icmp_id))  
            #print(byte1,byte2)
            #print(chr(byte1),chr(byte2))
            data.extend([chr(byte1),chr(byte2)]) 
    return callback



class Victim:
    def __init__(self): 
        #self.get_information_request() 
        #self.get_timestamp_request() 
        #self.get_redirect() 
        #self.get_source_quench() 
        #self.get_parameter_problem() 
        #self.get_time_exceeded() 
        #self.get_destination_unreachable()  
        self.get_timing_cc(2) 

    def get_information_request(self):
        information_data=[]
        TYPE_INFORMATION_REQUEST=15
        TYPE_INFORMATION_REPLY=16
        ip_host=ipaddress.IPv4Address("192.168.56.102") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_information_request( self.event_pktconn,information_data)
                #,"store":True 
                ,"iface":interface
            }
        try: 
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in information_data))
            return True 
        return False  
    
    def get_timestamp_request(self):
        timestamp_data=[]
        TYPE_TIMESTAMP_REQUEST=13
        TYPE_TIMESTAMP_REPLY=14
        ip_host=ipaddress.IPv4Address("192.168.56.102") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_TIMESTAMP_REQUEST} or icmp[0]=={TYPE_TIMESTAMP_REPLY}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_timestamp_request(self.event_pktconn,timestamp_data)
                #,"store":True 
                ,"iface":interface
            }
        try: 
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in timestamp_data))
            return True 
        return False  
    
    def get_redirect(self):
        redirect_data=[]
        TYPE_REDIRECT=5
        ip_host=ipaddress.IPv4Address("192.168.56.102") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_REDIRECT}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_redirect_message(self.event_pktconn,redirect_data)
                #,"store":True 
                ,"iface":interface
        } 
        try: 
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in redirect_data))
            return True 
        return False  
    
    def get_source_quench(self):
        source_quench_data=[]
        TYPE_SOURCE_QUENCH=4  
        ip_host=ipaddress.IPv4Address("192.168.56.102") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_SOURCE_QUENCH}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_source_quench(self.event_pktconn,source_quench_data)
                #,"store":True 
                ,"iface":interface
        } 
        try: 
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in source_quench_data))
            return True 
        return False  
    
    def get_parameter_problem(self):
        parameter_problem_data=[]
        TYPE_PARAMETER_PROBLEM=12  
        ip_host=ipaddress.IPv4Address("192.168.56.102") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_PARAMETER_PROBLEM}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_parameter_problem(self.event_pktconn,parameter_problem_data)
                #,"store":True 
                ,"iface":interface
        } 
        try:
            self.event_pktconn=com.get_threading_Event()
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in parameter_problem_data))
            return True 
        return False  
    
    def get_time_exceeded(self):
        time_exceeded_data=[]
        TYPE_TIME_EXCEEDED=11  
        ip_host=ipaddress.IPv4Address("192.168.56.102") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_TIME_EXCEEDED}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_time_exceeded(self.event_pktconn,time_exceeded_data)
                #,"store":True 
                ,"iface":interface
        } 
        try:
            self.event_pktconn=com.get_threading_Event()
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in time_exceeded_data))
            return True 
        return False  
    
    def get_destination_unreachable(self):
        destination_unreachable_data=[]
        TYPE_DESTINATION_UNREACHABLE=3 
        ip_host=ipaddress.IPv4Address("192.168.56.102") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_DESTINATION_UNREACHABLE}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_destination_unreachable(self.event_pktconn,destination_unreachable_data)
                #,"store":True 
                ,"iface":interface
        } 
        try:
            self.event_pktconn=com.get_threading_Event()
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in destination_unreachable_data))
            return True 
        return False  
    
    def get_timing_cc(self,numero_bit=0): 
        try: 
            ip_host=ipaddress.IPv4Address("192.168.56.102") 
            interface= mymethods.default_iface()  
            if numero_bit<=0:
                raise Exception("Numero di bit passato non valido")
        except Exception as e:
            raise Exception(f"Exception: {e}")
        
        timing_data=[]
        TYPE_ECHO_REQUEST=8
        TYPE_ECHO_REPLY=0 
        last_packet_time=None  
        try: 
            self.event_pktconn=com.get_threading_Event()
            callback_function=lambda: timeout_timing_covertchannel(self.event_pktconn)
            self.timer_timing_CC=com.get_timeout_timer(None,callback_function) 
        except Exception as e:
            raise Exception(f"Exception: {e}") 
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_timing_cc(
                    self.event_pktconn
                    ,self.timer_timing_CC
                    ,timing_data
                    ,last_packet_time
                    ,numero_bit
                )
                #,"store":True 
                ,"iface":interface
        }  
        try: 
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            )  
            com.wait_threading_Event(self.event_pktconn) 
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
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print(data)
            return True 
        return False

if __name__=="__main__": 
    print("Ciao") 
    victim=Victim()