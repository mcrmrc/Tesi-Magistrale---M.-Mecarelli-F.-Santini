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

from scapy.all import * 

def callback_get_timing_cc(victim,data,previous_time):
    TYPE_DESTINATION_UNREACHABLE=3 
    TEMPO_0=3 #sec
    TEMPO_1=8 #sec
    def callback(packet):
        nonlocal previous_time
        print(f"callback get_timing_cc received:\n\t{packet.summary()}") 
        print("previous_time",previous_time, type(previous_time))
        if previous_time is None:
            previous_time=packet.time
            return
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            time=packet.time-previous_time
            delta_0=abs(time-TEMPO_0)
            delta_1=abs(time-TEMPO_1)
            print("packet.time",packet.time,"previous_time",previous_time)
            print("time",time)
            print("1st",delta_0)
            print("2nd",delta_1)
            arr=[delta_0,delta_1]
            min_value=min(arr)
            min_indices = [i for i, v in enumerate(arr) if v == min_value]
            if len(min_indices)!=1:
                print("Più minimi combaciano", min_indices, arr)
            print("Minimo",min_indices[0])
            previous_time=packet.time
    return callback

def callback_get_destination_unreachable(victim,data):
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
                    com.set_threading_Event(victim.event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_DESTINATION_UNREACHABLE and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(victim.event_pktconn)
                return
    return callback

def callback_get_time_exceeded(victim,data):
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
                    com.set_threading_Event(victim.event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_TIME_EXCEEDED and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(victim.event_pktconn)
                return
    return callback

def callback_get_parameter_problem(victim,data):
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
                    com.set_threading_Event(victim.event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_SOURCE_QUENCH and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(victim.event_pktconn)
                return
    return callback

def callback_get_source_quench(victim,data):
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
                    com.set_threading_Event(victim.event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_SOURCE_QUENCH and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(victim.event_pktconn)
                return
    return callback

def callback_get_redirect_message(victim,data):
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
                    com.set_threading_Event(victim.event_pktconn)
                    return
            elif packet[ICMP].type==TYPE_REDIRECT and not packet[ICMP].haslayer(IPerror): #packet.haslayer(Padding):
                print("Padding")
                com.set_threading_Event(victim.event_pktconn)
                return
    return callback

def callback_get_timestamp_request(victim,data):
    def callback(packet):
        print(f"callback get_timestamp_request received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            print(f"Ricevuto pacchetto da {packet[IP].src}...")
            if packet[ICMP].id==0 and packet[ICMP].seq==1:
                print("END OF TRANSMISSION")
                com.set_threading_Event(victim.event_pktconn)
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

def callback_get_information_request(victim,data):
    def callback(packet):
        print(f"callback get_information_request received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP): 
            print(f"Ricevuto pacchetto da {packet[IP].src}...")
            if packet[ICMP].id==0 and packet[ICMP].seq==1:
                print("END OF TRANSMISSION")
                com.set_threading_Event(victim.event_pktconn)
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
        self.get_timing_cc() 

    def get_information_request(self):
        information_data=[]
        TYPE_INFORMATION_REQUEST=15
        TYPE_INFORMATION_REPLY=16
        ip_host="192.168.56.101"
        gateway_vittima=mymethods.calc_gateway(ip_host) 
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY}) and dst {ip_host}" 
                #,"count":1 
                ,"prn":callback_get_information_request(self,information_data)
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(gateway_vittima)[1]
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
            print("".join(x for x in information_data))
            return True 
        return False  
    
    def get_timestamp_request(self):
        timestamp_data=[]
        TYPE_TIMESTAMP_REQUEST=13
        TYPE_TIMESTAMP_REPLY=14
        ip_host="192.168.56.101"
        gateway_vittima=mymethods.calc_gateway(ip_host) 
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_TIMESTAMP_REQUEST} or icmp[0]=={TYPE_TIMESTAMP_REPLY}) and dst {ip_host}" 
                #,"count":1 
                ,"prn":callback_get_timestamp_request(self,timestamp_data)
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(gateway_vittima)[1]
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
            print("".join(x for x in timestamp_data))
            return True 
        return False  
    
    def get_redirect(self):
        redirect_data=[]
        TYPE_REDIRECT=5
        ip_host="192.168.56.101"
        gateway_vittima=mymethods.calc_gateway(ip_host) 
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_REDIRECT}) and dst {ip_host}" 
                #,"count":1 
                ,"prn":callback_get_redirect_message(self,redirect_data)
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(gateway_vittima)[1]
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
            print("".join(x for x in redirect_data))
            return True 
        return False  
    
    def get_source_quench(self):
        source_quench_data=[]
        TYPE_SOURCE_QUENCH=4  
        ip_host="192.168.56.101"
        gateway_vittima=mymethods.calc_gateway(ip_host) 
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_SOURCE_QUENCH}) and dst {ip_host}" 
                #,"count":1 
                ,"prn":callback_get_source_quench(self,source_quench_data)
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(gateway_vittima)[1]
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
            print("".join(x for x in source_quench_data))
            return True 
        return False  
    
    def get_parameter_problem(self):
        parameter_problem_data=[]
        TYPE_PARAMETER_PROBLEM=12  
        ip_host="192.168.56.101"
        gateway_vittima=mymethods.calc_gateway(ip_host) 
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_PARAMETER_PROBLEM}) and dst {ip_host}" 
                #,"count":1 
                ,"prn":callback_get_parameter_problem(self,parameter_problem_data)
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(gateway_vittima)[1]
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
        ip_host="192.168.56.101"
        gateway_vittima=mymethods.calc_gateway(ip_host) 
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_TIME_EXCEEDED}) and dst {ip_host}" 
                #,"count":1 
                ,"prn":callback_get_time_exceeded(self,time_exceeded_data)
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(gateway_vittima)[1]
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
        ip_host="192.168.56.101"
        gateway_vittima=mymethods.calc_gateway(ip_host) 
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_DESTINATION_UNREACHABLE}) and dst {ip_host}" 
                #,"count":1 
                ,"prn":callback_get_destination_unreachable(self,destination_unreachable_data)
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(gateway_vittima)[1]
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
    
    def get_timing_cc(self):
        timing_cc_data=[]
        TYPE_ECHO_REQUEST=8
        TYPE_ECHO_REPLY=0
        ip_host="192.168.56.101"
        gateway_vittima=mymethods.calc_gateway(ip_host) 
        last_packet_time=None
        args={
                "filter":f"icmp and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY}) and dst {ip_host}" 
                #,"count":1 
                ,"prn":callback_get_timing_cc(self,timing_cc_data,last_packet_time)
                #,"store":True 
                ,"iface":mymethods.iface_from_IPv4(gateway_vittima)[1]
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
            print("".join(x for x in timing_cc_data))
            return True 
        return False

if __name__=="__main__": 
    print("Ciao") 
    victim=Victim()