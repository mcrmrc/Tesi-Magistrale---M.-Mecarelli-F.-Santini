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
import ipaddress
import socket


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
        field=None 
        if (layer:=packet.getlayer("IPv6")) is not None:
            if (layer:=layer.getlayer("ICMPv6DestUnreach")) is None:
                print("not got layer ICMPv6TimeExceeded") 
                return
            if (layer:=layer.getlayer("IPerror6")) is not None:
                #print("got layer IPerror6") 
                if (field:=layer.getfieldval("plen")) is not None and field!=0xffff:
                    #print("ASAAAA: ",field)
                    #print("AAAA field","\t",field.to_bytes(2,"big").decode())
                    data.append(field.to_bytes(2,"big").decode())
                elif field is not None and field==0xffff:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
            layer=(
                layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                else layer.getlayer("ICMPv6EchoReply")
            )
            if layer is not None:
                #print("got layer ICMPv6EchoRequest | ICMPv6EchoReply") 
                if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")==1):
                    #print("ASAAAA: ",field)
                    #print("AAAA field","\t",field.to_bytes(2,"big").decode())
                    data.append(field.to_bytes(2,"big").decode()) 
                elif field is not None and (field==0 and layer.getfieldval("seq")==1):
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
                else: print("Caso non considetrato")  
    return callback

def callback_get_packet_to_big(event_pktconn,data):
    TYPE_PKT_BIG= 2
    def callback(packet):
        print(f"callback get_packet_to_big received:\n\t{packet.summary()}") 
        field=None 
        if (layer:=packet.getlayer("IPv6")) is not None:
            if (layer:=layer.getlayer("ICMPv6PacketTooBig")) is not None:
                #print("got layer ICMPv6TimeExceeded") 
                if (field:=layer.getfieldval("mtu")) is not None: #and field!=0:
                    #print("ASAAAA: ",field)
                    #print("AAAA field","\t",field.to_bytes(4,"big").decode())
                    data.append(field.to_bytes(4,"big").decode())
                #elif field is not None and field==0:
                #    print("END OF TRANSMISSION")
                #    com.set_threading_Event(event_pktconn)
                #    return 
                if layer.getlayer("IPerror6") is None:
                    print("AAAAAAA")
                    #com.set_threading_Event(event_pktconn)
                    #return
            if (layer:=layer.getlayer("IPerror6")) is not None:
                #print("got layer IPerror6") 
                if (field:=layer.getfieldval("plen")) is not None and field!=0xffff:
                    #print("ASAAAA: ",field)
                    #print("AAAA field","\t",field.to_bytes(2,"big").decode())
                    data.append(field.to_bytes(2,"big").decode())
                elif field is not None and field==0xffff:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
            layer=(
                layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                else layer.getlayer("ICMPv6EchoReply")
            )
            if layer is not None:
                #print("got layer ICMPv6EchoRequest | ICMPv6EchoReply") 
                if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")!=0):
                    #print("ASAAAA: ",field)
                    #print("AAAA field","\t",field.to_bytes(2,"big").decode())
                    data.append(field.to_bytes(2,"big").decode()) 
                elif field is not None and (field==0 and layer.getfieldval("seq")==1):
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
                else: print("Caso non considetrato")  
    return callback

def callback_get_time_exceeded(event_pktconn,data):
    TYPE_TIME_EXCEEDED=3  
    def callback(packet):
        print(f"callback get_time_exceeded received:\n\t{packet.summary()}") 
        field=None 
        if (layer:=packet.getlayer("IPv6")) is not None:
            if (layer:=layer.getlayer("ICMPv6TimeExceeded")) is not None:
                #print("got layer ICMPv6TimeExceeded") 
                if layer.getlayer("IPerror6") is None:
                    print("AAAAAAA")
                    #com.set_threading_Event(event_pktconn)
                    #return
            if (layer:=layer.getlayer("IPerror6")) is not None:
                #print("got layer IPerror6") 
                if (field:=layer.getfieldval("plen")) is not None and field!=0xffff:
                    #print("ASAAAA: ",field)
                    #print("AAAA field","\t",field.to_bytes(2,"big").decode())
                    data.append(field.to_bytes(2,"big").decode())
                elif field is not None and field==0xffff:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
            layer=(
                layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                else layer.getlayer("ICMPv6EchoReply")
            )
            if layer is not None:
                #print("got layer ICMPv6EchoRequest | ICMPv6EchoReply") 
                if (field:=layer.getfieldval("id")) is not None and not (field==0 and layer.getfieldval("seq")!=0):
                    #print("ASAAAA: ",field)
                    #print("AAAA field","\t",field.to_bytes(2,"big").decode())
                    data.append(field.to_bytes(2,"big").decode()) 
                elif field is not None and (field==0 and layer.getfieldval("seq")==1):
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return
                else: print("Caso non considetrato") 
    return callback

def callback_get_parameter_problem(event_pktconn,data): 
    TYPE_INFORMATION_REPLY=129
    TYPE_PARAMETER_PROBLEM=4  
    def callback(packet):
        print(f"\tcallback get_parameter_problem received:\n{packet.summary()}") 
        #print(packet.show2())
        #print("piango: ",repr(bytes(packet)))  
        field=None 
        if (layer:=packet.getlayer("IPv6")) is not None:
            #print("got layer IPv6")  
            if (layer:=layer.getlayer("ICMPv6ParamProblem")) is not None:
                #print("got layer ICMPv6ParamProblem") 
                if (field:=layer.getfieldval("ptr")) is not None and field!=0xffffffff: 
                    #print(field,"\t",field.to_bytes(4,"big").decode())
                    data.append(field.to_bytes(4,"big").decode()) 
                elif field is not None and field==0xffffffff:
                    print("END OF TRANSMISSION")
                    com.set_threading_Event(event_pktconn)
                    return 
            if (layer:=layer.getlayer("IPerror6")) is not None:
                #print("got layer IPerror6") 
                if (field:=layer.getfieldval("plen")) is not None:
                    #print(field,"\t",field.to_bytes(4,"big").decode())
                    data.append(field.to_bytes(2,"big").decode())
            layer=(
                layer.getlayer("ICMPv6EchoRequest") if layer.getlayer("ICMPv6EchoReply") is None 
                else layer.getlayer("ICMPv6EchoReply")
            )
            if layer is not None:
                #print("got layer ICMPv6EchoRequest | ICMPv6EchoReply") 
                if (field:=layer.getfieldval("id")) is not None:
                    #print(field,"\t",field.to_bytes(4,"big").decode())
                    data.append(field.to_bytes(2,"big").decode()) 
    return callback

def callback_get_information_request(event_pktconn,data):
    def callback(packet):
        print(f"callback get_information_request received:\n\t{packet.summary()}")  
        if packet.haslayer(IPv6) and (packet.haslayer(ICMPv6EchoReply) or packet.haslayer(ICMPv6EchoRequest)): 
            icmp_echo_type=(
                "ICMPv6EchoReply" if packet.haslayer(ICMPv6EchoReply) 
                else "ICMPv6EchoRequest" if packet.haslayer(ICMPv6EchoRequest) 
                else None
            )
            #print(f"Ricevuto pacchetto da {packet[IPv6].src}...")
            if packet[echo_type].id==0 and packet[echo_type].seq==1:
                print("END OF TRANSMISSION")
                com.set_threading_Event(event_pktconn)
                return
            icmp_id=packet[echo_type].id
            byte1 = (icmp_id >> 8) & 0xFF 
            byte2 = icmp_id & 0xFF 
            #print(icmp_id,type(icmp_id))  
            #print(byte1," : ",byte2,"\t",chr(byte1)," : ",chr(byte2)) 
            data.extend([chr(byte1),chr(byte2)]) 
    return callback

class Victim:
    def __init__(self): 
        #self.get_information_request() 
        #self.get_parameter_problem() 
        #self.get_time_exceeded()  
        #self.get_packet_to_big() 
        #self.get_destination_unreachable() 

        self.get_timing_cc(4) 

    def get_information_request(self): 
        information_data=[]
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129 
        ip_host=ipaddress.IPv6Address("fe80::43cc:4881:32d7:a33e")  
        #ip_google=socket.getaddrinfo("www.google.com", None, socket.AF_UNSPEC)
        #print("IP_GOOGLE: ",ip_google)
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp6 and (icmp6[0]=={TYPE_INFORMATION_REQUEST} or icmp6[0]=={TYPE_INFORMATION_REPLY}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_information_request(self.event_pktconn,information_data)
                #,"store":True 
                ,"iface": interface
            }
        try: 
            sniffer,pkt_timer=com.sniff_packet(
                args
                ,timeout_time=None
                ,event=self.event_pktconn
            ) 
            com.wait_threading_Event(self.event_pktconn) 
        except Exception as e:
            raise Exception(f"get_information_request: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in information_data))
            return True 
        return False  
    
    def get_parameter_problem(self): 
        parameter_problem_data=[]
        TYPE_PARAMETER_PROBLEM=4  
        ip_host=ipaddress.IPv6Address("fe80::43cc:4881:32d7:a33e") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp6 and (icmp6[0]=={TYPE_PARAMETER_PROBLEM}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_parameter_problem(self.event_pktconn,parameter_problem_data)
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
            raise Exception(f"get_parameter_problem: {e}")
        com.stop_sinffer(sniffer)
        if com.stop_timer(pkt_timer): 
            print("".join(x for x in parameter_problem_data))
            return True 
        return False  
    
    def get_time_exceeded(self):
        time_exceeded_data=[]
        TYPE_TIME_EXCEEDED=3  
        ip_host=ipaddress.IPv6Address("fe80::43cc:4881:32d7:a33e") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp6 and (icmp6[0]=={TYPE_TIME_EXCEEDED}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_time_exceeded(self.event_pktconn,time_exceeded_data)
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
            print("".join(x for x in time_exceeded_data))
            return True 
        return False  

    def get_packet_to_big(self):
        timestamp_data=[]
        TYPE_PKT_BIG= 2
        ip_host=ipaddress.IPv6Address("fe80::43cc:4881:32d7:a33e") 
        interface= mymethods.default_iface() 
        args={
                "filter":f"icmp6 and (icmp6[0]=={TYPE_PKT_BIG}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_packet_to_big(self.event_pktconn,timestamp_data)
                #,"store":True 
                ,"iface": interface
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
    
    def get_destination_unreachable(self):
        destination_unreachable_data=[]
        TYPE_DESTINATION_UNREACHABLE=1 
        ip_host=ipaddress.IPv6Address("fe80::43cc:4881:32d7:a33e") 
        try: 
            self.event_pktconn=com.get_threading_Event()
            interface= mymethods.default_iface() 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp6 and (icmp6[0]=={TYPE_DESTINATION_UNREACHABLE}) and dst {ip_host.compressed}" 
                #,"count":1 
                ,"prn":callback_get_destination_unreachable(self.event_pktconn,destination_unreachable_data)
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
            print("".join(x for x in destination_unreachable_data))
            return True 
        return False  
        
    def get_timing_cc(self,numero_bit=0): 
        try: 
            ip_host=ipaddress.IPv6Address("fe80::43cc:4881:32d7:a33e") 
            interface= mymethods.default_iface() 
            if numero_bit<=0:
                raise Exception("Numero di bit passato non valido")
        except Exception as e:
            raise Exception(f"Exception: {e}")
        timing_data=[]
        TYPE_INFORMATION_REQUEST=128
        TYPE_INFORMATION_REPLY=129
        last_packet_time=None
        try: 
            self.event_pktconn=com.get_threading_Event()
            callback_function=lambda: timeout_timing_covertchannel(self.event_pktconn)
            self.timer_timing_CC=com.get_timeout_timer(None,callback_function) 
        except Exception as e:
            raise Exception(f"Exception: {e}")
        args={
                "filter":f"icmp6 and (icmp6[0]=={TYPE_INFORMATION_REQUEST} or icmp6[0]=={TYPE_INFORMATION_REPLY}) and dst {ip_host.compressed}" 
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
            com.stop_sinffer(sniffer)
            if com.stop_timer(pkt_timer): 
                print(data)
                return True 
            return False
        except Exception as e:
            raise Exception(f"wait_conn_from_attacker: {e}")
        

if __name__=="__main__": 
    print("Ciao") 
    victim=Victim()