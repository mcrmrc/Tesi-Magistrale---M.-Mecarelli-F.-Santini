from scapy.all import * 
from attacksingleton  import * 
import ipaddress   

 

def ipv4_timing_channel_8bit(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
    print("ipv4_timing_channel_8bit")
    if not istype.bytes(data) or not istype.ipaddress(ip_dst):
        raise Exception(f"Argoemnti non corretti")
    if ip_dst.version!=4:
        print(f"IP version is not 4: {ip_dst.version}")
        return False
    target_mac = ipinterface.get_macAddress(ip_dst).strip().replace("-",":").lower()
    interface=ipinterface.iface_from_IP(ip_dst) 
    print(f"Interfaccia per destinazione: {interface}")
    
    TYPE_ECHO_REQUEST=8
    TYPE_ECHO_REPLY=0
    min_sec_delay=1 #originale 0
    max_sec_delay=25 #originale 255

    midnight = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start_time=datetime.datetime.now(datetime.timezone.utc) 

    pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
    pkt.summary()
    #pkt.show()
    sendp(pkt, verbose=1, iface=interface) 
    for index in data:
        current_time=datetime.datetime.now()
        #print(f"Current time: {current_time}")

        delay=min_sec_delay+(index/255)*(max_sec_delay-min_sec_delay)
        print(f"Delay :{index}\t{delay}\n")
        #print(f"Data: {index}\t{index-31}\t{type(index)}\n") 
        time.sleep(delay)
        pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY)/Raw()
        pkt.summary()
        #pkt.show()
        sendp(pkt, verbose=1, iface=interface)

        old_time=current_time
        #current_time=datetime.datetime.now()
        print(f"Current time: {current_time}")
        print(f"Time difference: {current_time-old_time}\t{(current_time-old_time).total_seconds()}\n")  
    end_time=datetime.datetime.now(datetime.timezone.utc) 
    print("Tempo di esecuzione: ", end_time-start_time, (end_time-start_time).total_seconds())

#-------------------------------------------------------
data="Dato mandato da computer di Marco".encode()
ip_dst=ipaddress.ip_address("192.168.1.17") 
ipv4_timing_channel_8bit(data, ip_dst)