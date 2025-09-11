import datetime, ipaddress

data="echo 'Ciao'".encode() 

def test_1():
    for index in range(0, len(data), 5): 
        try:
            icmp_id=(data[index]<<8)+data[index+1]  
            print(f"ICMP id: {icmp_id}")
        except IndexError as e: 
            #print(f"Index error: {e}")
            icmp_id=(data[index]<<8)
            print(f"ICMP id: {icmp_id}")
            exit()
        except Exception as e:
            exit()
        current_time=datetime.datetime.now(datetime.timezone.utc) 
        midnight = current_time.replace(hour=0, minute=0, second=0, microsecond=0) 

        data_pkt=int.from_bytes(data[index+2:index+3]) *10**3
        current_time=current_time.replace(microsecond=data_pkt)
        icmp_ts_ori=int((current_time - midnight).total_seconds() * 1000) 
        print(f"Byte data: {data[index+2:index+3]}")
        print(f"Data pkt: {data_pkt}")
        print(f"Timestamp: {icmp_ts_ori}") 
    
        data_pkt=int.from_bytes(data[index+3:index+4]) *10**3 
        if current_time.second+1<60:
            current_time=current_time.replace(
                second=current_time.second+1, microsecond=data_pkt
            ) 
        else:
            current_time=current_time.replace(
                minute=current_time.minute+1,second=(current_time.second+1)%60, microsecond=data_pkt
            ) 
        icmp_ts_rx=int((current_time - midnight).total_seconds() * 1000) 
        print(f"Byte data: {data[index+3:index+4]}")
        print(f"Data pkt: {data_pkt}")
        print(f"Timestamp: {icmp_ts_rx}")

        data_pkt=int.from_bytes(data[index+4:index+5]) *10**3 
        if current_time.second+1<60: 
            current_time=current_time.replace(
                second=current_time.second+1, microsecond=data_pkt
            )
        else: 
            current_time=current_time.replace(
                minute=current_time.minute+1,second=(current_time.second+1)%60, microsecond=data_pkt
            )
        icmp_ts_tx=int((current_time - midnight).total_seconds() * 1000) 
        print(f"Byte data: {data[index+4:index+5]}")
        print(f"Data pkt: {data_pkt}")
        print(f"Timestamp: {icmp_ts_tx}")

def test_2():
    for index in range(0, len(data), 12): 
        print(f"Byte data: {int.from_bytes(data[index:index+4])}")
        print(f"Byte data: {int.from_bytes(data[index+5:index+8])}") 
        print(f"Byte data: {int.from_bytes(data[index+8:index+12])}") 

from mymethods import IP_INTERFACE as ipinterface 
from mymethods import IS_TYPE as istype, ping_once, IP_INTERFACE as ipinterface, THREADING_EVENT as threadevent 
from mymethods import TIMER as mytimer, GET as get, SNIFFER as mysniffer, is_scelta_SI_NO, print_dictionary 
from scapy.all import *
ip_address, errore=ipinterface.find_local_IP() 

def func3():
    packet_list=[]
    data="echo 'Ciao'".encode()
    ip_dst=ipaddress.ip_address("192.168.1.17")
    def ipv4_destination_unreachable(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
            if not istype.bytes(data) or not istype.ipaddress(ip_dst):
                raise Exception(f"Argoemnti non corretti")
            if ip_dst.version!=4:
                print(f"IP version is not 4: {ip_dst.version}")
                return False
            interface,_=ipinterface.iface_from_IP(ip_dst) 
            TYPE_DESTINATION_UNREACHABLE=3 
            ip_dst=ipaddress.ip_address("192.168.1.17")
            for index in range(0, len(data), 8):
                dummy_ip=IP(src=ip_dst.compressed, dst="8.8.8.8", len=int.from_bytes(data[index+4:index+6])) / \
                    ICMP(id=int.from_bytes(data[index+6:index+8]))
                pkt= IP(dst=ip_dst.compressed)/\
                    ICMP(type=TYPE_DESTINATION_UNREACHABLE, unused=int.from_bytes(data[index:index+4]) )/\
                    Raw(load=bytes(dummy_ip)[:28])
                #print(f"Sending {pkt.summary()}") 
                print(f"Data: {data[index:index+4]}\t{int.from_bytes(data[index:index+4])}")
                print(f"Data: {data[index+4:index+6]}\t{int.from_bytes(data[index+4:index+6])}") 
                print(f"Data: {data[index+6:index+8]}\t{int.from_bytes(data[index+6:index+8])}")
                print(pkt.summary())
                packet_list.append(pkt)
                #if pkt:
                #    ans = send(pkt, verbose=1, iface=interface) 
            dummy_ip=IP(src=ip_dst.compressed, dst="8.8.8.8") / ICMP(id=0,seq=1)
            pkt= IP(dst=ip_dst.compressed)/ICMP(type=TYPE_DESTINATION_UNREACHABLE)/Raw(load=bytes(dummy_ip)[:28])
            #print(f"Sending {pkt.summary()}")  
            print(f"interface: {interface}")
            packet_list.append(pkt)
            #ans = send(pkt, verbose=1, iface=interface) 
            #if ans: 
            #    return True  
            #return False 

    ipv4_destination_unreachable(data, ip_dst)
    print(packet_list)
    print(len(packet_list)) 

    decoded_data=[]
    TYPE_DESTINATION_UNREACHABLE=3 
    for pkt in packet_list:
        if pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw): 
            inner_ip = IP(pkt[Raw].load)
            if inner_ip[ICMP].id==0 and inner_ip[ICMP].seq==1: 
                break 
            elif not inner_ip: 
                print("Pacchetto non ha livello IP error\t",pkt)
                break
            unused_int = pkt[ICMP].unused
            if isinstance(unused_int, bytes): 
                decoded_data.append(unused_int.decode().lstrip('\x00').rstrip('\x00')) 
            elif isinstance(unused_int, int): 
                decoded_data.append(unused_int.to_bytes(4, "big").decode().lstrip('\x00').rstrip('\x00')) 
            decoded_data.append(inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
            decoded_data.append(inner_ip[ICMP].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')) 
            
            #if pkt[ICMP][ICMPerror].id==0 and pkt[ICMP][ICMPerror].seq==1: 
                #print("AAAA")
                #print(decoded_data)
            #elif pkt[ICMP].type==TYPE_DESTINATION_UNREACHABLE and not inner_ip.haslayer(IP): #packet.haslayer(Padding):
                #threadevent.set(event_pktconn)
                #exit(0)
                #print("Pacchetto non ha livello IP error\t",pkt)
    print(decoded_data)

target_ip="192.168.1.17"
port=None
data="Dato mandato da computer di Marco"
ttl=64
icmp_id=12345 

def calculate_checksum(data):
    checksum = 0 
    # Handle odd-length data
    if len(data) % 2 != 0:
        data += b"\x00" 
    # Calculate checksum
    for i in range(0, len(data), 2):
        checksum += (data[i] << 8) + data[i+1] 
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16 
    return (~checksum) & 0xffff

def send_icmp_packet():
    icmp_type = 8  # ICMP echo request
    icmp_code = 0
    icmp_checksum = 0
    icmp_sequence = 1
    if data:
        icmp_payload = data.encode()
    else:
        icmp_payload = b"Hello, World!"
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence)
    icmp_checksum = calculate_checksum(icmp_header + icmp_payload)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, socket.htons(icmp_checksum), icmp_id, icmp_sequence)
    icmp_packet = icmp_header + icmp_payload 
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", ttl)) 
        sock.settimeout(2)
        if port:
            sock.sendto(icmp_packet, (target_ip, port))
        else:
            sock.sendto(icmp_packet, (target_ip, 0))
        print("ICMP packet sent successfully!")
#IPPROTO_ICMP 1
#IPPROTO_ICMPV6 58
#IPPROTO_IPV4 4
#IPPROTO_IPV6 41
#IPPROTO_TCP 6
#IPPROTO_UDP 17

from mymethods import IP_INTERFACE
from scapy.all import *
import attacksingleton

#attack_function={"ipv4_1":"ipv4_destination_unreachable"}
#data="cd /home/marco; ls".encode()


#IP_INTERFACE.get_macAddress(ip_dst)
#IP_INTERFACE.get_macAddress(ipaddress.ip_address("192.168.1.3")) 




def ipv4_destination_unreachable(data:bytes=None, ip_dst:ipaddress.IPv4Address=None):  
        if not (istype.bytes(data) and istype.ipaddress(ip_dst)):
            raise Exception(f"Argomenti non corretti")
        if ip_dst.version!=4:
            print(f"IP version is not 4: {ip_dst.version}")
            return False
        interface,_=ipinterface.iface_from_IP(ip_dst) 
        print(f"Interfaccia per destinazione: {interface}")
        TYPE_DESTINATION_UNREACHABLE=3 
        for index in range(0, len(data), 8):
            dummy_ip=IP(src=ip_dst.compressed, dst="8.8.8.8", len=int.from_bytes(data[index+4:index+6])) / \
                ICMP(id=int.from_bytes(data[index+6:index+8]))
            pkt= Ether(dst=ipinterface.get_macAddress(ip_dst).replace("-",":").lower())/\
                IP(dst=ip_dst.compressed)/\
                ICMP(type=TYPE_DESTINATION_UNREACHABLE, code=3, unused=int.from_bytes(data[index:index+4]) )/\
                Raw(load=bytes(dummy_ip)[:28]) 
            print(f"Data: {data[index:index+4]}\t{int.from_bytes(data[index:index+4])}")
            print(f"Data: {data[index+4:index+6]}\t{int.from_bytes(data[index+4:index+6])}") 
            print(f"Data: {data[index+6:index+8]}\t{int.from_bytes(data[index+6:index+8])}") 
            #print(f"Sending {pkt.summary()}") 
            pkt.show()
            sendp(pkt, verbose=1, iface=interface)  if pkt else print("Pacchetto non presente")
        dummy_ip=IP(src=ip_dst.compressed, dst="8.8.8.8") / ICMP(id=0,seq=1)
        pkt= Ether(dst=ipinterface.get_macAddress(ip_dst).replace("-",":").lower())/\
            IP(dst=ip_dst.compressed)/\
            ICMP(type=TYPE_DESTINATION_UNREACHABLE, code=3)/\
            Raw(load=bytes(dummy_ip)[:28])
        #pkt.show()
        print(f"interface: {interface}")
        sendp(pkt, verbose=1, iface=interface) 

data="Dato mandato da computer di Marco".encode()
ip_dst=ipaddress.ip_address("192.168.1.17")
#ipv4_destination_unreachable(data, ip_dst) 

#from attacksingleton import SendSingleton
attacksingleton.SendSingleton.ipv4_destination_unreachable(data=data, ip_dst=ip_dst) 
exit()

from scapy.all import get_if_hwaddr 

#------------------------------
target_mac = "24:77:03:18:7b:74"    # quello visto in Wireshark
dst="192.168.1.17"
iface = "Ethernet"  # nome esatto dell’interfaccia in Scapy

ip_dst=ipaddress.ip_address("192.168.1.17")
target_mac = ipinterface.get_macAddress(ip_dst).strip().replace("-",":").lower()
print("MAC destinazione: ", target_mac)
interface=IP_INTERFACE.iface_from_IP(ip_dst) 
print("Interfaccia:", interface)
pkt = Ether(dst=target_mac)/IP(dst=ip_dst.compressed)/ICMP()/Raw(b"test 3456")
ans=srp1(pkt, iface=interface, verbose=1)
if ans:
    print("Risposta ricevuta:")
    ans.show()