from scapy import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.utils import hexdump, rdpcap 

packets = rdpcap('tesi_magistrale_00001_20260111234052.pcap') 
def print_packet(index, file_name): 
    pkt = Ether(bytes(packets[index]))
    #pkt.payload = IP(pkt.payload.load)
    with open(file_name+".txt", "w") as f: 
        f.write("Detailed packet information:\n")
        f.write(pkt.show2(dump=True))
        f.write("\nHexdump of the packet:\n")
        f.write(hexdump(pkt, dump=True)) 
    pkt.pdfdump(file_name+".pdf", layer_shift=1) 
print("Destination unused") 
print_packet(4563-1, "packet_destination_unused")
exit()
print("Destination unreachable") 
print_packet(496-1, "packet_destination_unreachable")
print("Time exceeded")
print_packet(968-1, "packet_time_exceeded")
print("Parameter problem")
print_packet(1109-1, "packet_parameter_problem")
print("Source quench")
print_packet(1466-1, "packet_source_quench")
print("Redirect")
print_packet(1600-1, "packet_redirect")
print("Echo solo identifier") 
for index in [1901, 1902, 1903, 1904]: 
    print_packet(index-1, f"packet_echo_solo_identifier_{index-1900}")
print("Timestamp") 
for index in [2708, 2709]: 
    print_packet(index-1, f"packet_timestamp_{index-2707}")
print("Echo solo payload") 
print_packet(3240-1, "packet_echo_solo_payload")
print("information") 
for index in [3326, 3327, 3328, 3329]: 
    print_packet(index-1, f"packet_information_{index-3325}")
print("Destination unused") 
print_packet(4563-1, "packet_destination_unused")
print("Timeexceede unused") 
print_packet(4737-1, "packet_timeexceeded_unused")
print("Parameter problem unused")
print_packet(4872-1, "packet_parameterproblem_unused")
print("Source quench unused")
print_packet(4976-1, "packet_sourcequench_unused")



