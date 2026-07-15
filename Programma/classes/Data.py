

from enum import Enum
import ipaddress
import socket
import threading

from Programma.custom_enum import SEPARAZIONE_DATI
from Programma.methods.check_type import is_enum_member, is_integer, is_ipaddress
from Programma.methods.get_methods import get_threading_Event, get_threading_Lock


class DATA: 
    class PROXY: 
        def __init__(self, proxy:ipaddress._IPAddressBase, proxy_port:int=None): 
            if not is_ipaddress(proxy): 
                raise TypeError("proxy non valido") 
            if not is_integer(proxy_port) or not 1023<proxy_port<65536: 
                raise ValueError("proxy_port non valido")
            self.ipaddress:ipaddress.IPv4Address=proxy 
            self.port=proxy_port
            self.socket:socket.socket=None 
            self.event:threading.Event=get_threading_Event() 
            self.data_received:list[str]=[] 
            self.data_lock=get_threading_Lock() 
    
    class METHODS: 
        def invia_dati(type_separazione:Enum): 
            def by_id(): 
                print("Invio dati seprandoli by ID") 
            #-------------------
            if not is_enum_member(type_separazione, SEPARAZIONE_DATI): 
                raise TypeError("Tipologia separazione dati non vlaida")
            if type_separazione.value==SEPARAZIONE_DATI.ID.value: 
                by_id() 

        def separa_dati(type_separazione:Enum, data_received:dict[str,list]): 
            def by_id(): 
                print("Invio dati seprandoli by ID") 
                dati_separati:dict[str,list]=[]
                unindent_data=[]
                ## dati_separati={id:lista}
                for list_data in data_received.values(): 
                    if isinstance(list_data, bytes):
                            list_data=list_data.decode()
                    else: print(type(data))
                    for data in list_data.split("||"): 
                        unindent_data.append([x for x in data])
                #print("unindent_data: ",unindent_data)    
                for list_data in unindent_data:
                    #print("list_data: ",list_data)
                    #print(f"\t***{list_data}")
                    if isinstance(list_data, bytes):
                            list_data=list_data.decode()
                    else: print(type(data))
                    list_data=list_data.split("&&")
                    if len(list_data)!=2:
                        print(f"Errore. Length is {len(list_data)}\t{list_data}")
                        continue
                    if dati_separati.get(list_data[0]) is None:
                        dati_separati.update({list_data[0]:[]}) 
                    dati_separati.get(list_data[0]).append(list_data[1]) 
                return dati_separati 
            def old_by_id(dati_separati:dict[str,list]): 
                unindent_data=[]
                ## dati_separati={id:lista}
                for list_data in data_received.values():
                    for data in list_data:
                        if isinstance(data, bytes):
                            data=data.decode()
                        if isinstance(data, str):
                            data=data.split("||")
                        else: print(type(data))
                        #print("Separa: ",data) 
                        unindent_data.append([x for x in data])
                #print("unindent_data: ",unindent_data)    
                for list_data in unindent_data:
                    #print("list_data: ",list_data)
                    #print(f"\t***{list_data}")
                    for index in range(len(list_data)):
                        #print(f"AAAA: {index}/{len(list_data)}")
                        if not list_data[index]: 
                            continue
                        #print(f"\t***{list_data[index]}") 
                        if isinstance(list_data[index],bytes):
                            data=list_data[index].decode()
                        if isinstance(list_data[index],str): 
                            data=list_data[index].split("\t")
                        #print("***DATA: ",data) 
                        if dati_separati.get(data[1]) is None:
                            dati_separati.update({data[1]:[]}) 
                        dati_separati.get(data[1]).append(data)
            #-------------------
            if not is_enum_member(type_separazione, SEPARAZIONE_DATI): 
                raise TypeError("Tipologia separazione dati non vlaida")
            if type_separazione.value==SEPARAZIONE_DATI.ID.value: 
                by_id() 
            
        def unisci_dati(dati_separati:dict[str:list]):
            payload=[] 
            for index in range(len(dati_separati)): 
                #print("DATI: ",dati_separati.get(str(index))) 
                for data in dati_separati.get(str(index)):
                    if data[2]==MSG.LAST_PACKET.value:
                        continue
                    payload.append(data[2])
            return payload
