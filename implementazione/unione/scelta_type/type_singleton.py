import ipaddress

class AttackType:
    attack_dict={ 
        "ipv4_destination_unreachable":"ipv4_3" 
        ,"ipv4_source_quench":"ipv4_4"
        ,"ipv4_redirect":"ipv4_5"  
        ,"ipv4_timing_channel_1bit":"ipv4__16" 
        ,"ipv4_timing_channel_2bit":"ipv4_16" 
        ,"ipv4_timing_channel_4bit":"ipv4_16" 

        ,"ipv4_time_exceeded":"ipv4_11"
        ,"ipv4_parameter_problem":"ipv4_12" 
        ,"ipv4_timestamp_request":"ipv4_13"
        ,"ipv4_timestamp_reply":"ipv4_14"
        ,"ipv4_information_request":"ipv4_15"
        ,"ipv4_information_reply":"ipv4_16"  

        ,"ipv6_destination_unreachable":"ipv6_1" 
        ,"ipv6_packet_to_big":"ipv6_2" 
        ,"ipv6_time_exceeded":"ipv6_3" 
        ,"ipv6_parameter_problem":"ipv6_4" 
        ,"ipv6_timing_channel_1bit":"ipv6_129" 
        ,"ipv6_timing_channel_2bit":"ipv6_129" 
        ,"ipv6_timing_channel_4bit":"ipv6_129"

        ,"ipv6_information_request":"ipv6_128" 
        ,"ipv6_information_reply":"ipv6_129"  
    } 

    def get_attack_function(self, attack_name): 
        try: 
            list_function_attack={}
            for key,val in self.attack_dict.items():
                if str(key)==str(attack_name) or str(val)==str(attack_name):
                    list_function_attack[key]=val 
            #print("self.used_attack: ",list_function_attack) 
            #if len(list_function_attack)>0: 
            #    return list_function_attack
            #self.print_available_attacks() 
            return list_function_attack
        except Exception as e:
            raise Exception(f"Exception: {e}")
    
    def print_available_attacks(self):
        print("Gli attacchi disponibili sono:")
        for attack in self.attack_dict: 
            try:
                if "ipv4" in attack:
                    print(f"\t{attack.replace("ipv4_","")} -> {self.attack_dict[attack].replace("ipv4_","")} (IPv4)")
                elif "ipv6" in attack:
                    print(f"\t{attack.replace("ipv6_","")} -> {self.attack_dict[attack].replace("ipv6_","")} (IPv6)")
                else:
                    print(f"\t{attack} -> {self.attack_dict[attack]} (Unknown)")
            except Exception as e:
                print(f"Err:\t{attack} -> {self.attack_dict[attack]}")
                print(f"Errore nella stampa degli attacchi: {e}")
        print("Per scegliere un attacco, usa il nome o il numero corrispondente." \
            "\nAd esempio per l'attacco 'destination unreachable' in IPv4, puoi scegliere:" \
            "\n\t*il nome 'ipv4_destination_unreachable'" \
            "\n\t*il codice 'ipv4_3'." \
        )
    
    def choose_attack_function(self):  
        dict_to_check=self.attack_dict 
        result_input=True
        while True: 
            print_dictionary(dict_to_check)
            msg="Scegli il nome o il codice della funzione:\t"
            try:
                scelta=str(input(msg)).lower().strip()
            except Exception as e:
                print(f"choose_attack_function: {e}")
            print("Hai digitato: ",scelta if str(scelta)!="" else "<empty>") 
            func_trovate={}
            for key,value in dict_to_check.items(): 
                if scelta in key or scelta in value: 
                    func_trovate[key]=value 
            if len(func_trovate)==1:
                print("Funzione scelta: ", next(iter(func_trovate.items())))
                return next(iter(func_trovate.items()))
            elif len(func_trovate)<1:
                msg="Nessuna funzione trovata. Si vuole continuare? S/N\t" 
                result_input=str(input(msg)).lower().strip()
                dict_to_check=self.attack_dict
            elif len(func_trovate)>1: 
                msg="Mutliple funzioni trovate. Si vuole continuare? S/N\t" 
                result_input=str(input(msg)).lower().strip() 
                dict_to_check=func_trovate 
            else:
                raise Exception(f"Unknown case with len(func_trovate): {len(func_trovate)}")
            if not is_scelta_SI_NO(result_input):
                print("Si è scelto di non continuare")
                return None
        
    def get_filter_attack_from_function(self,function_name:str=None, ip_dst:ipaddress.IPv4Address|ipaddress.IPv6Address=None, checksum:int=None): 
        if function_name is None or not isinstance(function_name,str):
            raise ValueError(f"La funzione passata non è una stringa: {type(function_name)} {function_name}")
        if self.attack_dict.get(function_name) is None:
            raise ValueError(f"La funzione non è presente: {function_name}")
        print("function_name: ", function_name)
        match function_name:
            case "ipv4_destination_unreachable": 
                TYPE_DESTINATION_UNREACHABLE=3 
                return f"icmp and (icmp[0]=={TYPE_DESTINATION_UNREACHABLE})" #and dst {ip_host}" 
            case "ipv4_source_quench": 
                TYPE_SOURCE_QUENCH=4  
                return f"icmp and (icmp[0]=={TYPE_SOURCE_QUENCH})" # and dst {ip_host}" 
            case "ipv4_redirect": 
                TYPE_REDIRECT=5
                return f"icmp and (icmp[0]=={TYPE_REDIRECT})" # and dst {ip_host}" 
            case "ipv4_timing_channel_1bit" | "ipv4_timing_channel_2bit" | "ipv4_timing_channel_4bit":
                TYPE_ECHO_REQUEST=8
                TYPE_ECHO_REPLY=0
                return f"icmp and (icmp[0]=={TYPE_ECHO_REQUEST} or icmp[0]=={TYPE_ECHO_REPLY})" # and dst {ip_host}"  
            case "ipv4_time_exceeded": 
                TYPE_TIME_EXCEEDED=11
                return f"icmp and (icmp[0]=={TYPE_TIME_EXCEEDED})" # and dst {ip_host}"
            case "ipv4_parameter_problem": 
                TYPE_PARAMETER_PROBLEM=12  
                return f"icmp and (icmp[0]=={TYPE_PARAMETER_PROBLEM})" # and dst {ip_host}" 
            case "ipv4_timestamp_request" | "ipv4_timestamp_reply": 
                TYPE_TIMESTAMP_REQUEST=13
                TYPE_TIMESTAMP_REPLY=14
                return f"icmp and (icmp[0]=={TYPE_TIMESTAMP_REQUEST} or icmp[0]=={TYPE_TIMESTAMP_REPLY})" # and dst {ip_host}" 
            case "ipv4_information_request" | "ipv4_information_reply": 
                TYPE_INFORMATION_REQUEST=15
                TYPE_INFORMATION_REPLY=16
                return f"icmp and (icmp[0]=={TYPE_INFORMATION_REQUEST} or icmp[0]=={TYPE_INFORMATION_REPLY})" # and dst {ip_host}"
            #------------------------------------
            case "ipv6_destination_unreachable": 
                TYPE_DESTINATION_UNREACHABLE=1 
                f"icmp6 and (icmp6[0]=={TYPE_DESTINATION_UNREACHABLE})"# and dst {ip_host.compressed}" 
            case "ipv6_packet_to_big": 
                TYPE_PKT_BIG= 2
                f"icmp6 and (icmp6[0]=={TYPE_PKT_BIG})"# and dst {ip_host.compressed}" 
            case "ipv6_time_exceeded": 
                TYPE_TIME_EXCEEDED=3  
                f"icmp6 and (icmp6[0]=={TYPE_TIME_EXCEEDED})"# and dst {ip_host.compressed}" 
            case "ipv6_parameter_problem": 
                TYPE_PARAMETER_PROBLEM=4  
                f"icmp6 and (icmp6[0]=={TYPE_PARAMETER_PROBLEM})"# and dst {ip_host.compressed}" 
            case "ipv6_timing_channel_1bit" | "ipv6_timing_channel_2bit" | "ipv6_timing_channel_4bit": 
                TYPE_ECHO_REQUEST=128
                TYPE_ECHO_REPLY=129
                f"icmp6 and (icmp6[0]=={TYPE_ECHO_REQUEST} or icmp6[0]=={TYPE_ECHO_REPLY})"# and dst {ip_host.compressed}"  
            case "ipv6_information_request" | "ipv6_information_reply": 
                TYPE_ECHO_REQUEST=128
                TYPE_ECHO_REPLY=129 
                return f"icmp6 and (icmp6[0]=={TYPE_ECHO_REQUEST} or icmp6[0]=={TYPE_ECHO_REPLY})" # and dst {ip_host}"   

    def get_filter_connection_from_function(self,function_name:str=None, ip_src:ipaddress.IPv4Address|ipaddress.IPv6Address=None, checksum:int=None, ip_dst:ipaddress.IPv4Address|ipaddress.IPv6Address=None, interface:str=None): 
        IPv4_ECHO_REQUEST_TYPE=8
        IPv4_ECHO_REPLY_TYPE=0
        IPv6_ECHO_REQUEST_TYPE=128
        IPv6_ECHO_REPLY_TYPE=129
        if not isinstance(function_name,str):
            raise ValueError(f"La funzione passata non è una stringa: {type(function_name)} {function_name}")
        match function_name:
            case "wait_conn_from_proxy" | "wait_proxy_update"| "wait_conn_from_victim": 
                if not isinstance(checksum, int):
                    raise ValueError(f"Il checksum passato non è un intero: {type(function_name)} {function_name}")
                if not isinstance(ip_src,ipaddress.IPv4Address) and not isinstance(ip_src,ipaddress.IPv6Address): 
                    raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(function_name)} {function_name}")
                
                if ip_src.version==4:
                    return f"icmp and icmp[0]==8 and src {ip_src.compressed} and icmp[4:2]={checksum}" 
                elif ip_src.version==6:
                    return f"icmp6 and (icmp6[0]=={IPv6_ECHO_REQUEST_TYPE} and src {ip_src.compressed} and icmp[4:2]={checksum}" 
                else: raise Exception(f"Caso non contemplato: {ip_src.version}") 
            case "wait_data_from_proxy" | "wait_conn_from_attacker" | "wait_command_from_attacker": 
                if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                    raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}")
                if not isinstance(ip_src,ipaddress.IPv4Address) and not isinstance(ip_src,ipaddress.IPv6Address): 
                    raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(function_name)} {function_name}")
                
                if ip_src.version==4:
                    return f"icmp and icmp[0]==8 and src {ip_src.compressed} and dst {ip_dst.compressed}" 
                elif ip_src.version==6:
                    return f"icmp6 and icmp6[0]==128 and src {ip_src.compressed} and dst {ip_dst.compressed}" 
                else: raise Exception(f"Caso non contemplato: {ip_src.version}")  
            case "wait_data_from_vicitm":
                if not isinstance(ip_src,ipaddress.IPv4Address) and not isinstance(ip_src,ipaddress.IPv6Address): 
                    raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(function_name)} {function_name}")
                if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                    raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}")

                if ip_src.version==4:
                    return f"icmp and src {ip_src.compressed} and dst {ip_dst.compressed}" 
                elif ip_src.version==6:
                    return f"icmp6 and src {ip_src.compressed} and dst {ip_dst.compressed}" 
                else: raise Exception(f"Caso non contemplato: {ip_src.version}") 
            case "wait_conn_from_proxy":
                if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                    raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}") 
                if not isinstance(checksum, int):
                    raise ValueError(f"Il checksum passato non è un intero: {type(function_name)} {function_name}")
                
                if ip_src.version==4:
                    return f"icmp and icmp[0]==8 and dst {ip_dst.compressed} and icmp[4:2]=={checksum}" 
                elif ip_src.version==6:
                    return f"icmp6 and icmp6[0]==128 and dst {ip_dst.compressed} and icmp[4:2]=={checksum}" 
                else: raise Exception(f"Caso non contemplato: {ip_src.version}") 
            case "wait_attacker_command":
                if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                    raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}")
                
                if ip_dst.version==4:
                    return f"icmp and icmp[0]==8 and dst {ip_dst.compressed}" 
                elif ip_dst.version==6:
                    return f"icmp6 and icmp6[0]==128 and dst {ip_dst.compressed}" 
                else: raise Exception(f"Caso non contemplato: {ip_src.version}") 
            case "victim_wait_conn_from_proxy":
                if not isinstance(ip_dst,ipaddress.IPv4Address) and not isinstance(ip_dst,ipaddress.IPv6Address): 
                    raise ValueError(f"Il proxy passato non è ne un IPv4Address ne un IPv6Address: {type(ip_dst)} {ip_dst}")
                if not isinstance(checksum, int):
                    raise ValueError(f"Il checksum passato non è un intero: {type(function_name)} {function_name}")
                
                if ip_dst.version==4:
                    return f"icmp and icmp[0]==8 and dst {ip_dst.compressed} and icmp[4:2]=={checksum}"
                elif ip_dst.version==6:
                    return aaa
                else: raise Exception(f"Caso non contemplato: {ip_src.version}") 
            case "":
                if ip_src.version==4:
                    return aaa
                elif ip_src.version==6:
                    return aaa
                else: raise Exception(f"Caso non contemplato: {ip_src.version}") 
        
    

def is_scelta_SI_NO(scelta:str=None):
    if not isinstance(scelta,str) or scelta is None:
         return False
    is_scelta_yes=False 
    whitebox=["yes","si","yeah"]
    for x in whitebox:
        if scelta!="" and (is_scelta_yes or x.startswith(scelta) or x in scelta):
            is_scelta_yes=True
            break 
    return is_scelta_yes

def print_dictionary(dictionary:dict=None):
    if dictionary is None or not isinstance(dictionary,dict):
        raise Exception("Dizionario passato non valido") 
    elif len(dictionary)<=0:
        print("Il dizionario è vuoto")
        return
    print("Valori presenti:")
    for key, value in dictionary.items():
        print(f"\t{key}\t{value}")