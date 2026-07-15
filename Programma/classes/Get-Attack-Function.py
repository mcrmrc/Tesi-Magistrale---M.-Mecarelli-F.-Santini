import time
from enum import Enum
from Programma.custom_enum import ATTACK_TYPE
from Programma.methods.check_type import is_enum_member, is_integer, is_string
from Programma.methods.utils_methods import ask_bool_choice


class GET_ATTACK_FUNCTION: 
    def choose_attack_function(): 
        attack_enum=None
        while True: 
            print(ATTACK_TYPE.print_available_attack(),"\n")
            msg="Scegli il nome o il codice della funzione:\t" 
            scelta=str(input(msg)).lower().strip() 
            print("Hai scelto: ",scelta if str(scelta)!="" else "<empty>") 
            attack_enum=ATTACK_TYPE.get_attack_method(scelta) 
            if is_enum_member(attack_enum,ATTACK_TYPE): 
                break
            msg="\n\nNessuna funzione trovata. Si vuole continuare? S/N\t" 
            if not ask_bool_choice(msg): 
                break
        return attack_enum 

    def get_attack_method(attack=None)->Enum: 
        #Data in input una qualsiasi variabile ritorna l'enum associato quando possibile
        if is_enum_member(attack, ATTACK_TYPE): 
            return attack  
        elif is_enum_member(attack,Enum): 
            try: 
                return ATTACK_TYPE[attack.name] 
            except KeyError as k: 
                print("STRINGA NON VALIDA",k)
            try: 
                return ATTACK_TYPE(attack.value)
            except ValueError as v: 
                print("INTEGER NON VALIDO",v) 
        elif is_integer(attack): 
            try:
                return ATTACK_TYPE(attack)
            except ValueError as v:
                print("INTEGER NON VALIDO",v)
        elif is_string(attack): 
            try:
                return ATTACK_TYPE(int(attack))
            except ValueError as k: 
                print("STRINGA NON VALIDA",k)
            try:
                return ATTACK_TYPE[attack]
            except KeyError as k: 
                print("STRINGA NON VALIDA",k)
        
        return None
    
    def get_description(attack:Enum=None)->str: 
        if is_enum_member(attack, ATTACK_TYPE): 
            match attack: 
                case ATTACK_TYPE.ipv4_destination_unreachable: 
                    return "Usa i campi di ICMP Destination Unreachable"
                case ATTACK_TYPE.ipv4_destination_unreachable_unused: 
                    return "Usa icampi di ICMP Destination Unreachable. In particolare 'unused'"
                case ATTACK_TYPE.ipv4_time_exceeded: 
                    return "Usa i campi di ICMP Time Exceeded"
                case ATTACK_TYPE.ipv4_time_exceeded_unused: 
                    return "Usa i campi di ICMP Time Exceeded. In particolare 'unused'"
                case ATTACK_TYPE.ipv4_parameter_problem: 
                    return "Usa i campi di ICMP Parameter Problem"
                case ATTACK_TYPE.ipv4_parameter_problem_unused: 
                    return "Usa i campi di ICMP Parameter Problem. In particolare 'unused'"
                case ATTACK_TYPE.ipv4_source_quench: 
                    return "Usa i campi di ICMP Source Quench"
                case ATTACK_TYPE.ipv4_source_quench_unused: 
                    return "Usa i campi di ICMP Source Quench. In particolare 'unused'"
                case ATTACK_TYPE.ipv4_redirect: 
                    return "Usa i campi di ICMP Redirect"
                case ATTACK_TYPE.ipv4_echo_campi: 
                    return "Usa i campi di ICMP Echo. In particolare 'identifier'"
                case ATTACK_TYPE.ipv4_echo_payload: 
                    return "Usa i campi di ICMP Echo. In particolare 'payload'"
                case ATTACK_TYPE.ipv4_echo_random_payload: 
                    return "Usa i campi di ICMP Echo. In particolare 'payload' con dimensione variabile"
                case ATTACK_TYPE.ipv4_echo_campi_payload: 
                    return "Usa i campi di ICMP Echo. In particolare 'idnetifier' e 'payload'"
                case ATTACK_TYPE.ipv4_timestamp: 
                    return "Usa i campi di ICMP Timestamp"
                case ATTACK_TYPE.ipv4_information: 
                    return "Usa i campi di ICMP Information"
                case ATTACK_TYPE.ipv4_timing_channel_8bit: 
                    return "Usa i campi di ICMP per inviare dati tramite il tempo"
                case ATTACK_TYPE.ipv4_timing_channel_8bit_noise: 
                    return "Usa i campi di ICMP per inviare dati tramite il tempo aggiungendo del rumore di sottofondo"
                #------------------------------------------------
                case ATTACK_TYPE.ipv6_echo: 
                    return "Usa i campi di ICMP v6 Echo"
                case ATTACK_TYPE.ipv6_parameter_problem: 
                    return "Usa i campi di ICMP v6 Parameter Problem"
                case ATTACK_TYPE.ipv6_time_exceeded: 
                    return "Usa i campi di ICMP v6 Time Exceeded"
                case ATTACK_TYPE.ipv6_packet_to_big: 
                    return "Usa i campi di ICMP v6 Packet to Big"
                case ATTACK_TYPE.ipv6_destination_unreachable: 
                    return "Usa i campi di ICMP v6 Destination Unreachable"
                case ATTACK_TYPE.ipv6_timing_cc: 
                    return "Usa i campi di ICMP v6 per inviare dati tramite il tempo"
                #------------------------------------------------
        raise Exception("Attacco immesso non valido: ",attack) 
    
    def print_available_attack(): 
        time.sleep(0.5)
        print("Gli attacchi disponibili sono:\n")
        for enumerator in list(ATTACK_TYPE): 
            time.sleep(2) 
            print(f" *{enumerator.name}:{enumerator.value}\n\t{ATTACK_TYPE.get_description(enumerator)}\n") 
        time.sleep(0.5) 
        print("\n Per scegliere un attacco, usa il nome o il numero corrispondente.") 
        time.sleep(1) 
        print(""" 
            \nAd esempio per l'attacco ICMPv4 Destination Unreachable, puoi scegliere: 
            \n\t*Il nome 'ipv4_destination_unreachable' 
            \n\t\toppure'.
            \n\t*Il numero '0'.
        """) 
