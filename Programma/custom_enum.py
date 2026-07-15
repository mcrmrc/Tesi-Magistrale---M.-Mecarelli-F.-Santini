from enum import Enum 
from check_type import * 
from mymethods import ask_bool_choice
import time 

class SEPARAZIONE_DATI(Enum): 
    ID="by_id"

class ENTITY(Enum):
    ATTACKER="attacker"
    VICTIM="victim"
    PROXY="proxy"

class MSG(Enum):
    CONFIRM_ATTACKER="__CONFIRM_ATTACKER__"
    CONFIRM_VICTIM="__CONFIRM_VICTIM__"
    CONFIRM_PROXY="__CONFIRM_PROXY__"
    CONFIRM_COMMAND="__CONFIRM_COMMAND__"
    ATTACK_FUNCTION="__ATTACK_FUNCTION__"
    LAST_PACKET="__LAST_PACKET__"
    WAIT_DATA="__WAIT_DATA__"
    END_COMMUNICATION="__END_COMMUNICATION__"
    END_DATA="__END_DATA__"
    START_SOURCES="__START_SOURCES__"
    END_SOURCES="__END_SOURCES__" 
    END_SOCKETSEND="__END_SEND__"
    SEPARATORE_INDEX_DATA="&&"
    SEPARATORE_BATCH="&&"

class MSG_CONFIG(Enum): 
    attack_method="attack_function" 
    proxy_list="proxy_list" 

class ICMP_TYPE(Enum): 
    v4_DestinationUnreachable=3
    v4_TimeExceeded=11 
    v4_ParameterProblem=12 
    v4_SourceQuench=4 
    v4_Redirect=5 
    v4_Echo_Request=8
    v4_Echo_Reply=0 
    v4_Timestamp_Request=13
    v4_Timestamp_Reply=14
    v4_Information_Request=15
    v4_Information_Reply=16 
    #
    v6_DestinationUnreachable=1
    v6_PacketTooBig=2
    v6_TimeExceeded=3
    v6_ParameterProblem=4
    v6_Echo_Request=128
    v6_Echo_Reply=129  

class SENDER_TYPE(Enum): 
        TRUE_SENDER=1
        FAKE_SENDER_ACTIVE=2 
        FAKE_SENDER_INACTIVE=3
        FAKE_SENDER_BOTH=4 

class ATTACK_TYPE(Enum): 
    ipv4_destination_unreachable=0
    ipv4_destination_unreachable_unused=1
    ipv4_time_exceeded=2
    ipv4_time_exceeded_unused=3
    ipv4_parameter_problem=4
    ipv4_parameter_problem_unused=5
    ipv4_source_quench=6
    ipv4_source_quench_unused=7
    ipv4_redirect=8
    ipv4_echo_campi=9
    ipv4_echo_payload=10
    ipv4_echo_campi_payload=11
    ipv4_timestamp=12
    ipv4_information=13
    ipv4_timing_channel_8bit=14
    ipv4_timing_channel_8bit_noise=15 
    ipv4_echo_random_payload=16  

    ipv6_echo=20
    ipv6_parameter_problem=21
    ipv6_time_exceeded=22
    ipv6_packet_to_big=23
    ipv6_destination_unreachable=24 
    ipv6_timing_cc=25  

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
