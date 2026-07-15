from enum import Enum 
import time

class SEPARAZIONE_DATI(Enum): 
    ID="by_id"

class ENTITY(Enum):
    ATTACKER="attacker"
    VICTIM="victim"
    PROXY="proxy"

class MSG(Enum):
    CONFIRM_ATTACKER="__confirm_attacker__"
    CONFIRM_VICTIM="__confirm_victim__"
    CONFIRM_PROXY="__confirm_proxy__"
    CONFIRM_COMMAND="__confirm_command__"
    ATTACK_FUNCTION="__attack_function__"
    LAST_PACKET="__last_packet__"
    WAIT_DATA="__wait_data__"
    END_COMMUNICATION="__end_communication__"
    END_DATA="__end_data__"
    START_SOURCES="__start_sources__"
    END_SOURCES="__end_sources__" 
    END_SOCKETSEND="__end_socketsend__"
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

class EXIT_CASES(Enum): 
    EXIT="exit"
    QUIT="quit" 
    END_COMMUNICATION=MSG.END_COMMUNICATION.value.lower()


def print_enum(enum_class:type[Enum]=None): 
    if not enum_class or not issubclass(enum_class, Enum): 
        raise ValueError(f"Enum non valido: {enum_class}") 
    print("I valori presenti sono:")
    for enumerator in enum_class: 
        #time.sleep(0.5) 
        print(f"\t{enumerator.name}:{enumerator.value}")  
