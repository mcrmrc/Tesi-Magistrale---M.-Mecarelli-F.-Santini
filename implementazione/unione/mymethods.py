from scapy.all import get_if_list, get_if_addr 
from scapy.all import conf
import argparse

def supported_arguments(parser=None):
    if parser is None:
        raise Exception("Parser nullo")
    print("Controlla di inserire due volte - per gli argomenti")
    print("Argomenti supportati:") 
    for action in parser._actions:
        print("\t{arg}: {help}".format(
            arg=action.option_strings[0],
            help=action.help
        )) 

def check_args(parser=None): 
    if parser is None:
        raise Exception("Parser nullo")
    try:
        args, unknown = parser.parse_known_args()
        #args= parser.parse_args()
        print("Argomenti passati: {}".format(args))
        if len(unknown) > 0:
            print("Argomenti sconosciuti: {}".format(unknown))
            supported_arguments(parser)
            exit(1) 
        return args
    except Exception as e:
        print("Errore: {}".format(e)) 
        exit(1) 

def test_check_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host_ip',type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
    parser.add_argument('--host_iface',type=str, help="Intefaccia di rete dove l'host riceverà i pacchetti ICMP")
    #parser.add_argument('--provaFlag',type=int, help="Comando da eseguire")
    check_args(parser)

def calc_checksum(data: bytes) -> int:
    """
    Calculate the Internet checksum for the given data.
    
    :param data: The data to calculate the checksum for (as bytes).
    :return: The checksum as an integer.
    """
    checksum = 0
    # Process the data in 16-bit chunks
    for i in range(0, len(data), 2):
        # Combine two bytes into one 16-bit word
        word = data[i] << 8
        if i + 1 < len(data):
            word += data[i + 1]
        checksum += word
        # Handle overflow by adding the carry
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    # One's complement of the result
    checksum = ~checksum & 0xFFFF
    return checksum

def test_calc_checksum():
    # Example data (as bytes)
    example_data = b"__CONNECT__ "
    example_data = b"Hello, checksum!"
    result = calc_checksum(example_data)
    print(f"Checksum: {result:#06x}")  # Print checksum in hexadecimal format

def iface_for_IP(target_ip=None):
    if target_ip is None:
        raise Exception("Indirizzo IP uguale a None")
    iface_name = conf.route.route(target_ip)[0]
    iface_ip = conf.route.route(target_ip)[1] 
    return iface_ip,iface_name

def interfaccia_byIP(target_ip=None):
    if target_ip is None:
        raise Exception("Indirizzo IP uguale a None")
    for iface in get_if_list():
        try:
            if get_if_addr(iface) == target_ip:
                #print(f"L'interfaccia per {target_ip} è: {iface}")
                return iface
        except Exception as e:
            # Alcune interfacce (es. virtuali) potrebbero non avere un IP assegnato
            print(f"Eccezione: {e}") 
    return None

def test_get_interface():
    target_ip="192.168.56.101"
    iface_ip,iface_name=iface_for_IP(target_ip)
    if iface_ip is not None:
        print(f"L'interfaccia per {target_ip} è: {iface_ip}")
    if iface_name is not None:
        print(f"Il nome dell'interfaccia per {target_ip} è: {iface_name}")


if __name__=="__main__":
    test_get_interface() 
