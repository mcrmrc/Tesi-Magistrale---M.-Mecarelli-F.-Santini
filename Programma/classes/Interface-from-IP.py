import ipaddress
from Programma.methods.network_methods import interface_from_IPAddress
from Programma.methods.check_type import is_ipaddress

class INTERFACE_FROM_IP:  
    def __init__(self, ip_address:ipaddress.IPv4Address=None): 
        if not is_ipaddress(ip_address): 
            raise Exception("INTERFACE_FROM_IP: indirizzo IP non valido") 
        self.ip_address=ip_address
        self.interface=interface_from_IPAddress(ip_address) 