import ipaddress 
from Programma.methods import get_local_IP, get_public_IP, get_IPv6_scopeID


class HOST_IPs: 
    def __init__(self):
        local_IP, error=get_local_IP() 
        if error: 
            raise Exception("Errore nella rilevazione dell'IP privato: ",error)
        self.local_IP=ipaddress.ip_address(local_IP)
        self.global_IP=ipaddress.ip_address(get_public_IP())
        if self.local_IP.version==6:
            self.local_scopeID=get_IPv6_scopeID(self.local_IP) 
        if self.global_IP.version==6:
            self.global_scopID=get_IPv6_scopeID(self.global_IP)  