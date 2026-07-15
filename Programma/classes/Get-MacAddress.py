import ipaddress
import sys
from Programma.methods.check_type import is_ipaddress


class GET_MAC_ADDRESS: 
    def __init__(self, ip_address:ipaddress.IPv4Address=None): 
        if not is_ipaddress(ip_address):  
            raise Exception("GET_MAC_ADDRESS: IP address non valido") 
        self.ip_address=ip_address
        if sys.platform == "win32":
            self.mac_address=(self._windows_macAddr()).lower().strip().replace("-",":") 
        elif sys.platform=="linux": 
            self.mac_address=(self._linux_macAddr()).lower().strip().replace("-",":") 