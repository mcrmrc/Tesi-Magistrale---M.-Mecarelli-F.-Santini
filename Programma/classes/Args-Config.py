import argparse
import ipaddress
import json
import os
from ..custom_enum import ATTACK_TYPE, ENTITY
from ..methods.check_type import is_enum_member, is_integer, is_list, is_namespace, is_string
from ..methods.get_methods import get_local_IP
from ..classes import PARSER

class ARGS_FROM_FILE_CONFIG: 
    def __init__(self,config_file_path:str="./attack_file.json"): 
        if not is_string(config_file_path):
            raise TypeError("Percorso del file non è una stringa valida:",config_file_path)
        if not config_file_path.endswith(".json"):
            raise TypeError(f"File non è un JSON:",config_file_path)
        if not os.path.exists(config_file_path):
            raise FileNotFoundError(f"File non presente:",config_file_path)
        self.config_file_path=config_file_path 
        with open(self.config_file_path, 'r') as file: 
            print(f"File di configurazione {self.config_file_path} caricato correttamente") 
            self.json_file = json.load(file) 
    
    def ip_victim(self): 
        try:  
            return ipaddress.ip_address(
                self.json_file.get("ip_vittima", None) 
            )
        except Exception as e: 
            print(e) 
        return None
    
    def proxy_list(self):
        proxy_list:list[ipaddress._IPAddressBase]=[]
        for ip_proxy in self.json_file.get("proxy_list", []): 
            try: 
                proxy_list.append(
                    ipaddress.ip_address(ip_proxy)
                ) 
            except ValueError as v: 
                print(f"IP non valido: {v}")
            except Exception as e:
                print(f"{e}") 
        return proxy_list if len(proxy_list)>0 else None 
    
    def attack_type(self): 
        try:
            attack_type=ATTACK_TYPE.get_attack_method(
                self.json_file.get("attack_function", None)
                ) 
            if is_enum_member(attack_type,ATTACK_TYPE): 
                return attack_type 
        except Exception as e:
            print(f"{e}") 
        return None 
    
    def proxy_port(self): 
        try:
            proxy_port=int(self.config_file.get("proxy_port", None))
            if is_integer(proxy_port) and 0<proxy_port<65536: 
                return proxy_port 
        except Exception as e:
            print(f"{e}")  
            print(f"Porta {proxy_port} non valida") 
        return None 
    
    def num_proxy(self):
        try:
            num_proxy=int(self.config_file.get("num_proxy", None) )
            if is_integer(num_proxy): 
                return num_proxy 
        except Exception as e:
            print(f"{e}")
        return None

class ARGS_FROM_COMMAND_LINE:
    def __init__(self, entita:ENTITY=None)->argparse.Namespace: 
        if not is_enum_member(entita, ENTITY): 
            raise TypeError("Entità non valida:",entita) 
        parser = argparse.ArgumentParser() 
        match entita:
            case ENTITY.ATTACKER:
                parser.add_argument(
                    "--file_path",
                    type=str, 
                    help="File di configurazione"
                )  
            case ENTITY.PROXY: 
                parser.add_argument(
                    "--ip_attaccante",
                    type=str, 
                    help="IP dell'attaccante"
                ) 
            case ENTITY.VICTIM:
                parser.add_argument(
                    "--num_proxy",
                    type=int, 
                    help="Numero dei proxy necessari"
                )
            case _: 
                raise ValueError("Entità non valida:",entita)
        args,unknown =PARSER.check_arguments(parser) 
        if not is_namespace(args):   
            raise TypeError(f"Namespace non valido: {args}") 
        if is_list(unknown) and len(unknown)>0: 
            raise ValueError(f"Argomenti sconosciuti: {unknown}") 
        try:
            match entita:
                case ENTITY.ATTACKER:
                    if not args.file_path or not is_string(args.file_path): 
                        raise ValueError(f"--file_path non specificato") 
                case ENTITY.PROXY: 
                    if not args.ip_attaccante or not is_string(args.ip_attaccante): 
                        raise ValueError(f"--ip_attaccante non specificato") 
                case ENTITY.VICTIM:
                    if not args.num_proxy or not is_integer(args.num_proxy): 
                        raise ValueError(f"--num_proxy non specificato") 
                case _: 
                    raise ValueError("Entità non valida:",entita)
        except ValueError as e:
            print(e) 
            #parser.print_help() 
            PARSER.print_supported_arguments(parser) 
            args=None 
        return args

class ARGS_CONFIG:
    class FROM_FILE: 
        def get_ip_host(self): 
            ip_host, errore=get_local_IP() 
            if errore:
                print("errore:",errore)  
                msg="Inserire indirizzo IP dell'host:\n\t#" 
                ip_host=input(msg) 
            #self.ip_host=ipaddress.ip_address("192.168.56.104") #TODO eliminare alla fine 
            for count in range(3):
                try:
                    ip_host=ipaddress.ip_address(ip_host) 
                    return ip_host
                except Exception as e:
                    print(f"get_ip_host: {e}") 
                    print("Indirizzo IP dell'host non valido") 
                    msg="Inserire indirizzo IP dell'host:\n\t#" 
                    ip_host=input(msg) 
            return None 
        
        def ask_proxy_port(self):
            try: 
                msg="Inserire porta proxy (0-65535):\n\t#"
                proxy_port=int(input(msg)) 
                if is_integer(proxy_port) and 0<proxy_port<65536: 
                    return proxy_port
            except Exception as e:
                print(f"{e}")  
                print(f"Porta {proxy_port} non valida") 
        
        def ask_num_proxy(self): 
            try:
                print("Numero proxy non valido")
                msg="Inserire numero proxy (1-100):\n\t#"
                num_proxy=int(input(msg)) 
                if is_integer(num_proxy) and 0<num_proxy<100: 
                    return num_proxy 
            except Exception as e:
                print(f"{e}") 
                print("Numero proxy non valido")
            return None 
        
        def ask_attack_type(self): 
            try: 
                attack_type=ATTACK_TYPE.choose_attack_function() 
                if is_enum_member(attack_type,ATTACK_TYPE): 
                    return attack_type 
            except Exception as e:
                print(f"{e}") 
            return None 
        
    
    
