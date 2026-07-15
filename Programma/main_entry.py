from Programma.methods.check_type import is_namespace, is_string 
from classes import ARGS_CONFIG 
from config import localhost 
from custom_enum import ENTITY 


if __name__=="__main__": 
    args=ARGS_CONFIG.FROM_COMMAND(ENTITY.ATTACKER).args
    if not is_namespace(args): 
        exit(-1) 
    if not is_string(args.file_path):
        config_args=ARGS_CONFIG.FROM_FILE(args.file_path) 
    else: config_args=ARGS_CONFIG.FROM_FILE(None) 
    attacker=Attacker(config_args) 
    attacker.start()

if __name__=="__main__": 
    args=ARGS_CONFIG.FROM_COMMAND(ENTITY.PROXY) 
    if not is_namespace(args): 
        exit(-1) 
    if int(args.proxy_port): 
        proxy_port=args.proxy_port
    if not is_string(args.ip_attaccante): 
        raise ValueError("IP attaccante non specificato") 
    ip_attaccante=None
    if args.ip_attaccante=="SELF": 
        attacker_mode=True
        ip_attaccante=ipaddress.ip_address(localhost)
    else: 
        attacker_mode=False
        ip_attaccante=ipaddress.ip_address(args.ip_attaccante)
    proxy=Proxy(ip_attaccante, proxy_port) 
    proxy.start()

if __name__ == "__main__": 
    args=ARGS_CONFIG.FROM_COMMAND(ENTITY.VICTIM).args 
    if not is_namespace(args): 
        exit(-1) 
    if not is_string(args.file_path):
        config_args=ARGS_CONFIG.FROM_FILE(args.file_path) 
    else: config_args=ARGS_CONFIG.FROM_FILE(None) 
    vittima=Victim(config_args.num_proxy ) 
    vittima.start()

