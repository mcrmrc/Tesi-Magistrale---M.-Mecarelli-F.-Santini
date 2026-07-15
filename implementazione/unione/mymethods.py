from scapy.all import conf 

def add_argument(param_arg, parser=None):
    if parser is None:
        raise Exception("Parser nullo")
    if len(param_arg)!=3:
        raise Exception("Numero di parametri non corretto")
    if type(param_arg[0]) is not str:
        raise Exception("L'argomento non è una stringa")
    if type(param_arg[2]) is not str:
        raise Exception("Il messaggio di aiuto non è una stringa")
    if not param_arg[0].startswith("--") and not param_arg[0].startswith("-"):
        raise Exception("L'argomento deve iniziare con - oppure con --")
    return parser.add_argument(param_arg[0],type=param_arg[1], help=param_arg[2])

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

def iface_from_IP(target_ip=None):
    if target_ip is None:
        raise Exception("Indirizzo IP uguale a None")
    iface_name = conf.route.route(target_ip)[0]
    iface_ip = conf.route.route(target_ip)[1] 
    return iface_ip,iface_name 
 
