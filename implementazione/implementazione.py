from icmplib import ping

def test_icmplib(): 
    address =""
    numPings=1 #count 
    try:
        ping(address, count=4, interval=1, timeout=2, id=None, source=None, family=None, privileged=True, **kwargs)
        #multiping
        #async_ping
        #async_multiping
    except NameLookupError as e:
        print(f"Error: {e}")
        print("If you pass a hostname or FQDN in parameters and it does not exist or cannot be resolved.")
    except SocketPermissionError as e:
        print(f"Error: {e}")
        print("If the privileges are insufficient to create the socket.")
    except SocketAddressError as e:
        print(f"Error: {e}")
        print("If the source address cannot be assigned to the socket.")
    except ICMPSocketError as e:
        print(f"Error: {e}")
        print("If another error occurs. See the ICMPv4Socket or ICMPv6Socket class for details.")
    except Exception as e:
        print(f"Error: {e}")
        print("")
    


def main():
    print("Hello World")
    address =""

if __name__=="__main__":
    main()