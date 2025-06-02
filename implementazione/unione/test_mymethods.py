import mymethods
import argparse

def test_check_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host_ip',type=str, help="L'IP dell host dove ricevere i pacchetti ICMP")
    parser.add_argument('--host_iface',type=str, help="Intefaccia di rete dove l'host riceverà i pacchetti ICMP")
    #parser.add_argument('--provaFlag',type=int, help="Comando da eseguire")
    mymethods.check_args(parser)

def test_calc_checksum():
    # Example data (as bytes)
    example_data = b"__CONNECT__ "
    example_data = b"Hello, checksum!"
    result = mymethods.calc_checksum(example_data)
    print(f"Checksum: {result:#06x}")  # Print checksum in hexadecimal format

def test_iface_from_IP():
    target_ip="192.168.56.1"
    iface_ip,iface_name=mymethods.iface_from_IP(target_ip)
    if iface_ip is not None:
        print(f"L'interfaccia per {target_ip} è: {iface_ip}")
    if iface_name is not None:
        print(f"Il nome dell'interfaccia per {target_ip} è: {iface_name}")

from scapy.all import conf
if __name__=="__main__":
    test_check_args()
    test_calc_checksum()
    test_iface_from_IP() 