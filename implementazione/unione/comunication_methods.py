#from scapy.all import *
from scapy.all import IP, ICMP, Raw,  Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr
from scapy.all import sr1, sendp, AsyncSniffer, get_if_hwaddr, in6_getnsma, in6_getnsmac, srp1

import threading 
import argparse
import mymethods
import time
import re 
import subprocess 
import ipaddress
import sys
import socket
import os

CONFIRM_ATTACKER="__CONFIRM_ATTACKER__"
CONFIRM_VICTIM="__CONFIRM_VICTIM__"
CONFIRM_PROXY="__CONFIRM_PROXY__"
CONFIRM_COMMAND="__CONFIRM_COMMAND__"
ATTACK_FUNCTION="__ATTACK_FUNCTION__"
LAST_PACKET="__LAST_PACKET__"
WAIT_DATA="__WAIT_DATA__"
END_COMMUNICATION="__END_COMMUNICATION__"
END_DATA="__END_DATA__"

exit_cases=["exit","quit",END_COMMUNICATION]




