import string 
import argparse 
import sys
import subprocess
import threading 
import os
import time 
from custom_enum import MSG 
from check_type import * 
from get_type import *
import ctypes

exit_cases=["exit","quit",MSG.END_COMMUNICATION.value] 

systemsDictionary={
    'aix':"AIX",
    'android':"Android",
    'emscripten':"Emscripten",
    'ios':"iOS", 
    'linux':"Linux", 
    'darwin':"macOS", 
    'win32':"Windows", 
    'cygwin':"Windows/Cygwin", 
    'wasi':"WASI" 
} 

def non_blocking_sleep(secondi:int=None): 
    if not is_integer(secondi) or secondi<0:
        raise Exception("aspetta_tempo: Argomenti non validi") 
    if secondi>=60: 
        print(f"Attesa di {secondi//60} minuti e {secondi%60} secondi in corso...")
    else:
        print(f"Attesa di {secondi} secondi in corso...")
    while secondi>0:
        time.sleep(1)
        secondi-=1  


class POWER_SLEEP: 
    #On Window syou can use the WIn32 API via ctypes to set an execution state that keeps the system awake
    class WINDOWS: 
        keep_preventing_sleep=True
        duration_time:int=None 
        # Constants from Win32 API
        ES_AWAYMODE_REQUIRED = 0x00000040
        ES_CONTINUOUS = 0x80000000
        ES_DISPLAY_REQUIRED = 0x00000002
        ES_SYSTEM_REQUIRED = 0x00000001 

        def __init__(self, duration_time:int=None): 
            if not is_integer(duration_time):
                raise TypeError("duration_time non intero")
            # Load kernel32 DLL
            self.kernel32 = ctypes.windll.kernel32 
            self.duration_time=duration_time

        def prevent_sleep(self):
            #Prevents system from sleeping using Windows API  
            print("PREVENT SLEEP")
            self.kernel32.SetThreadExecutionState(
                self.ES_CONTINUOUS | self.ES_SYSTEM_REQUIRED | self.ES_DISPLAY_REQUIRED
            )

        def allow_sleep(self):
            #Restores normal sleep behavior. 
            print("ALLOW SLEEP")
            self.kernel32.SetThreadExecutionState(self.ES_CONTINUOUS)
        
        def run(self):
            try: 
                print("Preventing sleep... Press Ctrl+C to stop.")
                self.prevent_sleep() 
                keep_preventing_sleep=True
                #start_time=time.time() 
                #if duration_time is None: 
                #    exit
                # Simulate long-running low-performance task
                while keep_preventing_sleep:
                    time.sleep(1)  # Sleep to keep CPU usage low
            except KeyboardInterrupt:
                print("\nRestoring normal sleep settings...")
            finally: 
                self.allow_sleep() 
    class LINUX: 
        cmd='systemd-inhibit --what=sleep --why="Timing covert channel" python3 your_script.py'

        def run_with_inhibit():
            cmd = [
                "systemd-inhibit",
                "--what=sleep",
                "--why=Timing covert channel",
                "--mode=block",
                sys.executable,
                *sys.argv
            ]
            os.execvp(cmd[0], cmd)
    class MACOS: 
        cmd='caffeinate -dimsu python3 your_script.py' 

        def run(): 
            subprocess.Popen(["caffeinate", "-dimsu"])


def sanitize_str(stringa):
    if type(stringa) is not str or string is None:
        raise Exception("Stringa non valida")
    stringa = ''.join(
        char if char in string.printable 
        else'' 
        for char in stringa
    ) 
    #stringa=stringa.replace("\t","")
    #stringa=stringa.replace("\n","")
    return stringa.strip() 

def print_dictionary(dictionary:dict=None):
    if not isinstance(dictionary,dict):
        raise Exception("print_dictionary: Dizionario passato non valido") 
    elif len(dictionary)<=0:
        print("Il dizionario è vuoto")
        return
    print("Valori presenti:")
    for key, value in dictionary.items():
        print(f"\t{key}\t\t{value}") 

def ask_bool_choice(msg:str):
    def is_scelta_SI_NO(scelta:str=None):
        if not is_string(scelta): 
            return False 
        whitebox=["yes","si","yeah"]
        for x in whitebox:
            if sanitize_str(scelta)!="" and (x.startswith(scelta) or x in scelta):
                return True 
        return False
    if not isinstance(msg, str):
        raise Exception("ask_bool_choice: Il messaggio non è una stringa")
    return is_scelta_SI_NO(input(f"{msg}"))

class PARSER: 
    def add_argument(param_arg, parser=None):
        if parser is None:
            raise Exception("Parser nullo")
        if len(param_arg)!=3:
            raise Exception("Numero di parametri non corretto")
        if type(param_arg[0]) is not str: 
            raise Exception("L'argomento non è una stringa")
        if type(param_arg[2]) is not str: 
            raise Exception("Il messaggio di aiuto non è una stringa")
        if not (param_arg[0].startswith("--") or param_arg[0].startswith("-")):
            raise Exception("L'argomento deve iniziare con - oppure con --")
        return parser.add_argument(param_arg[0],type=param_arg[1], help=param_arg[2])

    def print_supported_arguments(parser:argparse.ArgumentParser=None): 
        if is_ArgumentParser(parser): 
            print("Controlla di inserire due volte - per gli argomenti")
            print("Argomenti supportati:") 
            for action in parser._actions:
                print("\t{arg}: {help}".format(
                    arg=action.option_strings[0],
                    help=action.help
                )) 

    def check_arguments(parser: argparse.ArgumentParser=None): 
        if is_ArgumentParser(parser):  
            args, unknown = parser.parse_known_args() 
            return args, unknown 
        return None, None

class CALC: 
    def checksum(data: bytes) -> int:
        """
        Calculate the Internet checksum for the given data.
        
        :param data: The data to calculate the checksum for (as bytes).
        :return: The checksum as an integer.
        """
        checksum = 0 
        # Handle odd-length data
        if len(data) % 2 != 0:
            data += b"\x00"
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
        print(f"The checksum of\n\t{data}\n\tis\n\t{checksum}") 
        return checksum 
    
    def checksumV2(data):
        checksum = 0 
        # Handle odd-length data
        if len(data) % 2 != 0:
            data += b"\x00" 
        # Calculate checksum
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1] 
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16 
        return (~checksum) & 0xffff

class TIMER: 
    def stop(timer:threading.Timer=None): 
        if is_threading_Timer(timer): 
            if timer.is_alive(): 
                print("Fermo il timer",end="  ")
                timer.cancel()  
                print(f"Timer fermato? {timer.is_alive()}")
                if not timer.is_alive(): 
                    print("Timer fermato correttamente")
                    return True
                print("Timer ancora in esecuzione")
            else: 
                print("Il timer non era in esecuzione") 
            return False 
        raise Exception(f"Timer non istanza di threadig.Timer: {type(timer)}") 

