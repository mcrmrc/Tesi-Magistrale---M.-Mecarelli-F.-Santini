import sys
import time
import os
import ctypes
from asyncio import subprocess
from Programma.methods.check_type import is_integer

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
