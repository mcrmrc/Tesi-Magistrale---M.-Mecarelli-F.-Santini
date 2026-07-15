

import sys
import threading

from Programma.methods.check_type import is_list, is_string, is_subprocess_Popen
from Programma.custom_enum import MSG
from Programma.methods.get_methods import get_shellProcess_command

class EXCEUTE_COMMAND: 
    def __init__(self, comando:str=None): 
        def check_system_compatibility():
            supportedSystems=["linux","win32"] 
            if sys.platform not in supportedSystems: 
                print(sys.platform," non supportato")
                return False 
            return True     
        def append_END_DATA(command:str=None):
            if not is_string(command):
                raise ValueError("comando non stringa",comando) 
            if sys.platform=="win32":
                command+=f" && echo '{MSG.END_DATA.value}'"
            elif sys.platform=="linux": 
                command+=f"; echo '{MSG.END_DATA.value}'" 
            else: print("Sistema operativo non supportato.") 
            print("END append_END_DATA->",command) 
            return command
        def read_stream(stream, data_list:list=None):  
            if not is_list(data_list): 
                raise TypeError("data_list non valida")
            for line in iter(stream.readline, ''):
                if line:
                    decoded = line.rstrip()
                    #print(f"{label}: {decoded}")
                    data_list.append(decoded)
            stream.close() 
        #---------------------
        print("Sistema supportato...") 
        if not is_string(comando): 
            raise ValueError("comando non stringa",comando) 
        if not check_system_compatibility(): 
            raise SystemError(f"{sys.platform} non supportato...") 
        #comando=append_END_DATA(comando)  
        process_shell=get_shellProcess_command(comando) 
        if not is_subprocess_Popen(process_shell): 
            raise Exception("shell non valida:",type(process_shell)) 
        if not process_shell.stdout: 
            raise Exception("stdout non valido") 
        if not process_shell.stderr: 
            raise Exception("stdout non valido") 
        print("Shell aperta con successo...") 
        data_stdout=[] 
        thread_stdout = threading.Thread(
            target=read_stream, 
            args=(process_shell.stdout, data_stdout),
            daemon=True
        ) 
        thread_stdout.start() 

        data_stderr=[] 
        thread_stderr = threading.Thread(
            target=read_stream, 
            args=(process_shell.stderr, data_stderr), 
            daemon=True
        ) 
        thread_stderr.start() 
        
        process_shell.wait()
        process_shell.terminate() 
        thread_stdout.join()
        thread_stderr.join() 
        print("Comando eseguito") 
        #print("STDOUT",data_stdout) 
        data:str=""
        if is_list(data_stdout) and len(data_stdout)>0: 
            data+="".join(text for text in data_stdout) 
        #print("STDEERR",data_stderr) 
        if is_list(data_stderr) and len(data_stderr)>0: 
            data+="".join(text for text in data_stderr) 
        #print("DATI ESECUZIONE",data) 
        self.data=data.strip()
        #if self.data=="": 
        #    self.data=None
