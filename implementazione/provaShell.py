#https://docs.python.org/3/library/platform.html#module-platform

#https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands
#https://www.lifewire.com/list-of-command-prompt-commands-4092302
import os 
import sys
import subprocess
import argparse
import threading

#print(sys.flags)

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
#print(systemsDictionary[sys.platform])

parser = argparse.ArgumentParser()
parser.add_argument('--dst',type=str, help='IP di destinazione')
parser.add_argument('--path',type=str, help='Path del file da mandare')
parser.add_argument('--command',type=str, help='Comando da eseguire')
#parser.add_argument('--provaFlag',type=int, help='Comando da eseguire')

def printSupportedArguments():
    print("Controlla di inserire due volte - per gli argomenti")
    print("Argomenti supportati:")
    print("\t--dst: IP di destinazione")

def checkCompatibility():
    pass
    
def tras():
    print("Sistema operativo: {}".format(systemsDictionary[sys.platform]))
    print("Versione Python: {}".format(sys.version))
    print("Architettura: {}".format(sys.maxsize > 2**32 and "64 bit" or "32 bit"))
    print("Processi in esecuzione: {}".format(os.getpid()))
    print("Directory corrente: {}".format(os.getcwd()))
    print("Lista file nella directory corrente:")
    print(os.listdir('.'))

def executeCommand(command):
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True)
        if result.returncode == 0:
            print("Comando eseguito con successo:")
            print(result.stdout)
        else:
            print("Errore nell'esecuzione del comando:")
            print(result.stderr)
    except Exception as e:
        print(f"Si è verificato un errore: {e}")

def executeCommand2(command):
    try:
        
        process.stdin.write(command)
        process.stdin.flush()
        result = process.stdout.readline()
        if result is not None:
            print("Comando eseguito con successo:")
            print(result)
        else:
            print("Errore nell'esecuzione del comando:")
            print(result)
        process.terminate()
    except Exception as e:
        print(f"Si è verificato un errore: {e}")

# Funzione per leggere l'output in background
def read_output2(pipe):
    while True:
        line = pipe.readline()
        if not line:
            break
        print(line, end='')

def read_output(pipe):
    buffer = []
    while True:
        line = pipe.readline()
        if not line:
            break
        print(line, end='')
        buffer.append(line)
        # Usa un prompt marker per sapere quando smettere (opzionale)
        if line.strip() == '__END__':
            break
    return buffer

def getShellProcess():
    try:
        if sys.platform == "win32":
            return subprocess.Popen(
                ["cmd.exe"], 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
        elif sys.platform=="linux":
            return subprocess.Popen(
                ["/bin/bash"], 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
        else:
            print("Sistema operativo non supportato per l'apertura della shell.")
            raise NotImplementedError(
                "Sistema operativo non supportato per l'apertura della shell"
            )
    except Exception as e:
        print(f"Errore nell'apertura della shell: {e}")
        return None

if __name__ == "__main__":
    supportedSystems=["linux","win32"] 
    if sys.platform not in supportedSystems:
        print("Sistema non supportato {}".format(sys.platform))
        exit(1) 
    try:
        args, unknown = parser.parse_known_args()
        #args= parser.parse_args()
        print("Argomenti passati: {}".format(args))
        if len(unknown) > 0:
            print("Argomenti sconosciuti: {}".format(unknown))
            printSupportedArguments()
            exit(1) 
    except Exception as e:
        print("Errore: {}".format(e)) 
        exit(1)
    #result = subprocess.run("dir", shell=True, cwd=r"D:\Tesi Magistrale")
    #print(result.stdout)
    print("Sistema supportato")
    try:
        process = getShellProcess()
        if process is None:
            print("Errore nell'apertura della shell")
            exit(1)
        print("Shell aperta con successo")
        # Avvia un thread per leggere continuamente l'output
        #output_thread = threading.Thread(target=read_output, args=(process.stdout,))
        #output_thread.daemon = True
        #output_thread.start()
        while True:
            command = input("Inserisci un comando {} da eseguire (o 'exit' per uscire): ".format(systemsDictionary[sys.platform]))
            if command.lower() in ["exit","quit"]:
                print("Uscita dalla shell")
                process.stdin.write("exit\n")
                process.stdin.flush()
                break
            else:
                print("Esecuzione comando: {}".format(command))
                process.stdin.write( "{com} & echo __END__\n".format(
                    com=command.replace("\n", " ")
                ))
                process.stdin.flush()
                #result = process.stdout.readline()
                #print(result)
                while True:
                    output_line = process.stdout.readline()
                    if not output_line:
                        break
                    if output_line.strip() == "__END__":
                        break
                    print(output_line, end='') 
        process.wait()  # Attende la chiusura del processo
        process.terminate()  # Termina il processo
    except Exception as e:
        print(f"Errore nell'apertura della shell: {e}")
        exit(1)
    #command=input("Inserisci un comando {} da eseguire: ".format(systemsDictionary[sys.platform]))
    #while command!="exit": 
        #print("Esecuzione comando: {}".format(command))
        #executeCommand2(command)
        #command=input("Inserisci un comando {} da eseguire: ".format(systemsDictionary[sys.platform]))
    #print("Fine del programma")
    exit(0)
    

def prova():
    result=subprocess.run("dir", shell=True, capture_output=True, text=True)  
    #os.system("dir") #Work in Windows wioth CMD
    print(result.stdout)
    print(result.stderr)

    #https://learn.microsoft.com/it-it/windows-server/administration/windows-commands/icacls
    result=subprocess.run(["icacls","prova.py"], shell=True, capture_output=True, text=True)  
    #os.system("dir") #Work in Windows wioth CMD
    print(result.stdout)
    print(result.stderr)

    result=subprocess.run([
        "powershell", 
        "-Command", 
        "Get-Item -Path 'prova.py' | Format-List"
    ], capture_output=True, text=True)
    #print(result.stdout)
    #print(result.stderr)

    result=subprocess.run([
        "powershell", 
        "-Command", 
        "Get-Acl -Path 'prova.py' | Format-List"
    ], capture_output=True, text=True)  
    #os.system("dir") #Work in Windows wioth CMD
    #print(result.stdout)
    #print(result.stderr)


#https://medium.com/@prachi1808saini/title-sending-messages-using-the-ping-command-in-linuxu-d6083b0a8517 

#https://thepythoncode.com/article/sniff-http-packets-scapy-python
#https://www.geeksforgeeks.org/packet-sniffing-using-scapy/
#https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sniffing/index.html



#iface: Specify the network interface to sniff on.
#count: The number of packets to capture. If omitted, sniffing will continue until stopped.
#filter: Apply a BPF (Berkeley Packet Filter) to capture only certain packets.
#prn: Define a callback function to execute with each captured packet.
#store: Whether to store sniffed packets or discard them.



#Scapy can also store sniffed packets in a .pcap file, which can be analyzed later with tools like Wireshark. To save packets to a file, use the wrpcap() function:
#   Save captured packets to a file
#   wrpcap('captured.pcap', packets)

#Scapy can read packets from a .pcap file using the rdpcap() function or by setting the offline parameter in the sniff() function:
#   Read packets from a file
#   packets = rdpcap('captured.pcap')


#Try disabling the firewall temporarily on the VM to test:
#   On Windows: 
#   netsh advfirewall set allprofiles state off
#On Linux: 
#   sudo ufw disable (if ufw is used)



