import sys
import subprocess

def firewall_disable():
    print("Disabilitando il firewall")
    if sys.platform == "win32":
        print("Il sistema è Windows...")
        #check its current status -> Get-NetFirewallProfile | Format-Table -Property Name, Enabled
        command="Get-NetFirewallProfile | Format-Table -Property Name, Enabled"
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        ) 
        stdout, stderr = process_shell.communicate()
        if stderr: 
            raise Exception(f"line 345 disable_firewall: {stderr}")  
        #print("Stato iniziale dei profili")
        for line in stdout.split("\n"):
            if any((profile in line) for profile in ["Domain", "Private", "Public"]): 
                #print(f"\tRisultato del profilo: {line}") 
                pass
        process_shell.wait() 
        #disable the Windows Firewall for all profiles -> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
        command="Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False"
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate() 
        if stderr: 
            raise Exception(f"line 363 disable_firewall: {stderr}")
        process_shell.wait() 
        #verify that the changes have taken effect -> Get-NetFirewallProfile | Format-Table -Property Name, Enabled
        #command="Get-NetFirewallProfile | Format-Table -Property Name, Enabled"
        #process_shell= subprocess.Popen(
        #    ["powershell", "-Command", command], 
        #    stdin=subprocess.PIPE
        #    ,stdout=subprocess.PIPE
        #    ,stderr=subprocess.PIPE
        #    ,text=True
        #    ,bufsize=1
        #)
        #stdout, stderr = process_shell.communicate() 
        #if stderr: 
        #    raise Exception(f"line 378 disable_firewall: {stderr}") 
        #print("Controllato il risutlato su tutti i profili")
        #for line in stdout.split("\n"):  
        #    if any((profile in line) for profile in ["Domain", "Private", "Public"]):
        #        if "True" in line:
        #            raise Exception(f"Profilo non disabilitato: {line}")
        #        #print(f"\tRisultato del profilo: {line}") 
        print("Tutti i profili disabilitati. Firewall disabilitato con successo") 
        process_shell.wait()
    elif sys.platform=="linux":
        print("Il sistema è Linux...")
        #Is the ufw running?
        command="sudo ufw status"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        if stderr: 
            raise Exception(f"line 401 disable_firewall: {stderr}")  
        #print("Stato iniziale del firewall")
        for line in stdout.split("\n"): 
            if any((stato in line) for stato in ["attivo", "active"]): 
                #print(f"\t{line}")  
                pass
        process_shell.wait() 
        #Stop the ufw on Linux
        command="sudo ufw disable"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        if stderr:
            raise Exception(f"line 421 disable_firewall: {stderr}")
        if stdout:
            #print(f"{stdout}") 
            pass
        process_shell.wait()
        #Disable the ufw on Linux at boot time
        command="sudo systemctl disable ufw"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate() 
        process_shell.wait() 
        #Is the ufw running?
        #command="sudo ufw status"
        #process_shell= subprocess.Popen(
        #    ["bash", "-c", command] 
        #    ,stdin=subprocess.PIPE 
        #    ,stdout=subprocess.PIPE 
        #    ,stderr=subprocess.PIPE 
        #    ,text=True
        #    ,bufsize=1
        #)
        #stdout, stderr = process_shell.communicate()
        #if stderr: 
        #    raise Exception(f"line 401 disable_firewall: {stderr}")  
        #print("Stato finale del firewall")
        #for line in stdout.split("\n"): 
        #    if any((stato in line) for stato in ["inattivo", "inactive"]): 
        #        #print(f"\t inattivo: {line}") 
        #        pass
        #    elif any((stato in line) for stato in ["attivo", "active"]):
        #        #print(f"\t attivo: {line}") 
        #        pass 
        print("Tutti i profili disabilitati. Firewall disabilitato con successo")
        process_shell.wait() 
    else:
        raise Exception("Sistema operativo non supportato per l'apertura della shell.") 

def firewall_enable(): 
    print("Riabilitando il firewall")
    if sys.platform == "win32":
        print("Il sistema è Windows...")  
        #check its current status -> Get-NetFirewallProfile | Format-Table -Property Name, Enabled
        command="Get-NetFirewallProfile | Format-Table -Property Name, Enabled"
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        ) 
        stdout, stderr = process_shell.communicate()
        if stderr: 
            raise Exception(f"line 466 disable_firewall: {stderr}")  
        #print("Stato iniziale dei profili")
        for line in stdout.split("\n"):
            if any((profile in line) for profile in ["Domain", "Private", "Public"]): 
                #print(f"\tRisultato del profilo: {line}") 
                pass
        process_shell.wait() 
        #disable the Windows Firewall for all profiles -> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
        command="Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True"
        process_shell= subprocess.Popen(
            ["powershell", "-Command", command], 
            stdin=subprocess.PIPE
            ,stdout=subprocess.PIPE
            ,stderr=subprocess.PIPE
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate() 
        if stderr: 
            raise Exception(f"line 484 disable_firewall: {stderr}")
        #print("Comando eseguito con successo")  
        process_shell.wait()  
        #verify that the changes have taken effect -> Get-NetFirewallProfile | Format-Table -Property Name, Enabled
        #command="Get-NetFirewallProfile | Format-Table -Property Name, Enabled"
        #process_shell= subprocess.Popen(
        #    ["powershell", "-Command", command], 
        #    stdin=subprocess.PIPE
        #    ,stdout=subprocess.PIPE
        #    ,stderr=subprocess.PIPE
        #    ,text=True
        #    ,bufsize=1
        #)
        #stdout, stderr = process_shell.communicate() 
        #if stderr: 
        #    raise Exception(f"line 499 disable_firewall: {stderr}") 
        #print("Controllato il risutlato su tutti i profili")
        #for line in stdout.split("\n"):  
        #    if any((profile in line) for profile in ["Domain", "Private", "Public"]):
        #        if "False" in line:
        #            raise Exception(f"Profilo non riabilitato: {line}")
        #        #print(f"\tRisultato del profilo: {line}")
        print("Tutti i profili riabilitati. firewall riabilitato")
        process_shell.wait() 
    elif sys.platform=="linux":
        print("Il sistema è Linux...") 
        #Is the ufw running?
        command="sudo ufw status" #sudo ufw --version 
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        if stderr: 
            raise Exception(f"line 474 disable_firewall: {stderr}")  
        #print("Stato iniziale del firewall")
        for line in stdout.split("\n"): 
            if any((stato in line) for stato in ["inattivo", "inactive"]): 
                #print(f"\t inattivo: {line}") 
                pass
            elif any((stato in line) for stato in ["attivo", "active"]):
                #print(f"\t attivo: {line}") 
                pass
        process_shell.wait() 
        #Enable the ufw on Linux at boot time
        command="sudo systemctl enable ufw"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        #if stderr:
        #    raise Exception(f"line 437 disable_firewall: {stderr}")
        for line in stdout.split("\n"): 
            if "Created" in line:
                #print(f"Disabled ufw at boot time: {line}") 
                pass
        process_shell.wait() 
        #Start the ufw on Linux
        command="sudo ufw enable"
        process_shell= subprocess.Popen(
            ["bash", "-c", command] 
            ,stdin=subprocess.PIPE 
            ,stdout=subprocess.PIPE 
            ,stderr=subprocess.PIPE 
            ,text=True
            ,bufsize=1
        )
        stdout, stderr = process_shell.communicate()
        if stderr:
            raise Exception(f"line 421 disable_firewall: {stderr}")
        if stdout:
            #print(f"{stdout}") 
            pass
        process_shell.wait()
        #Is the ufw running?
        #command="sudo ufw status" #sudo ufw --version 
        #process_shell= subprocess.Popen(
        #    ["bash", "-c", command] 
        #    ,stdin=subprocess.PIPE 
        #    ,stdout=subprocess.PIPE 
        #    ,stderr=subprocess.PIPE 
        #    ,text=True
        #    ,bufsize=1
        #)
        #stdout, stderr = process_shell.communicate()
        #if stderr: 
        #    raise Exception(f"line 474 disable_firewall: {stderr}")  
        #print("Stato finale del firewall")
        #for line in stdout.split("\n"): 
        #    if any((stato in line) for stato in ["inattivo", "inactive"]): 
        #        #print(f"\t inattivo: {line}") 
        #        pass
        #    elif any((stato in line) for stato in ["attivo", "active"]):
        #        #print(f"\t attivo: {line}") 
        #        pass 
        print("Tutti i profili riabilitati. firewall riabilitato")
        process_shell.wait() 
    else: 
        raise Exception(  "Sistema operativo non supportato per l'apertura della shell")
