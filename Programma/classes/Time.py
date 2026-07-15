import threading
from Programma.methods.check_type import is_threading_Timer


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
