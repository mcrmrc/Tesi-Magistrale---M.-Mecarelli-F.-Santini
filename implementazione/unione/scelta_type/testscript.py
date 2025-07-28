int1=int.from_bytes("i".encode())
int2=int.from_bytes("p".encode())
XOR=int1^int2
print(f"Int1:{int1}\tInt2:{int2}\tXOR:{XOR}\tInt1 from XOR:{XOR^int2}")
print(f"Bytes:\n\t{bin(int1)}\n\t{bin(int2)}\n\t{bin(XOR)}")