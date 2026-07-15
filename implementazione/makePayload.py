with open("payload.txt", "w+") as f:
    for i in range(33, 126):
        f.write(chr(i))
    f.write("\n")
    for i in range(33, 126):
        f.write(chr(i))
    f.write("\n")
    for i in range(33, 126):
        f.write(chr(i))
    f.write("\n")
