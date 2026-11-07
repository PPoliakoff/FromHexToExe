


# write string of chars
# write byte
# write 32 bits
# fill with N bytes

def f_wStr(f,text):
    return f.write(text.encode('utf-8'))

def f_fill(f,count,number):
    byte=number.to_bytes(1)
    for i in range(count):
        f.write(byte)
    return count

def f_w08b(f,number):
    byte=number.to_bytes(1)
    return f.write(byte)

def f_w16b(f,number):
    return f.write(number.to_bytes(2,'little'))

def f_w32b(f,number):
    return f.write(number.to_bytes(4,'little'))

def f_w64b(f,number):
    return f.write(number.to_bytes(8,'little'))

n=0
with open("MyExe.exe","wb") as f:
    n+=f_wStr(f,"MZ")     
    n+=f_fill(f,0x3c-n,0)  # DOS program
    n+=f_w08b(f,0xe0)      # pointer to next header
    n+=f_fill(f,0xe0-n,0)  # DOS data
    n+=f_wStr(f,"PE\0\0")  
    n+=f_w16b(f,0x8664)    # Processor
    n+=f_w16b(f,0x0004)    # >>>>number of sections

        