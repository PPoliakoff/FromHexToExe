from time import time


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

def f_wbytes(f,list):
    return f.write(bytes(list))

n=0
string1_virtualAddress=0
string2_virtualAddress=0
MessageBoxA_virtualAddress=0
with open("MyExe.exe","wb") as f:
    n+=f_wStr(f,"MZ")     
    n+=f_fill(f,0x3c-n,0)  # DOS header
    n+=f_w08b(f,0xC0)      # pointer to next header
    n+=f_fill(f,0xC0-n,0)  # DOS code
    n+=f_wStr(f,"PE\0\0")  

    #COFF file header
    #================
    n+=f_w16b(f,0x8664)    # Processor : x64
    n+=f_w16b(f,0x0003)    # >>>>number of sections
    n+=f_w32b(f,int(time())) # date (s. since 1/1/1970)
    n+=f_fill(f,8,0)       # unused
    n+=f_w16b(f,0x00F0)    # optional header size<<<<<???? how is it computed
    n+=f_w16b(f,0x0023)    # characteristics : no debug, non relocatable, executable

    # optional header
    # optional header standard fields
    n+=f_w16b(f,0x020B)    # PE32+ magic number
    n+=f_w16b(f,0x0100)    # Linker version 1.0
    n+=f_w32b(f,0x00000200) # sizeofcode
    n+=f_w32b(f,0x00000400) # sizeofinitializeddata
    n+=f_w32b(f,0x00000000) # sizeofuninitializeddata
    n+=f_w32b(f,0x00001000) # startaddress
    n+=f_w32b(f,0x00001000) # baseofcode


    # optional header windows fields
    n+=f_w64b(f,0x0000000140000000) #image base :address when loaded in RAM
    n+=f_w32b(f,0x00001000) #SectionAlignment
    n+=f_w32b(f,0x00000200) #FileAlignment
    n+=f_w32b(f,0x00000006) #OSversion
    n+=f_w32b(f,0x00000000) #ImageVersion
    n+=f_w32b(f,0x00000006) #SubsystemVersion
    n+=f_fill(f,4,0)       # unused
    n+=f_w32b(f,0x00004000) #SizeOfImage (multiple of section alignment) ????
    n+=f_w32b(f,0x00000400) #SizeOfHeaders (mulitple of File alignment)  (raw adrress of 1st section)
    n+=f_w32b(f,0) #CheckSum not used
    n+=f_w16b(f,0x0002) #Subsystem : ?? is this 2 or 3 ??
    n+=f_w16b(f,0x8120) #DllCharacteristics (sorry we don't use relocation)
    n+=f_w64b(f,0x00100000) #SizeOfStackReserve
    n+=f_w64b(f,0x00001000) #SizeOfStackCommit
    n+=f_w64b(f,0x00100000) #SizeOfHeapReserve
    n+=f_w64b(f,0x00001000) #SizeOfHeapCommit
    n+=f_w32b(f,0) #not used
    n+=f_w32b(f,16) #NumberOfRvaAndSizes

    # optional header data directories  
    n+=f_w64b(f,0) # export table
    n+=f_w32b(f,0x2154) # import table virtual address<<<<<<<<
    n+=f_w32b(f,0x0028) # import table size<<<<<<<
    
    n+=f_w64b(f,0) # resource table
    n+=f_w32b(f,0x3000) # exception table virtual address<<<<<
    n+=f_w32b(f,0xC0) # exception table size<<<<<<
    
    n+=f_w64b(f,0) # certificate table
    n+=f_w64b(f,0) # base relocation table
    n+=f_w32b(f,0x2020) # debug virtual address<<<<<<<
    n+=f_w32b(f,0x38) # debug size<<<<<<<<<
    
    n+=f_w64b(f,0) # Architecture :unused
    n+=f_w64b(f,0) # Global PTR
    n+=f_w64b(f,0) # TLS
    n+=f_w64b(f,0) # load config
    
    n+=f_w64b(f,0) # bound import
    n+=f_w32b(f,0x2000) #IAT virtual address<<<<<
    n+=f_w32b(f,0x0010) #IAT size<<<<<<
    
    n+=f_w64b(f,0) # delay Import
    n+=f_w64b(f,0) # CLR
    n+=f_w64b(f,0) # unused

    # sections declarations
    # .text section declaration
    n+=f_wStr(f,".text\0\0\0") # section name (len=8)
    n+=f_w32b(f,0x25) # virtual size<<<<<<
    n+=f_w32b(f,0x1000) # virtual address<<<<<
    n+=f_w32b(f,0x200) # raw size
    n+=f_w32b(f,0x0400) # raw address<<<<<<
    n+=f_w32b(f,0) # unused
    n+=f_w32b(f,0) # unused 
    n+=f_w32b(f,0) # unused
    n+=f_w32b(f,0x60000020) # section caracteristics: READ+EXECUTE:code
              
    # .rdata section declaration
    n+=f_wStr(f,".rdata\0\0") # section name (len=8)
    n+=f_w32b(f,0x01aa) # virtual size<<<<<<
    n+=f_w32b(f,0x2000) # virtual address<<<<<
    n+=f_w32b(f,0x200) # raw size
    n+=f_w32b(f,0x0600) # raw address<<<<<<
    n+=f_w32b(f,0) # unused
    n+=f_w32b(f,0) # unused 
    n+=f_w32b(f,0) # unused
    n+=f_w32b(f,0x40000040) # section caracteristics: READ:initialized Data

    # .pdata section declaration
    n+=f_wStr(f,".pdata\0\0") # section name (len=8)
    n+=f_w32b(f,0x00C0) # virtual size<<<<<<
    n+=f_w32b(f,0x3000) # virtual address<<<<<
    n+=f_w32b(f,0x200) # raw size
    n+=f_w32b(f,0x0800) # raw address<<<<<<
    n+=f_w32b(f,0) # unused
    n+=f_w32b(f,0) # unused 
    n+=f_w32b(f,0) # unused
    n+=f_w32b(f,0x40000040) # section caracteristics: READ:initialized Data

    #fill till first section
    n+=f_fill(f,0x400-n,0)

    # .text section (rawadress=0x400 , virtual address= 0x1000)
    n+=f_wbytes(f,[0x48,0x83,0xEC,0x28]) # sub	 rsp, 28h
    n+=f_wbytes(f,[0x45,0x33,0xc9])      # xor	 r9d, r9d
    n+=f_wbytes(f,[0x4c,0x8d, 0x05])     # lea	 r8, [STRING1]
    instruction_pointer=n-0x400+0x1000+4
    n+=f_w32b(f,string1_virtualAddress-instruction_pointer)
    n+=f_wbytes(f,[0x48,0x8d,0x15])      # lea	 rdx, [STRING2]
    instruction_pointer=n-0x400+0x1000+4
    n+=f_w32b(f,string2_virtualAddress-instruction_pointer)
    n+=f_wbytes(f,[0x33,0xc9])           # xor	 ecx,ecx
    n+=f_wbytes(f,[0xff,0x15])           # call	 QWORD PTR MessageBoxA
    instruction_pointer=n-0x400+0x1000+4
    n+=f_w32b(f,MessageBoxA_virtualAddress-instruction_pointer)
    n+=f_wbytes(f,[0x90])                # nop
    n+=f_wbytes(f,[0x33,0xc0])           # xor	 eax,eax 
    n+=f_wbytes(f,[0x48,0x83,0xc4,0x28]) # add	 rsp,28h
    n+=f_wbytes(f,[0xC3])                # ret 

    #fill till second section
    n+=f_fill(f,0x600-n,0)

    #second section: .rdata : raw address= 0x600, virtual address = 0x2000
    
    #IAT (virtual adrress : 0x2000)
    n+=f_w64b(f,0x2190) # address of the function name entry

    # initalized variables
    string1_virtualAddress=n-0x600+0x2000
    n+=f_wStr(f,"hello\0")
    string2_virtualAddress=n-0x600+0x2000
    n+=f_wStr(f,"world!\0")
    n+=f_fill(f,0x754-n,0)
    #IDT (raw address : 0x754 virtual address : 0x2154)
    n+=f_w32b(f,0x2180) # ILT virtual address
    n+=f_w32b(f,0) # 0
    n+=f_w32b(f,0) # Forwarder Chain set to 0
    n+=f_w32b(f,0x219E) # function names virtual address
    n+=f_w32b(f,0x2000) # IAT virtual address

    n+=f_fill(f,20,0) #IDT terminator

    n+=f_fill(f,0x780-n,0) #????
    
    #ILT(raw address : 0x780 virtual address : 0x2180)
    n+=f_w64b(f,0x2190) # address of the function name entry

    n+=f_fill(f,0x790-n,0) #????
    #function names (raw address : 0x790 virtual address : 0x2190)
    n+=f_w16b(f,hint)
    n+=f_wStr(f,"MessageBoxA\0")
    if n%2 !=0:
        n+=f_w08b(f,0) #align on 16bits

    #DLL names (raw address : 0x79E virtual address : 0x219E)
    n+=f_wStr(f,"USER32.dll\0")
    





