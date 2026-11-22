import struct, bisect
pdata=open(r"C:\ProgramData\scdump\8_7FF784870000.bin","rb").read()
ents={}
for i in range(4, len(pdata)-12, 12):
    b,e,u=struct.unpack_from("<III",pdata,i)
    if 0x1000 <= b < e <= 0x2CA2B7C and (e-b) < 0x20000:
        ents.setdefault(b,e)
begins=sorted(ents)
print("functions:", len(begins))
for rva in (0x23FF62D,):
    i=bisect.bisect_right(begins, rva)-1
    s=begins[i]; e=ents[s]
    print("RVA 0x%X -> function 0x%X..0x%X (size %d), offset in func 0x%X" % (rva,s,e,e-s,rva-s))
    text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
    off=s-0x1000
    print("prologue bytes:", text[off:off+12].hex(" "))
