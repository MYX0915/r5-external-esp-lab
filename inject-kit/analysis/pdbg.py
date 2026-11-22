import struct
pdata=open(r"C:\ProgramData\scdump\8_7FF784870000.bin","rb").read()
print("size:", len(pdata))
for i in range(6):
    b,e,u=struct.unpack_from("<III",pdata,i*12)
    print("  [%d] begin=0x%-8X end=0x%-8X unwind=0x%X  size=%d" % (i,b,e,u,e-b))
