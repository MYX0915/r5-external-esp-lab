import struct
pdata=open(r"C:\ProgramData\scdump\8_7FF784870000.bin","rb").read()
best=None
for shift in range(12):
    ok=0; tot=0
    for i in range(shift, len(pdata)-12, 12):
        b,e,u=struct.unpack_from("<III",pdata,i)
        tot+=1
        if 0x1000 <= b < e <= 0x2CA2B7C and (e-b) < 0x20000: ok+=1
    frac=ok/tot if tot else 0
    print("shift=%d sane=%d/%d (%.1f%%)" % (shift, ok, tot, frac*100))
