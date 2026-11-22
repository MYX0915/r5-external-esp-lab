import struct, glob, os
for hexv in ("120127980","132729D90"):
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: print("%s: no 0x4000 dump" % hexv); continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p170=struct.unpack_from("<Q", raw, 0x170)[0]
    pfd0=struct.unpack_from("<Q", raw, 0xFD0)[0]
    p376=struct.unpack_from("<3f", raw, 0x376C)
    print("0x%s vt=0x%X  +0x170=0x%X  +0xFD0=0x%X  +0x376C=(%.1f,%.1f,%.1f)" % (hexv,vt,p170,pfd0,p376[0],p376[1],p376[2]))
    open("pd_%s.txt"%hexv,"w").write("p 0x%X\n" % p170)
