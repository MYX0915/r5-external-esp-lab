import struct, glob, os
ents=["12E66E7C0","12E66FE40","12E6714C0","12E672B40","12E6741C0","12E675840"]
lines=[]
for e in ents:
    f=r"C:\ProgramData\scdump\9_%s.bin" % e
    raw=open(f,"rb").read()
    p0=struct.unpack_from("<Q", raw, 0xB0)[0]
    p1=struct.unpack_from("<Q", raw, 0xB8)[0]
    print("%s  +0xB0=0x%X  +0xB8=0x%X" % (e,p0,p1))
    lines.append("0x%X 0x1000"%p0)
open("tr.txt","w").write("\n".join(lines))
