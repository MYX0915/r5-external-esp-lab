import struct
ents=["12E66E7C0","12E66FE40","12E6714C0","12E672B40","12E6741C0","12E675840"]
lines=[]
for e in ents:
    raw=open(r"C:\ProgramData\scdump\9_%s.bin"%e,"rb").read()
    p1=struct.unpack_from("<Q", raw, 0xB8)[0]
    lines.append("0x%X 0x2000"%p1)
open("tr8.txt","w").write("\n".join(lines))
print("\n".join(lines))
