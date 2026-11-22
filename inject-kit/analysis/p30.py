import struct, glob, os
lines=[]
for f in sorted(glob.glob(r"C:\ProgramData\scdump\13_*.bin"))[:6]:
    if os.path.getsize(f)<0x200: continue
    raw=open(f,"rb").read()
    p=struct.unpack_from("<Q", raw, 0x30)[0]
    inst=os.path.basename(f)[3:].split(".")[0]
    print("%s +0x30 -> 0x%X" % (inst, p))
    if 0x10000 < p < 0x7FFF00000000:
        lines.append("0x%X 0x2000"%p)
open("p30.txt","w").write("\n".join(lines))
print("prepared", len(lines))
