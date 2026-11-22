import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_132769820.bin") if os.path.getsize(p)>=0x4000]
print("studioHdr dumps:", [(os.path.basename(x), os.path.getsize(x)) for x in fs])
if not fs: raise SystemExit
raw=open(max(fs,key=os.path.getmtime),"rb").read()
kids=[]
for i in range(0, min(len(raw),0x200), 8):
    v=struct.unpack_from("<Q", raw, i)[0]
    if 0x10000 < v < 0x7FFF00000000 and (v & 7)==0 and not (0x7FF776980000 <= v < 0x7FF790000000):
        kids.append((i,v))
print("candidate children:", [(hex(o),hex(v)) for o,v in kids])
open("kids2.txt","w").write("\n".join("p 0x%X"%v for _,v in kids))
