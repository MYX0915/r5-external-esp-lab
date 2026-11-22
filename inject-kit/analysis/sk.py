import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_C9F336E0.bin") if os.path.getsize(p)>=0x1000]
if not fs:
    print("no studioHdr dump"); raise SystemExit
raw=open(fs[0],"rb").read()
kids=[]
for i in range(0, min(len(raw),0x200)-8, 8):
    v=struct.unpack_from("<Q", raw, i)[0]
    if 0x10000 < v < 0x7FFF00000000 and (v & 7)==0 and not (0x7FF776980000 <= v < 0x7FF790000000):
        kids.append((i,v))
print("studioHdr child pointers:", [(hex(o),hex(v)) for o,v in kids])
open("skids.txt","w").write("\n".join("0x%X 0x4000"%v for _,v in kids[:6]))
