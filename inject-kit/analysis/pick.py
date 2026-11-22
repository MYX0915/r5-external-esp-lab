import struct, glob, os
f=max([p for p in glob.glob(r"C:\ProgramData\scdump\32_*.bin") if os.path.getsize(p)==0x8000], key=os.path.getmtime)
raw=open(f,"rb").read()
c=[]
for off in range(0, 0x8000-8, 8):
    v=struct.unpack_from("<Q", raw, off)[0]
    if not (0x10000 < v < 0x00007FFF00000000): continue
    if v & 0xF: continue
    if 0x7FF776980000 <= v < 0x7FF790000000: continue
    c.append((off,v))
seen=set(); out=[]
for off,v in c:
    if v in seen: continue
    seen.add(v); out.append((off,v))
print("unique aligned heap ptrs:", len(out))
open("cands.txt","w").write("\n".join("0x%X"%v for off,v in out[:40]))
open("candmap.txt","w").write("\n".join("+0x%X 0x%X"%(off,v) for off,v in out[:40]))
