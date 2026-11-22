import struct, glob, os
want=tuple(float(x) for x in open("selfpos.txt").read().split())
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(f)==0x8000]
f=max(fs, key=os.path.getmtime)
raw=open(f,"rb").read()
print("file:", os.path.basename(f), " target pos:", ["%.1f"%v for v in want])
ptrs=[]
for off in range(0, 0x8000-8, 8):
    v=struct.unpack_from("<Q", raw, off)[0]
    if 0x10000 < v < 0x00007FFF00000000 and (v & 7)==0 and v >= 0x10000:
        if 0x7FF776980000 <= v < 0x7FF790000000: continue   # module
        ptrs.append((off,v))
seen=set(); uniq=[]
for off,v in ptrs:
    if v in seen: continue
    seen.add(v); uniq.append((off,v))
print("unique heap pointers:", len(uniq))
open("chaseB.txt","w").write("\n".join("0x%X 0x2000"%v for off,v in uniq[:20]))
for off,v in uniq[:10]:
    print("   +0x%04X -> 0x%X" % (off,v))
