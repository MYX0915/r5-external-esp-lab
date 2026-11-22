import struct, os
# newest 0x8000 dump of our own object
import glob
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\9_*.bin") if os.path.getsize(f)==0x8000]
f=max(fs, key=os.path.getmtime)
raw=open(f,"rb").read()
print("using:", os.path.basename(f))
ptrs=[]
for off in range(0, 0x8000-8, 8):
    v=struct.unpack_from("<Q", raw, off)[0]
    if not (0x10000 < v < 0x00007FFF00000000): continue
    if v & 0xF: continue
    if 0x7FF776980000 <= v < 0x7FF790000000: continue
    ptrs.append((off,v))
print("candidates:", len(ptrs))
open("bm1.txt","w").write("\n".join("0x%X 0x2000"%v for _,v in ptrs[:10]))
for off,v in ptrs[:10]: print("   +0x%04X -> 0x%X" % (off,v))
