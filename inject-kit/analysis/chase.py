import numpy as np, struct
raw=open(r"C:\ProgramData\scdump\5_12E5C6D00.bin","rb").read()
ptrs=[]
for off in range(0, 0x4000, 8):
    v=struct.unpack_from("<Q", raw, off)[0]
    if 0x10000 < v < 0x7FFF00000000 and (v & 7)==0:
        # skip pointers that point inside this same object
        if 0x12E5C6D00 <= v < 0x12E5C6D00+0x8000: continue
        ptrs.append((off,v))
print("pointers found:", len(ptrs))
for off,v in ptrs[:14]:
    print("  +0x%04X -> 0x%X" % (off,v))
open("chase.txt","w").write("\n".join("0x%X 0x4000"%v for off,v in ptrs[:10]))
