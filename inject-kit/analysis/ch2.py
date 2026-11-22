import struct, glob, os
f=[p for p in glob.glob(r"C:\ProgramData\scdump\9_12E66E7C0.bin")]
raw=open(f[0],"rb").read()
ptrs=[]
for off in range(0, 0x2000, 8):
    v=struct.unpack_from("<Q", raw, off)[0]
    if 0x10000 < v < 0x7FFF00000000 and (v & 7)==0 and not (0x12E66E7C0 <= v < 0x12E66E7C0+0x8000):
        ptrs.append((off,v))
print("pointers:", len(ptrs))
for off,v in ptrs[:12]:
    print("  +0x%04X -> 0x%X" % (off,v))
open("chase2.txt","w").write("\n".join("0x%X 0x2000"%v for off,v in ptrs[:12]))
