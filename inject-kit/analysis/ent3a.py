import numpy as np, glob, os, struct
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_3AAC9020.bin") if os.path.getsize(p)==0x4000], key=os.path.getmtime)
if not fs: print("no dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
vt=struct.unpack_from("<Q", raw, 0)[0]
print("entity 0x3AAC9020  vtable=0x%X" % vt)
def f3(off):
    return struct.unpack_from("<3f", raw, off)
print("\n--- ???? (0x140..0x180) ---")
for off in range(0x140, 0x180, 4):
    v=struct.unpack_from("<f", raw, off)[0]
    print("   +0x%03X = %12.4f" % (off, v))
print("\n--- ??????? ---")
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=struct.unpack_from("<3f",f,32)
print("me = (%.1f, %.1f, %.1f)" % me)
for base in (0x14C,0x150,0x154,0x158,0x15C,0x160):
    try:
        t=f3(base)
        print("   +0x%03X as vec3 = (%.2f, %.2f, %.2f)" % (base,t[0],t[1],t[2]))
    except: pass
