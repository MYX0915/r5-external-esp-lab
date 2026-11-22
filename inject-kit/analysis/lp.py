import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF77AD*C660.bin") if os.path.getsize(p)>=0x20]
if not fs:
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x20]
    fs.sort(key=os.path.getmtime, reverse=True)
print("files:", [os.path.basename(x) for x in fs[:3]])
if fs:
    raw=open(fs[0],"rb").read()
    for off in (0,8,0x10):
        v=struct.unpack_from("<Q", raw, off)[0]
        ok = 0x10000 < v < 0x7FFF00000000 and (v & 7)==0
        print("  +0x%02X = 0x%-14X %s" % (off, v, "PTR" if ok else ""))
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    me=struct.unpack_from("<Q",f,56)[0]
    print("  (our handle-chain instance = 0x%X)" % me)
