import struct, glob, os
for name,a in (("me", open("me2.txt").read().split()[0]), ("dummy","0x1CC432260")):
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x400], key=os.path.getmtime)
    if not fs: print("%s: no dump"%name); continue
    raw=open(fs[-1],"rb").read()
    g268=raw[0x268]; g26c=raw[0x26C]
    ctx=struct.unpack_from("<i", raw, 0x29C)[0]
    print("%-6s %s  +0x268=%d  +0x26C=%d  +0x29C(ctxID)=%d" % (name,a,g268,g26c,ctx))
