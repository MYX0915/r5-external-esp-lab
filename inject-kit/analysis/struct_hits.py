import struct, glob, os
for a,label in ((0x4924DC8,"0x4924DC8"), (0xB48EC0,"0xB48EC0")):
    base=a-0x20; hexv="%X"%base
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x60], key=os.path.getmtime)
    if not fs: print("%s ?dump" % label); continue
    raw=open(fs[-1],"rb").read()
    print("=== %s ?????? +0x20?===" % label)
    for i in range(0,0x60,0x10):
        off=base+i
        q=struct.unpack_from("<Q",raw,i)[0]
        tag=""
        if 0x7FF600000000 <= q <= 0x7FFFFFFFFFFF: tag=" (??/????)"
        elif 0x10000 < q < 0x7FFF00000000 and (q&7)==0: tag=" (???)"
        print("  +0x%X 0x%016X%s" % (off,q,tag))
    print()
