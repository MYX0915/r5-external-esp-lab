import struct, glob, os
me=0xF702D940
other=0x1293AE950
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32)
print("feed ??: (%.2f,%.2f,%.2f)" % pos)
for name,base in (("??",me),("??B",other)):
    va=base+0x3000; hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: print("  %s ?dump" % name); continue
    raw=open(fs[-1],"rb").read()
    print("\n%s (0x%X) +0x3000 ?:" % (name,base))
    for off in range(0,0x1000,0x40):
        t=struct.unpack_from("<3f",raw,off)
        if all(abs(v)<40000 for v in t) and any(abs(v)>100 for v in t):
            print("   +0x%04X  (%.2f, %.2f, %.2f)" % (0x3000+off, t[0],t[1],t[2]))
