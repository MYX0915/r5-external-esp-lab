import struct, glob, os
for d in [l.strip() for l in open("dummies3.txt") if l.strip()]:
    e=int(d,16); hexv="%X"%e
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
    if not fs: print("  %s ?dump" % d); continue
    vt=struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0]
    print("  %s  ?? = 0x%X" % (d,vt))
