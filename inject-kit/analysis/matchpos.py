import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
print("me=(%.1f,%.1f,%.1f)\n" % tuple(me))
line=[l for l in open(r"C:\ProgramData\sc_classes.txt") if "0x7FF68C7400E8" in l][0].split()
for a in line[3:6]:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if not fs: print("  %s: no dump" % a); continue
    raw=open(fs[-1],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p978=struct.unpack_from("<3f", raw, 0x978)
    p376=struct.unpack_from("<3f", raw, 0x376C)
    ok978 = np.isfinite(p978).all() and abs(p978[0])>100
    ok376 = np.isfinite(p376).all() and abs(p376[0])>100
    print("  %s vt=0x%X" % (a,vt))
    print("     +0x978 = %s  d=%s" % (("(%.1f,%.1f,%.1f)"%tuple(p978)) if ok978 else "zero/NaN",
          ("%.0f"%np.linalg.norm(np.array(p978)-me)) if ok978 else "-"))
    print("     +0x376C= %s" % (("(%.1f,%.1f,%.1f)"%tuple(p376)) if ok376 else "zero/NaN"))
