import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32)); myinst=struct.unpack_from("<Q",f,56)[0]
print("me inst=0x%X pos=(%.1f,%.1f,%.1f)" % (myinst,me[0],me[1],me[2]))
for line in open("spread40.txt"):
    hexv=line.split()[0][2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    raw=open(fs[0],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p=struct.unpack_from("<3f", raw, 0x376C)
    if np.isfinite(p).all() and abs(p[0])>1 and abs(p[0])<100000:
        d=float(np.linalg.norm(np.array(p)-me))
        print("  0x%-10s vt=0x%-14X pos=(%9.1f,%9.1f,%9.1f) dist=%7.0f  %s" %
              (hexv, vt, p[0],p[1],p[2], d, "<-- ME" if int(hexv,16)==myinst else ""))
