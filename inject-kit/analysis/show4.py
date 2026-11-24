import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
for a in [l.strip() for l in open("targets4.txt") if l.strip()]:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: print(a,"no dump"); continue
    raw=open(fs[-1],"rb").read()
    p=struct.unpack_from("<3f", raw, 0x978)
    d=float(np.linalg.norm(np.array(p)-me))
    print("  %s  (%.0f,%.0f,%.0f)  %.1fm" % (a,p[0],p[1],p[2],d*0.01905))
