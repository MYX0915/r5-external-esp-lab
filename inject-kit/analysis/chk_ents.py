import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
lines=[l.split() for l in open(r"C:\ProgramData\sc_ents.txt") if l.strip()]
for p in lines[:5]:
    a=p[0]; hexv=a[2:]
    fs=sorted([q for q in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(q)>=0x1000], key=os.path.getmtime)
    if not fs: print(a,"no dump"); continue
    raw=open(fs[-1],"rb").read()
    pos=struct.unpack_from("<3f", raw, 0x978)
    d=float(np.linalg.norm(np.array(pos)-me)) if np.isfinite(pos).all() else -1
    print("  %s  +0x978=(%.1f,%.1f,%.1f) ??=%.0f??" % (a,pos[0],pos[1],pos[2],d))
