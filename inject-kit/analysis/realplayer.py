import struct, glob, os, numpy as np
e=0xF1097EA0
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("??: (%.1f,%.1f,%.1f)" % (me[0],me[1],me[2]))
hexv="%X"%e
fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
p=struct.unpack_from("<3f",raw,0x978)
print("\n?? 0xF1097EA0  +0x978 = (%.2f, %.2f, %.2f)" % p)
d=float(np.linalg.norm(np.array(p)-me))
print("???: %.1f ?" % (d*0.01905))
print("\n?????????????:")
for off in range(0,0x1000-12,4):
    t=struct.unpack_from("<3f",raw,off)
    if not all(abs(v)<40000 for v in t): continue
    if not (200<abs(t[0])<20000 and abs(t[1])<20000 and -1000<t[2]<4000): continue
    dd=float(np.linalg.norm(np.array(t)-me))*0.01905
    print("  +0x%04X (%.1f,%.1f,%.1f) ??? %.1f ?" % (off,t[0],t[1],t[2],dd))
