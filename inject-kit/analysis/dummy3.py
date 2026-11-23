import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
lines=[l for l in open(r"C:\ProgramData\sc_classes.txt") if "0x7FF68C769330" in l]
if not lines: print("class not present"); raise SystemExit
addrs=lines[0].split()[3:6]
print("me=(%.0f,%.0f,%.0f)" % tuple(me))
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=os.path.getmtime)
    if not fs: print("  %s: no dump" % a); continue
    raw=open(fs[-1],"rb").read()
    p=struct.unpack_from("<3f", raw, 0x978)
    d=float(np.linalg.norm(np.array(p)-me)) if np.isfinite(p).all() else -1
    print("  %s  +0x978=(%9.1f,%9.1f,%9.1f)  d=%.0f" % (a,p[0],p[1],p[2],d))
