import struct, glob, os, numpy as np
line=[l for l in open(r"C:\ProgramData\sc_classes.txt") if "0x7FF68C75C678" in l][0].split()
addrs=line[3:6]
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
print("me=(%.0f,%.0f,%.0f)" % tuple(me))
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=os.path.getmtime)
    if not fs: print("  %s: no dump" % a); continue
    raw=open(fs[-1],"rb").read()
    p978=struct.unpack_from("<3f", raw, 0x978)
    pdd0=struct.unpack_from("<Q", raw, 0xDD0)[0]
    d = float(np.linalg.norm(np.array(p978)-me)) if np.isfinite(p978).all() else -1
    print("  %s  +0x978=(%9.1f,%9.1f,%9.1f) d=%.0f   +0xDD0=0x%X" % (a,p978[0],p978[1],p978[2],d,pdd0))
