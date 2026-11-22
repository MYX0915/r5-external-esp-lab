import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
print("me = (%.1f, %.1f, %.1f)" % tuple(me))
for v in ("3B0A0030","2A34FD60","4209650"):
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%v) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    print("\n=== 0x%s  vtable=0x%X ===" % (v, vt))
    for off in (0x978, 0xEA0):
        if off+12 <= len(raw):
            t=struct.unpack_from("<3f", raw, off)
            if np.isfinite(t).all() and abs(t[0])>1:
                d=float(np.linalg.norm(np.array(t)-me))
                print("   +0x%03X vec3 = (%9.1f, %9.1f, %9.1f)   dist_to_me=%.0f" % (off,t[0],t[1],t[2],d))
