import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("me=(%.1f,%.1f,%.1f)\n" % (me[0],me[1],me[2]))
for b,stride,off in (("282FECE0",0x20,0x08),("282FD380",0x20,0x08)):
    base=int(b,16); hexv=b
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x800], key=os.path.getmtime)
    if not fs: print("0x%s ?dump" % b); continue
    raw=open(fs[-1],"rb").read()
    n=len(raw)//stride
    print("=== 0x%s  ?? %d (?? 0x%X, ?? +0x%02X) ===" % (b,n,stride,off))
    ds=[]
    for k in range(n):
        v=struct.unpack_from("<3f", raw, k*stride+off)
        d=float(np.linalg.norm(np.array(v)-me))
        ds.append(d)
        if k<10:
            print("  [%2d] (%.1f, %.1f, %.1f)  ? %.1f ?" % (k,v[0],v[1],v[2],d*0.01905))
    print("  ...  ????? %.1f ???? %.1f ?\n" % (min(ds)*0.01905, max(ds)*0.01905))
