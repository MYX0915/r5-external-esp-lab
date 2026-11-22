import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
print("me = (%.1f, %.1f, %.1f)" % tuple(me))
insts=[l.strip() for l in open("all869.txt") if l.strip()]
res=[]
for v in insts:
    hexv=v[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if len(fs)<2: continue
    a=np.fromfile(fs[-2],dtype=np.float32); b=np.fromfile(fs[-1],dtype=np.float32)
    n=min(len(a),len(b))
    with np.errstate(invalid="ignore"):
        d=np.abs(a[:n]-b[:n])
        near=(np.abs(a[:n]-me[0])<3000)|(np.abs(b[:n]-me[0])<3000)
        m=np.isfinite(d)&(d>0.1)&(d<2000)&near&(np.abs(a[:n])>1000)&(np.abs(b[:n])>1000)
    idx=np.nonzero(m)[0]
    if len(idx):
        res.append((len(idx), v, [(int(i*4),float(a[i]),float(b[i])) for i in idx[:4]]))
res.sort(reverse=True)
print("entities changing near my x: %d" % len(res))
for c,v,det in res[:8]:
    print("  %s c=%d" % (v,c))
    for off,x,y in det: print("      +0x%05X  %.1f -> %.1f" % (off,x,y))
