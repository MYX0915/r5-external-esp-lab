import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
cands=[l.split() for l in open("arrcands.txt") if l.strip()]
print("me=(%.0f,%.0f,%.0f)  ?? %d\n" % (me[0],me[1],me[2],len(cands)))
def score(raw, stride):
    n=len(raw)//stride
    best=(0,0)
    for off in range(0, stride-12+1, 4):
        run=0; mx=0
        for k in range(n):
            v=struct.unpack_from("<3f", raw, k*stride+off)
            ok = abs(v[0])>100 and abs(v[0])<20000 and abs(v[1])<20000 and -500<v[2]<3000
            if ok: run+=1; mx=max(mx,run)
            else: run=0
        if mx>best[1]: best=(off,mx)
    return best[0], best[1], n
results=[]
for row in cands:
    st, base = row[0], row[1]
    stride=int(st,16); b=int(base,16); hexv="%X"%b
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x400], key=os.path.getmtime)
    if not fs: continue
    off,mx,n = score(open(fs[-1],"rb").read(), stride)
    results.append((mx, st, base, off, n))
results.sort(reverse=True)
print("??????:")
for mx,st,base,off,n in results[:12]:
    print("  ??%-5s %-12s ??+0x%02X  ?? %2d/%d" % (st,base,off,mx,n))
