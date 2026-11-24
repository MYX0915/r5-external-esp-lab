import struct, glob, os, numpy as np
cands=[l.split() for l in open("arrcands.txt") if l.strip()]
def score(raw, stride):
    n=len(raw)//stride
    best=None
    for off in range(0, stride-12+1, 4):
        vals=[]
        run=0; mx=0; start=0; bestseg=None
        for k in range(n):
            v=struct.unpack_from("<3f", raw, k*stride+off)
            ok = abs(v[0])>100 and abs(v[0])<20000 and abs(v[1])<20000 and -500<v[2]<3000
            if ok:
                if run==0: start=k
                run+=1
                if run>mx: mx=run; bestseg=(start,run)
            else: run=0
        if bestseg is None: continue
        s,ln = bestseg
        seg=[struct.unpack_from("<3f", raw, (s+i)*stride+off) for i in range(ln)]
        arr=np.array(seg)
        # ??????x ? y ???? > 20
        var = float(np.std(arr[:,0])) + float(np.std(arr[:,1]))
        if var < 20.0: continue
        if best is None or ln>best[1]:
            best=(off, ln, var, s)
    return best
res=[]
for row in cands:
    st, base = row[0], row[1]
    stride=int(st,16); b=int(base,16); hexv="%X"%b
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x400], key=os.path.getmtime)
    if not fs: continue
    r=score(open(fs[-1],"rb").read(), stride)
    if r: res.append((r[1], st, base, r[0], r[2], r[3]))
res.sort(reverse=True)
print("??'?????'????:")
for ln,st,base,off,var,s in res[:12]:
    print("  ??%-5s %-12s ??+0x%02X ??%2d? ???%.0f ????%d" % (st,base,off,ln,var,s))
if not res: print("  ???????????????")
