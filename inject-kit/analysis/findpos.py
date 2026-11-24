import struct, glob, os, numpy as np, collections
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
insts=[l.strip() for l in open("allinst.txt") if l.strip()]
ofs_hits=collections.Counter()
cand=[]
for a in insts:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    arr=np.frombuffer(raw, dtype=np.float32)
    n=len(arr)//3*3
    T=arr[:n].reshape(-1,3).astype(np.float64)
    with np.errstate(invalid="ignore",over="ignore"):
        d=np.linalg.norm(T-me, axis=1)
        m=np.isfinite(d)&(d<250)   # 5 ??
    idx=np.nonzero(m)[0]
    for i in idx:
        ofs_hits[int(i)*4]+=1
        cand.append((float(d[i]),a,int(i)*4))
print("???????? 10?:")
for ofs,c in ofs_hits.most_common(10):
    print("   +0x%05X  %d ?" % (ofs,c))
cand.sort()
print("\n??? 10 ??????<5??:")
for d,a,ofs in cand[:10]:
    print("   %5.2f m  %s  offset=+0x%X" % (d*0.01905,a,ofs))
