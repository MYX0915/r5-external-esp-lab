import struct, glob, os, numpy as np, collections
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
base=0xB9B5C0
hexv="B9B5C0"
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x400], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
S=0x40
n=len(raw)//S
print("me=(%.1f,%.1f,%.1f)  ???=%d\n" % (me[0],me[1],me[2],n))
# ?????????????????
cnt=collections.Counter()
for k in range(n):
    e=k*S
    for off in range(0,S-12+1,4):
        v=struct.unpack_from("<3f", raw, e+off)
        if abs(v[0])>100 and abs(v[0])<20000 and abs(v[1])<20000 and -500<v[2]<3000:
            cnt[off]+=1
print("???????????? -> ??????:")
for off,c in cnt.most_common(8):
    print("  +0x%02X  ? %d/%d ??????" % (off,c,n))
best=cnt.most_common(1)[0][0]
print("\n???? +0x%02X ??????:" % best)
for k in range(min(n,12)):
    v=struct.unpack_from("<3f", raw, k*S+best)
    d=float(np.linalg.norm(np.array(v)-me))
    print("  ??%-2d (%.1f, %.1f, %.1f)   ? %.1f ?" % (k, v[0],v[1],v[2], d*0.01905))
