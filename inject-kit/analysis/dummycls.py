import numpy as np, glob, os, struct, collections
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
print("me = (%.1f, %.1f, %.1f)\n" % tuple(me))
insts=[l.strip() for l in open("all869.txt") if l.strip()]
target=0x7FF779A69330
found=[]
classes=collections.Counter()
for v in insts:
    hexv=v[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    classes[vt]+=1
    if vt==target:
        t=struct.unpack_from("<3f", raw, 0x978)
        found.append((v,t,fs[-1]))
print("class 0x%X instances: %d" % (target, len(found)))
for v,t,p in found:
    if np.isfinite(t).all():
        d=float(np.linalg.norm(np.array(t)-me))
        print("   0x%-10s +0x978 = (%9.1f, %9.1f, %9.1f)  dist=%.0f" % (v,t[0],t[1],t[2],d))
print("\ntop classes overall:")
for vt,c in classes.most_common(6):
    print("   0x%-14X %d" % (vt,c))
