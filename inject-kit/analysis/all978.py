import numpy as np, glob, os, struct, collections
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
insts=[l.strip() for l in open("all869.txt") if l.strip()]
ok=0; byclass=collections.Counter(); samples=[]
for v in insts:
    hexv=v[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    t=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(t).all(): continue
    if abs(t[0])<1000 or abs(t[0])>40000: continue
    d=float(np.linalg.norm(np.array(t)-me))
    if d>3000: continue
    ok+=1
    vt=struct.unpack_from("<Q", raw, 0)[0]
    byclass[vt]+=1
    if len(samples)<6: samples.append((v,vt,t,d,fs[-1]))
print("entities with valid world triple at +0x978 within 3000 units: %d / %d" % (ok, len(insts)))
for v,vt,t,d,p in samples:
    print("   0x%-10s vt=0x%-14X (%.1f,%.1f,%.1f) dist=%.0f  [%s]" % (v,vt,t[0],t[1],t[2],d,os.path.basename(p)))
print("\nby class:")
for vt,c in byclass.most_common(6):
    print("   0x%X -> %d" % (vt,c))
