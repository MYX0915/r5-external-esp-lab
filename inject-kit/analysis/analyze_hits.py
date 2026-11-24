import struct, glob, os, numpy as np, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
cam=np.array(struct.unpack_from("<3f",f,8))
hits=[l.strip() for l in open(r"C:\ProgramData\sc_hits.txt") if l.startswith("0x")]
res=[]
for h in hits:
    e=int(h,16); hexv="%X"%e
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0xC], key=os.path.getmtime)
    if not fs: continue
    v=np.array(struct.unpack_from("<3f", open(fs[-1],"rb").read(),0))
    if not np.isfinite(v).all(): continue
    d_me=float(np.linalg.norm(v-me)); d_cam=float(np.linalg.norm(v-cam))
    res.append((min(d_me,d_cam), h, v, d_me, d_cam))
res.sort()
print("me=(%.1f,%.1f,%.1f)  cam=(%.1f,%.1f,%.1f)\n" % (me[0],me[1],me[2],cam[0],cam[1],cam[2]))
print("??????????:")
seen=[]
for d,h,v,dm,dc in res:
    key=tuple(round(x,1) for x in v)
    if key in seen: continue
    seen.append(key)
    tag = "???" if dc<1 else ("??" if dm<1 else "??")
    print("  %6.2f?  %-12s (%.2f, %.2f, %.2f)  %s" % (d*0.01905, h, v[0],v[1],v[2], tag))
    if len(seen)>=15: break
