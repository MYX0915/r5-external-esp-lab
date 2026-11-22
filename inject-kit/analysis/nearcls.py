import numpy as np, glob, os, struct, collections
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",f,8)); pos=np.array(struct.unpack_from("<3f",f,32))
print("cam=(%.0f,%.0f,%.0f) pos=(%.0f,%.0f,%.0f)" % (cam[0],cam[1],cam[2],pos[0],pos[1],pos[2]))
near=collections.Counter(); rows=[]
for line in open("cur.txt"):
    hexv=line.strip()[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    for off in (0x978, 0x376C):
        t=struct.unpack_from("<3f", raw, off)
        if not np.isfinite(t).all(): continue
        if abs(t[0])<100 or abs(t[0])>40000 or abs(t[1])>40000 or abs(t[2])>40000: continue
        d=float(np.linalg.norm(np.array(t)-cam))
        if d<3000:
            near[vt]+=1
            rows.append((d,hexv,vt,off,t))
            break
rows.sort()
print("entities within 3000 units: %d" % len(rows))
for d,v,vt,off,t in rows[:12]:
    print("   %6.0fm 0x%-10s vt=0x%-14X @+0x%03X (%.0f,%.0f,%.0f)" % (d,v,vt,off,t[0],t[1],t[2]))
print("\nclasses among them:")
for vt,c in near.most_common(5): print("   0x%X -> %d" % (vt,c))
