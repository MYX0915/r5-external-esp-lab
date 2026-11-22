import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32))
x,y,z=float(pos[0]),float(pos[1]),float(pos[2])
print("player pos=(%.2f,%.2f,%.2f)" % (x,y,z))
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(p)>0x100000],
          key=os.path.getmtime, reverse=True)[:8]
trip=[]
for f2 in fs:
    a=np.fromfile(f2, dtype=np.float32)
    idx=np.nonzero(np.abs(a-x)<8.0)[0]
    for i in idx:
        if i+2 < len(a):
            seg=a[i:i+3]
            if np.isfinite(seg).all():
                d=np.abs(seg-np.array([x,y,z]))
                trip.append((os.path.basename(f2), int(i*4), seg.copy(), d.sum()))
trip.sort(key=lambda t:t[3])
print("float x-matches:", len(trip))
for nm,off,seg,d in trip[:8]:
    print("   %-22s +0x%06X  (%.2f, %.2f, %.2f)  diff=%.2f" % (nm,off,seg[0],seg[1],seg[2],d))
