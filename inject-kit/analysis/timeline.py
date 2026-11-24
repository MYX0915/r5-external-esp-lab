import glob, os, collections, datetime
import numpy as np
files=glob.glob(r"C:\ProgramData\scdump\*.bin")
tl=collections.defaultdict(lambda: [0,0])   # minute -> [valid, invalid]
sizes=collections.defaultdict(lambda: [0,0])
for f in files:
    try: d=np.fromfile(f,dtype=np.uint8)
    except Exception: continue
    if len(d)<16: continue
    ok = bool(d[:min(256,len(d))].any())
    t=datetime.datetime.fromtimestamp(os.path.getmtime(f)).strftime('%H:%M')
    tl[t][0 if ok else 1]+=1
    sz=os.path.getsize(f)
    if sz in (0x800,0x1000,0x2000):
        sizes[sz][0 if ok else 1]+=1
print("???????? / ???:")
for t in sorted(tl):
    v,z=tl[t]
    bar="#"*min(40,v//3)
    print("   %s  ?? %4d  ?? %4d  %s" % (t,v,z,bar))
print("\n????????:")
for sz in sorted(sizes):
    v,z=sizes[sz]
    tot=v+z
    print("   0x%-5X ?? %4d / %4d = %.1f%%" % (sz,v,tot,100.0*v/tot))
