import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32); inst=struct.unpack_from("<Q",f,56)[0]
print("player pos=(%.1f,%.1f,%.1f) inst=0x%X" % (pos[0],pos[1],pos[2],inst))
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%X.bin"%inst) if os.path.getsize(p)>=0x2000]
raw=open(max(fs,key=os.path.getmtime),"rb").read()
q=np.frombuffer(raw, dtype=np.uint64)
tag = (q >> 59) & 0x1F
flo = (q & 0xFFFFFFFF).view(np.uint32).view(np.float32) if False else None
low = (q & 0xFFFFFFFF).astype(np.uint32).view(np.float32)
mask = (tag == 4) & np.isfinite(low) & (np.abs(low) < 20000) & (np.abs(low) > 1)
idx = np.nonzero(mask)[0]
print("qwords with tag==4 and plausible float in low32: %d" % len(idx))
hits=[]
for i in idx:
    v=float(low[i])
    d=min(abs(v-pos[0]),abs(v-pos[1]),abs(v-pos[2]))
    if d < 50: hits.append((i*8, v, d))
print("matching own position components:", len(hits))
for off,v,d in hits[:8]:
    print("   +0x%05X  %.2f  (diff %.2f)" % (off,v,d))
