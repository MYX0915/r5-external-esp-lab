import numpy as np, glob, os
D=r"C:\ProgramData\scdump"
rows=[]
for f in sorted(glob.glob(os.path.join(D,"15_*.bin"))):
    va=int(os.path.basename(f).split("_")[1].split(".")[0],16)
    raw=np.fromfile(f,dtype=np.uint8)
    if len(raw) < 0x1F84: continue
    pos=np.frombuffer(raw[0x1F78:0x1F78+12],dtype=np.float32)
    ang=np.frombuffer(raw[0x1F84:0x1F84+8],dtype=np.float32)
    ok=np.isfinite(pos).all() and (abs(pos[0])<9000) and (abs(pos[1])<9000) and (abs(pos[0])+abs(pos[1])>1)
    rows.append((va,ok,pos,ang))
hits=[r for r in rows if r[1]]
print("objects with a valid position at +0x1F78: %d / %d" % (len(hits), len(rows)))
for va,ok,pos,ang in hits[:15]:
    print("  0x%-11X pos=(%8.1f,%8.1f,%8.1f) ang=(%7.2f,%7.2f)" % (va,pos[0],pos[1],pos[2],ang[0],ang[1]))
