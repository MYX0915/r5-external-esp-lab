import struct, glob, os, numpy as np, time
def feed():
    for _ in range(40):
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=68 and struct.unpack_from("<I",raw,64)[0]:
            cam=np.array(struct.unpack_from("<3f",raw,8))
            if np.isfinite(cam).all() and abs(cam).sum()>1: return cam
        time.sleep(0.1)
cam=feed(); print("camera =", ["%.1f"%v for v in cam])
fs=sorted(glob.glob(r"C:\ProgramData\scdump\vd*.bin"), key=os.path.getmtime, reverse=True)
print("vd dumps:", len(fs))
seen=set()
for f in fs:
    raw=open(f,"rb").read()
    if len(raw) < 0x3780: continue
    va=os.path.basename(f).split("_")[1].split(".")[0]
    if va in seen: continue
    seen.add(va)
    p=struct.unpack_from("<3f", raw, 0x376C)
    d=float(np.linalg.norm(np.array(p)-cam)) if np.isfinite(p).all() else -1
    print("  0x%-12s +0x376C=(%10.1f,%10.1f,%10.1f)  dist=%8.1f" % (va, p[0],p[1],p[2], d))
