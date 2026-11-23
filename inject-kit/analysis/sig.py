import numpy as np, glob, os, struct
# ???????? dump
cands=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x4000]
cands.sort(key=os.path.getmtime, reverse=True)
print("recent 0x4000 dumps:", len(cands))
found=0
for p in cands[:80]:
    raw=open(p,"rb").read()
    a=np.frombuffer(raw, dtype=np.int32)
    for off in range(0x40, min(len(a)-0x24, 0x2000)):
        h=a[off]
        if not (1 <= h <= 1000): continue
        # ???health
        t=a[off+4]      # +0x10 bytes = +4 ints
        if not (0 <= t <= 4): continue
        s=a[off+7]      # +0x1C bytes = +7 ints
        if not (0 <= s <= 64): continue
        mh=a[off+0x4C]
        if not (1 <= mh <= 2000): continue
        print("  %s  +0x%03X health=%d team=%d squad=%d maxHealth=%d" % (
            os.path.basename(p), off*4, h, t, s, mh))
        found+=1
        break
    if found>=6: break
if not found: print("  (no health-like signature in first 0x2000)")
