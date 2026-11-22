import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("player pos:", ["%.2f"%v for v in pos])
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(p)>0x100000],
          key=os.path.getmtime, reverse=True)[:6]
scales=[1,2,4,8,16,32,64,100]
for f2 in fs:
    a=np.fromfile(f2, dtype=np.uint64)
    low=(a & 0xFFFFFFFF).astype(np.uint32).view(np.int32)
    tag=(a>>59)&0x1F
    for s in scales:
        tgt=(pos*s).astype(np.int64)
        for comp in range(3):
            d=np.abs(low.astype(np.int64)-tgt[comp])
            hit=np.nonzero(d<=2)[0]
            if len(hit)>=2:
                print("  %-22s scale=%-3d comp=%d tgt=%d hits=%d at %s (tags=%s)" %
                      (os.path.basename(f2), s, comp, tgt[comp], len(hit),
                       [hex(int(i*8)) for i in hit[:3]], [int(tag[i]) for i in hit[:3]]))
