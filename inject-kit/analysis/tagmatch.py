import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32)); cam=np.array(struct.unpack_from("<3f",f,8))
print("pos=(%.1f,%.1f,%.1f)" % (pos[0],pos[1],pos[2]))
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(p)>0x100000],
          key=os.path.getmtime, reverse=True)[:4]
for f2 in fs:
    a=np.fromfile(f2, dtype=np.uint64)
    tag=(a>>59)&0x1F
    low=(a & 0xFFFFFFFF).astype(np.uint32).view(np.float32)
    m=(tag==4)&np.isfinite(low)
    idx=np.nonzero(m)[0]
    vals=low[idx]
    for name,tgt in (("pos",pos),):
        for comp in range(3):
            d=np.abs(vals-tgt[comp])
            hit=np.nonzero(d<3.0)[0]
            if len(hit):
                print("  %-24s %s[%d]=%.1f  matches=%d at %s" % (os.path.basename(f2), name, comp, tgt[comp], len(hit), [hex(int(idx[h]*8)) for h in hit[:4]]))
