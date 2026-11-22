import numpy as np, glob, os, struct
# ??????? +0x170 ????????? +0x376C
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32)); myinst=struct.unpack_from("<Q",f,56)[0]
print("my pos=(%.1f,%.1f,%.1f) inst=0x%X" % (me[0],me[1],me[2],myinst))
n170=0; n376c=0; tot=0
for line in open("spread40.txt"):
    hexv=line.split()[0][2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    tot+=1
    raw=open(fs[0],"rb").read()
    p170=struct.unpack_from("<Q", raw, 0x170)[0]
    p=struct.unpack_from("<3f", raw, 0x376C)
    if 0x10000 < p170 < 0x7FFF00000000: n170+=1
    if np.isfinite(p).all() and abs(p[0])>1: n376c+=1
print("sampled=%d  with +0x170 ptr=%d  with +0x376C coord=%d" % (tot,n170,n376c))
