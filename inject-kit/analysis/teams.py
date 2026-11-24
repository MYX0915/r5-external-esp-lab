import struct, glob, os, numpy as np, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32)); ang=struct.unpack_from("<2f",f,20)
yaw=ang[1] % 360
addrs=[l.strip() for l in open(r"C:\ProgramData\sc_addr.txt") if l.strip() and l.startswith("0x")]
res=[]
for a in addrs:
    e=int(a,16); hexv="%X"%(e+0x334)
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x4], key=os.path.getmtime)
    if not fs: continue
    team=struct.unpack_from("<i", open(fs[-1],"rb").read(),0)[0]
    hexv2="%X"%e
    fs2=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv2) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs2: continue
    raw=open(fs2[-1],"rb").read()
    pos=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(pos).all(): continue
    d=float(np.linalg.norm(np.array(pos)-me))
    if d<1: continue
    dx,dy=pos[0]-me[0], pos[1]-me[1]
    brg=math.degrees(math.atan2(dy,dx))
    res.append((team,d,a,brg,pos))
res.sort(key=lambda x:x[1])
print("me team=0  yaw=%.1f\n" % yaw)
print("????:")
for t,d,a,brg,pos in res[:12]:
    tag = "??" if t!=0 else "??/??"
    print("  team=%2d  %6.1fm  %s  %s  ??=%.1f" % (t, d*0.01905, a, tag, brg))
