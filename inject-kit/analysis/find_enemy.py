import struct, glob, os, numpy as np, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32)); ang=struct.unpack_from("<2f",f,20)
yaw=ang[1] % 360
addrs=[l.strip() for l in open(r"C:\ProgramData\sc_addr.txt") if l.strip() and l.startswith("0x")]
res=[]
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    pos=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(pos).all(): continue
    d=float(np.linalg.norm(np.array(pos)-me))
    if d<1 or d>20000: continue
    dx,dy=pos[0]-me[0], pos[1]-me[1]
    brg=math.degrees(math.atan2(dy,dx))
    rel=(brg-yaw+540)%360-180
    res.append((d,a,rel,pos))
res.sort()
print("me=(%.0f,%.0f,%.0f)  yaw=%.1f" % (me[0],me[1],me[2],yaw))
print("\n?????:")
for d,a,rel,pos in res[:8]:
    print("  %6.1fm  ?%+7.1f?  %s" % (d*0.01905, rel, a))
if res:
    open("target.json","w").write('{"addr":"%s","rel":%f,"dist":%f}' % (res[0][1], res[0][2], res[0][0]))
