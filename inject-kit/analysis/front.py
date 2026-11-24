import struct, glob, os, numpy as np, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32)); ang=struct.unpack_from("<2f",f,20)
yaw=math.degrees(ang[1]) % 360
addrs=[l.strip() for l in open(r"C:\ProgramData\sc_addr.txt") if l.strip()]
res=[]
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    pos=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(pos).all() or (abs(pos[0])<1 and abs(pos[1])<1): continue
    dx,dy=pos[0]-me[0], pos[1]-me[1]
    d=math.sqrt(dx*dx+dy*dy+(pos[2]-me[2])**2)
    brg=math.degrees(math.atan2(dy,dx))
    rel=(brg-yaw+540)%360-180
    res.append((abs(rel),d,a,rel,pos))
res.sort()
print("me=(%.0f,%.0f,%.0f) yaw=%.1f" % (me[0],me[1],me[2],yaw))
print("\n?????????|???| ?????:")
for ar,d,a,rel,pos in res[:5]:
    print("  ?%+6.1f?  %5.1fm  %s" % (rel, d*0.01905, a))
open("front.txt","w").write(res[0][2] if res else "")
