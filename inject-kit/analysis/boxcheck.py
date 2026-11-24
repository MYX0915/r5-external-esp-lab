import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20); pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]
W,H=1920,1080
gameFov=110.0
def efffov(w,h):
    t=math.tan(math.radians(gameFov)/2); t*= (w/h)/(4/3)
    return math.degrees(2*math.atan(t))
fovh=efffov(W,H)
def w2s(p):
    pitch=math.radians(ang[0]); yaw=math.radians(ang[1])
    dx,dy,dz=p[0]-cam[0],p[1]-cam[1],p[2]-cam[2]
    fx=math.cos(pitch)*math.cos(yaw); fy=math.cos(pitch)*math.sin(yaw); fz=-math.sin(pitch)
    rx=math.sin(yaw); ry=-math.cos(yaw); rz=0.0
    ux=ry*fz-rz*fy; uy=rz*fx-rx*fz; uz=rx*fy-ry*fx
    z=dx*fx+dy*fy+dz*fz; x=dx*rx+dy*ry+dz*rz; y=dx*ux+dy*uy+dz*uz
    if z<=1: return None
    fl=(W/2)/math.tan(math.radians(fovh)/2)
    return (W/2+fl*x/z, H/2-fl*y/z)
print("pitch=%.2f yaw=%.2f  fov=%.1f  ??=(%d,%d)" % (ang[0],ang[1],fovh,W/2,H/2))
inside=False
for k in range(min(cnt,24)):
    e=struct.unpack_from("<3f",f,64+k*12)
    feet=(e[0],e[1],e[2]); head=(e[0],e[1],e[2]+72)
    a=w2s(feet); b=w2s(head)
    if not a or not b:
        print("  [%2d] ?????????" % k); continue
    bh=a[1]-b[1]; bw=max(6, bh*0.42)
    x0,x1=a[0]-bw/2, a[0]+bw/2; y0,y1=b[1],a[1]
    inc = (x0<=W/2<=x1) and (y0<=H/2<=y1)
    if inc: inside=True
    print("  [%2d] ? x[%.0f,%.0f] y[%.0f,%.0f]  ?????=%s" % (k,x0,x1,y0,y1,inc))
print("\n??: ??????? = %s" % inside)
