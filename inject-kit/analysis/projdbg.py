import struct, math, time
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
kh=struct.unpack_from("<I",f,48)[0]
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]
print("ok=%d count=%d" % (kh,cnt))
print("cam =(%.1f,%.1f,%.1f)" % cam)
print("ang =(%.2f,%.2f,%.2f)" % ang)
print("pos =(%.1f,%.1f,%.1f)" % pos)
pitch=math.radians(ang[0]); yaw=math.radians(ang[1])
fx=math.cos(pitch)*math.cos(yaw); fy=math.cos(pitch)*math.sin(yaw); fz=-math.sin(pitch)
rx=math.sin(yaw); ry=-math.cos(yaw); rz=0.0
ux=ry*fz-rz*fy; uy=rz*fx-rx*fz; uz=rx*fy-ry*fx
print("forward=(%.3f,%.3f,%.3f) right=(%.3f,%.3f,%.3f) up=(%.3f,%.3f,%.3f)" % (fx,fy,fz,rx,ry,rz,ux,uy,uz))
print("\n??????????? (x?, y?, z?):")
for i in range(min(cnt,12)):
    e=struct.unpack_from("<3f", f, 64+i*12)
    dx=e[0]-cam[0]; dy=e[1]-cam[1]; dz=e[2]-cam[2]
    z=dx*fx+dy*fy+dz*fz
    x=dx*rx+dy*ry+dz*rz
    y=dx*ux+dy*uy+dz*uz
    tag = "??" if z>1 else "z<0 ???"
    print("   ent[%2d] x=%9.1f y=%9.1f z=%9.1f  %s" % (i,x,y,z,tag))
