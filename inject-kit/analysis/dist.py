import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); pos=struct.unpack_from("<3f",f,32)
ang=struct.unpack_from("<3f",f,20)
cnt=struct.unpack_from("<I",f,44)[0]
print("cam=(%.0f,%.0f,%.0f) ang=(%.1f,%.1f)" % (cam[0],cam[1],cam[2],ang[0],ang[1]))
print("count=%d" % cnt)
W,H=1920,1080
pitch=math.radians(ang[0]); yaw=math.radians(ang[1])
fx=math.cos(pitch)*math.cos(yaw); fy=math.cos(pitch)*math.sin(yaw); fz=-math.sin(pitch)
rx=math.sin(yaw); ry=-math.cos(yaw); rz=0.0
ux=ry*fz-rz*fy; uy=rz*fx-rx*fz; uz=rx*fy-ry*fx
fpx=(W/2)/math.tan(math.radians(110)/2)
print("\n?????? / ???? / ??(??)")
for i in range(min(cnt,12)):
    e=struct.unpack_from("<3f", f, 64+i*12)
    d=math.dist(e,pos)
    dx=e[0]-cam[0]; dy=e[1]-cam[1]; dz=e[2]-cam[2]
    z=dx*fx+dy*fy+dz*fz
    x=dx*rx+dy*ry+dz*rz
    y=dx*ux+dy*uy+dz*uz
    if z<=1: print("   ent[%2d] d=%6.0f  z<0 (??)" % (i,d)); continue
    sx=W/2+fpx*x/z; sy=H/2-fpx*y/z
    # ?? +75 ??
    t=(e[0],e[1],e[2]+75)
    dx2=t[0]-cam[0]; dy2=t[1]-cam[1]; dz2=t[2]-cam[2]
    z2=dx2*fx+dy2*fy+dz2*fz; x2=dx2*rx+dy2*ry+dz2*rz; y2=dx2*ux+dy2*uy+dz2*uz
    sy2=H/2-fpx*y2/z2 if z2>1 else sy
    hgt=sy-sy2
    print("   ent[%2d] d=%6.0f (%6.0fm)  screen=(%5.0f,%5.0f)  ??=%.1fpx %s" % (i,d,d*0.01905,sx,sy,hgt,"? ?????" if hgt<10 else ""))
