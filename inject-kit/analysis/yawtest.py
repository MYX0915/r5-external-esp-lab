import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
cnt=struct.unpack_from("<I",f,44)[0]
ents=[struct.unpack_from("<3f", f, 64+i*12) for i in range(cnt)]
W,H=2560,1440
def score(yaw_off_deg, pitch_sign=1, fov=110):
    pitch=math.radians(ang[0]*pitch_sign); yaw=math.radians(ang[1]+yaw_off_deg)
    fx=math.cos(pitch)*math.cos(yaw); fy=math.cos(pitch)*math.sin(yaw); fz=-math.sin(pitch)
    rx=math.sin(yaw); ry=-math.cos(yaw); rz=0.0
    ux=ry*fz-rz*fy; uy=rz*fx-rx*fz; uz=rx*fy-ry*fx
    fpx=(W/2)/math.tan(math.radians(fov)/2)
    ons=[]
    for e in ents:
        dx=e[0]-cam[0]; dy=e[1]-cam[1]; dz=e[2]-cam[2]
        z=dx*fx+dy*fy+dz*fz
        if z<=1: continue
        x=dx*rx+dy*ry+dz*rz
        y=dx*ux+dy*uy+dz*uz
        sx=W/2+fpx*x/z; sy=H/2-fpx*y/z
        if 0<=sx<=W and 0<=sy<=H: ons.append((sx,sy))
    return ons
for off in (0,90,-90,180):
    for ps in (1,-1):
        o=score(off,ps)
        print("yaw%+4d pitch%+d ? ?????? %d" % (off,ps,len(o)))
print()
best=score(0,1)
print("??????????:", [(round(a),round(b)) for a,b in best][:8])
