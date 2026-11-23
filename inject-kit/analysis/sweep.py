import struct, math, itertools
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
cnt=struct.unpack_from("<I",f,44)[0]
ents=[struct.unpack_from("<3f", f, 64+i*12) for i in range(cnt)]
W,H=1920,1080
print("cam=(%.0f,%.0f,%.0f) ang=(%.1f,%.1f) n=%d" % (cam[0],cam[1],cam[2],ang[0],ang[1],cnt))
best=[]
for yaw_off in (0,90,-90,180):
    for ps in (1,-1):
        for fov in (90,100,110,120,130):
            pitch=math.radians(ang[0]*ps); yaw=math.radians(ang[1]+yaw_off)
            fx=math.cos(pitch)*math.cos(yaw); fy=math.cos(pitch)*math.sin(yaw); fz=-math.sin(pitch)
            rx=math.sin(yaw); ry=-math.cos(yaw); rz=0.0
            ux=ry*fz-rz*fy; uy=rz*fx-rx*fz; uz=rx*fy-ry*fx
            fpx=(W/2)/math.tan(math.radians(fov)/2)
            on=0
            for e in ents:
                dx=e[0]-cam[0]; dy=e[1]-cam[1]; dz=e[2]-cam[2]
                z=dx*fx+dy*fy+dz*fz
                if z<=1: continue
                x=dx*rx+dy*ry+dz*rz; y=dx*ux+dy*uy+dz*uz
                sx=W/2+fpx*x/z; sy=H/2-fpx*y/z
                if -200<=sx<=W+200 and -200<=sy<=H+200: on+=1
            best.append((on,yaw_off,ps,fov))
best.sort(reverse=True)
for b in best[:8]:
    print("  ???=%2d  yaw%+4d pitch%+d fov=%d" % b)
