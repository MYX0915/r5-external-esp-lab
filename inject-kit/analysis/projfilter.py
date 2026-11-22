import numpy as np, glob, os, struct, math
feed=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",feed,8))
ang=struct.unpack_from("<3f",feed,20)
print("cam=",["%.1f"%v for v in cam]," ang=",["%.2f"%v for v in ang])
pitch,yaw=math.radians(ang[0]),math.radians(ang[1])
fx,fy,fz=math.cos(pitch)*math.cos(yaw), math.cos(pitch)*math.sin(yaw), -math.sin(pitch)
rx,ry,rz=math.sin(yaw),-math.cos(yaw),0.0
ux,uy,uz=ry*fz-rz*fy, rz*fx-rx*fz, rx*fy-ry*fx
def proj(p,w=1920,h=1080,fov=90.0):
    d=np.array(p)-cam
    x=d@np.array([rx,ry,rz]); y=d@np.array([ux,uy,uz]); z=d@np.array([fx,fy,fz])
    if z<=1: return None
    f=(w/2)/math.tan(math.radians(fov)/2)
    return (w/2+f*x/z, h/2-f*y/z, z)
for f in sorted(glob.glob(r"C:\ProgramData\scdump\13_*.bin"))[:6]:
    if os.path.getsize(f)<0x1000: continue
    a=np.fromfile(f,dtype=np.float32)
    print("=== %s ===" % os.path.basename(f))
    found=0
    for i in range(0,len(a)-3,1):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        dist=np.linalg.norm(v-cam)
        if dist<5 or dist>4000: continue
        r=proj(v)
        if not r: continue
        if 0<=r[0]<=1920 and 0<=r[1]<=1080:
            print("   +0x%05X (%8.1f,%8.1f,%8.1f) dist=%7.1f screen=(%5.0f,%5.0f)" % (i*4,v[0],v[1],v[2],dist,r[0],r[1]))
            found+=1
            if found>=4: break
    if found==0: print("   none")
