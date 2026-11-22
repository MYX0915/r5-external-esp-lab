import numpy as np, glob, os, struct, math, time
def read_feed(tries=40):
    for _ in range(tries):
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=68 and struct.unpack_from("<I",raw,64)[0]:
            cam=np.array(struct.unpack_from("<3f",raw,8)); ang=struct.unpack_from("<3f",raw,20)
            if np.isfinite(cam).all() and abs(cam).sum()>1: return cam,ang
        time.sleep(0.1)
    return None,None
cam,ang=read_feed()
print("cam=",["%.1f"%v for v in cam]," ang=",["%.1f"%v for v in ang])
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
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\17_*.bin") if os.path.getsize(f)>0x1000]
print("fresh dumps:", len(fs))
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    out=[]
    for i in range(0,len(a)-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        dist=float(np.linalg.norm(v-cam))
        if dist<10 or dist>1500: continue
        r=proj(v)
        if r and 0<=r[0]<=1920 and 0<=r[1]<=1080: out.append((dist,i*4,v.copy(),r))
    out.sort()
    print("%-20s on-screen&<1500: %d" % (os.path.basename(f), len(out)))
    for dist,off,v,r in out[:3]:
        print("     +0x%05X (%8.1f,%8.1f,%8.1f) d=%6.1f screen=(%5.0f,%5.0f)" % (off,v[0],v[1],v[2],dist,r[0],r[1]))
