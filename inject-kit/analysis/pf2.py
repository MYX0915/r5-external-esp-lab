import numpy as np, glob, os, struct, math, time
def read_feed(tries=30):
    for _ in range(tries):
        try:
            raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
            if len(raw)>=68:
                ok=struct.unpack_from("<I",raw,64)[0]
                if ok:
                    cam=np.array(struct.unpack_from("<3f",raw,8))
                    ang=struct.unpack_from("<3f",raw,20)
                    if np.isfinite(cam).all() and abs(cam).sum()>1: return cam,ang
        except Exception: pass
        time.sleep(0.1)
    return None,None
cam,ang=read_feed()
print("cam=",None if cam is None else ["%.1f"%v for v in cam]," ang=",ang)
if cam is not None:
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
        out=[]
        for i in range(0,len(a)-3):
            v=a[i:i+3]
            if not np.isfinite(v).all(): continue
            dist=float(np.linalg.norm(v-cam))
            if dist<10 or dist>3000: continue
            r=proj(v)
            if not r: continue
            if 0<=r[0]<=1920 and 0<=r[1]<=1080: out.append((i*4,v.copy(),dist,r))
        print("%-20s candidates=%d" % (os.path.basename(f), len(out)))
        for off,v,dist,r in out[:3]:
            print("     +0x%05X (%8.1f,%8.1f,%8.1f) d=%6.1f screen=(%5.0f,%5.0f)" % (off,v[0],v[1],v[2],dist,r[0],r[1]))
