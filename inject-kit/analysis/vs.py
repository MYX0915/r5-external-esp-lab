import numpy as np, math
raw=open(r"C:\ProgramData\scdump\11_1C10D7110.bin","rb").read()
pos=np.frombuffer(raw[0x1F78:0x1F78+12],dtype=np.float32)
ang=np.frombuffer(raw[0x1F84:0x1F84+12],dtype=np.float32)
eye_pos=np.frombuffer(raw[0x376C:0x376C+12],dtype=np.float32)
print("pos   =", pos)
print("angles=", ang, "(pitch,yaw,roll)")
print("eye?  =", eye_pos)

pitch,yaw = math.radians(ang[0]), math.radians(ang[1])
# camera basis (Source convention: yaw around Z, pitch around Y)
fwd=np.array([math.cos(pitch)*math.cos(yaw), math.cos(pitch)*math.sin(yaw), -math.sin(pitch)])
right=np.array([math.sin(yaw), -math.cos(yaw), 0.0])
up=np.cross(right,fwd)

def project(p, eye, w=1920, h=1080, fov=90.0):
    d=np.array(p)-eye
    x=d@right; y=d@up; z=d@fwd
    if z<=0.1: return None
    f=(w/2)/math.tan(math.radians(fov)/2)
    return (w/2 + f*x/z, h/2 - f*y/z, z)

for name,eye in (("pos+64",pos+np.array([0,0,64.0])), ("eye376C",eye_pos)):
    r=project(pos, eye)
    print(f"  camera={name:8s} -> feet project {r}")
    if r: print(f"      normalized: x={r[0]/1920:.3f} y={r[1]/1080:.3f}  dist={r[2]:.1f}")
