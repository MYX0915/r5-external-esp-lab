import struct, math, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20); pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]
print("pitch=%.2f yaw=%.2f  count=%d" % (ang[0],ang[1],cnt))
best=None
for k in range(min(cnt,24)):
    e=struct.unpack_from("<3f",f,64+k*12)
    hpm,sh,shm=0,0,0
    dx=e[0]-pos[0]; dy=e[1]-pos[1]; dz=e[2]-pos[2]
    D=math.hypot(dx,dy); d3=math.sqrt(dx*dx+dy*dy+dz*dz)*0.01905
    if D<1: continue
    # ??
    g,t,v0=725.0,4.0,1500.0
    A=D/t; B=(dz+0.5*g*t*t)/t
    reqV=math.hypot(A,B)
    if reqV>v0: continue
    base=math.degrees(math.atan2(B,A)); phi=math.degrees(math.acos(min(1,reqV/v0)))
    lo,hi=base-phi,base+phi
    use = hi if hi<=89 else (lo if lo<=89 else None)
    if use is None: continue
    print("  [%2d] D=%.1fm dz=%.0f reqV=%.0f LOW=%.1f HIGH=%.1f use=%.1f" % (k,D*0.01905,dz,reqV,lo,hi,use))
    if best is None or D<best[0]: best=(D,k,use)
if best:
    print("\n??: slot %d  D=%.1fm  ? pitch=%.1f" % (best[1], best[0]*0.01905, -best[2]))
    open("nade_target.txt","w").write("%d %.2f" % (best[1], -best[2]))
