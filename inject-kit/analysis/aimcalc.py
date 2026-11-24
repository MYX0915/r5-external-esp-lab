import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32); cam=struct.unpack_from("<3f",f,8)
ang=struct.unpack_from("<3f",f,20)
cnt=struct.unpack_from("<I",f,44)[0]
g,t,v0=725.0,4.0,1490.0
print("?? pitch=%.2f yaw=%.2f" % (ang[0],ang[1]))
out=[]
for k in range(min(cnt,24)):
    e=struct.unpack_from("<3f",f,64+k*12)
    dx=e[0]-cam[0]; dy=e[1]-cam[1]; dz=e[2]-cam[2]
    D=math.hypot(dx,dy)
    if D<1: continue
    A=D/t; B=(dz+0.5*g*t*t)/t
    reqV=math.hypot(A,B)
    base=math.degrees(math.atan2(B,A))
    miss=(reqV-v0)*t*0.01905
    yaw=math.degrees(math.atan2(dy,dx))
    print("  [%d] D=%.1fm base=%.1f ? pitch=%.1f yaw=%.1f  reqV=%.0f miss=%+.1fm" % (
        k, D*0.01905, base, -base, yaw, reqV, miss))
    out.append("%d %.2f %.2f %.2f" % (k, D*0.01905, -base, yaw))
open("aimtab.txt","w").write("\n".join(out))
