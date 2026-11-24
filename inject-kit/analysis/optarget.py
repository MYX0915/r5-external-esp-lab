import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32); ang=struct.unpack_from("<3f",f,20)
cnt=struct.unpack_from("<I",f,44)[0]
g,t,v0=725.0,4.0,1600.0
print("pitch=%.2f yaw=%.2f count=%d" % (ang[0],ang[1],cnt))
best=None
for k in range(min(cnt,24)):
    e=struct.unpack_from("<3f",f,64+k*12)
    D=math.hypot(e[0]-pos[0], e[1]-pos[1]); dz=e[2]-pos[2]
    if D<1: continue
    A=D/t; B=(dz+0.5*g*t*t)/t
    reqV=math.hypot(A,B)
    base=math.degrees(math.atan2(B,A))
    if reqV>v0:
        print("  [%2d] D=%.1fm reqV=%.0f > %.0f  ? MAXRANGE base=%.1f" % (k,D*0.01905,reqV,v0,-base))
        cand=(-base, D, k, 3)
    else:
        phi=math.degrees(math.acos(min(1,reqV/v0)))
        lo,hi=base-phi,base+phi
        mode = 2 if hi<=89 else (1 if lo<=89 else 0)
        use = hi if mode==2 else lo
        print("  [%2d] D=%.1fm reqV=%.0f HIGH=%.1f LOW=%.1f ? mode=%d ??pitch=%.1f" % (
            k,D*0.01905,reqV,-hi,-lo,mode,-use))
        cand=(-use, D, k, mode)
    yawt=math.degrees(math.atan2(e[1]-pos[1], e[0]-pos[0]))
    if best is None or D<best[1]:
        best=(cand[0], D, k, cand[3], yawt, e)
if best:
    print("\n??: slot %d  D=%.1fm  ??pitch=%.1f  ??yaw=%.1f" % (best[2],best[1]*0.01905,best[0],best[4]))
    open("op_target.txt","w").write("%.2f %.2f" % (best[0], best[4]))
