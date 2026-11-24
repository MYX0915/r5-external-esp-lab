import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]
g,t=725.0,4.0
tgts=[]
for k in range(min(cnt,24)):
    e=struct.unpack_from("<3f",f,64+k*12)
    D=math.hypot(e[0]-pos[0], e[1]-pos[1]); dz=e[2]-pos[2]
    if D<1: continue
    tgts.append((D,dz))
print("?????????:")
for D,dz in tgts:
    A=D/t; B=(dz+0.5*g*t*t)/t
    print("  D=%.1fm dz=%+.0f  reqV=%.0f" % (D*0.01905, dz, math.hypot(A,B)))
print("\n??????????????HIGH<=89?:")
for v0 in (1450,1480,1500,1520,1550,1600):
    print("  V=%-5d " % v0, end="")
    ok=[]
    for D,dz in tgts:
        A=D/t; B=(dz+0.5*g*t*t)/t
        reqV=math.hypot(A,B)
        if reqV>v0: ok.append("-"); continue
        base=math.degrees(math.atan2(B,A)); phi=math.degrees(math.acos(min(1,reqV/v0)))
        ok.append("H" if base+phi<=89 else "L")
    print("  ".join(ok))
print("\n(H=????, L=????, -=??)")
