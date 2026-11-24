import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]
g,t=725.0,4.0
for v0 in (1400,1450,1485,1500,1550):
    print("V=%d:" % v0, end=" ")
    for k in range(min(cnt,24)):
        e=struct.unpack_from("<3f",f,64+k*12)
        D=math.hypot(e[0]-pos[0], e[1]-pos[1]); dz=e[2]-pos[2]
        if D<1: continue
        A=D/t; B=(dz+0.5*g*t*t)/t
        reqV=math.hypot(A,B)
        miss=(reqV-v0)*t*0.01905
        print("%.0fm:reqV=%.0f miss=%+.1f" % (D*0.01905,reqV,miss), end="  ")
    print()
print("\n??: miss ???????????????????")
