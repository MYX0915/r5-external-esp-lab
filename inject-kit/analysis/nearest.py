import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
p=math.radians(ang[0]); y=math.radians(ang[1])
fw=(math.cos(p)*math.cos(y), math.cos(p)*math.sin(y), -math.sin(p))
print("cam=(%.1f,%.1f,%.1f)  ang=(%.2f,%.2f)" % (cam[0],cam[1],cam[2],ang[0],ang[1]))
print("forward=(%.4f,%.4f,%.4f)\n" % fw)
cnt=struct.unpack_from("<I",f,44)[0]
rows=[]
for i in range(cnt):
    e=struct.unpack_from("<3f", f, 64+i*12)
    dx=e[0]-cam[0]; dy=e[1]-cam[1]; dz=e[2]-cam[2]
    hd=math.hypot(dx,dy)
    if hd<1: continue
    bearing=math.degrees(math.atan2(dy,dx))
    elev=math.degrees(math.atan2(dz,hd))
    dot=(dx*fw[0]+dy*fw[1]+dz*fw[2])/math.sqrt(dx*dx+dy*dy+dz*dz)
    rows.append((hd,i,e,bearing,elev,math.degrees(math.acos(max(-1,min(1,dot))))))
rows.sort()
print("???????????:")
for hd,i,e,b,el,ang_off in rows[:8]:
    print("   ent[%2d] d=%6.0f ??=%8.1f? ??=%6.1f? ?????=%6.2f?  ??=(%.1f,%.1f,%.1f)" % (i,hd,b,el,ang_off,e[0],e[1],e[2]))
