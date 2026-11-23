import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
p=math.radians(ang[0]); y=math.radians(ang[1])
print("cam=(%.1f,%.1f,%.1f) ang=(%.2f,%.2f)" % (cam[0],cam[1],cam[2],ang[0],ang[1]))
print("??? forward = (%.4f, %.4f, %.4f)" % (math.cos(p)*math.cos(y), math.cos(p)*math.sin(y), -math.sin(p)))
rows=[]
for line in open(r"C:\ProgramData\sc_ents.txt"):
    parts=line.split()
    if len(parts)<5: continue
    try: x,zz=None,None; w=[float(v) for v in parts[2:5]]
    except: continue
    if not all(abs(v)>0.5 for v in w): continue
    dx=w[0]-cam[0]; dy=w[1]-cam[1]; dz=w[2]-cam[2]
    hd=math.hypot(dx,dy)
    if hd<1: continue
    bearing=math.degrees(math.atan2(dy,dx))
    elev=math.degrees(math.atan2(dz,hd))
    rows.append((hd,parts[0],w,bearing,elev))
rows.sort()
print("\n??????????")
for hd,a,w,b,e in rows:
    print("   %s  d=%6.0f  ??=%7.2f?  ??=%6.2f?  ??=(%.1f,%.1f,%.1f)" % (a,hd,b,e,w[0],w[1],w[2]))
