import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cnt=struct.unpack_from("<I",f,44)[0]
cam=struct.unpack_from("<3f",f,8); pos=struct.unpack_from("<3f",f,32)
print("count=%d" % cnt)
off=352
for k in range(min(cnt,24)):
    base=off+k*40
    if base+40>len(f): break
    hp,hpmax,sh,shmax=struct.unpack_from("<4I",f,base)
    team,life,nlen,flags=struct.unpack_from("<4B",f,base+16)
    e=struct.unpack_from("<3f",f,64+k*12)
    dx=e[0]-pos[0]; dy=e[1]-pos[1]; dz=e[2]-pos[2]
    d=(dx*dx+dy*dy+dz*dz)**0.5*0.01905
    print("  [%2d] %6.0fm flags=%d hp=%d/%d sh=%d/%d team=%d" % (k,d,flags,hp,hpmax,sh,shmax,team))
