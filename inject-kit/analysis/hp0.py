import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32); ang=struct.unpack_from("<3f",f,20)
cnt=struct.unpack_from("<I",f,44)[0]
print("?? pos=(%.1f,%.1f,%.1f) pitch=%.2f yaw=%.2f" % (pos[0],pos[1],pos[2],ang[0],ang[1]))
print("%-4s %8s %8s %10s %10s" % ("slot","??m","???","hp","??"))
for k in range(min(cnt,24)):
    base=352+k*40
    hp,hpm,sh,shm=struct.unpack_from("<4I",f,base)
    team,life,nlen,flags=struct.unpack_from("<4B",f,base+16)
    nm=f[base+20:base+40].split(b'\x00')[0].decode('latin1','replace')
    e=struct.unpack_from("<3f",f,64+k*12)
    D=math.hypot(e[0]-pos[0], e[1]-pos[1])
    print("%-4d %8.1f %8.0f %10d %10d  %s" % (k, D*0.01905, e[2]-pos[2], hp, sh, nm))
