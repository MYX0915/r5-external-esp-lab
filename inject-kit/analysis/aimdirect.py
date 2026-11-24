import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32); cam=struct.unpack_from("<3f",f,8)
for k in range(3):
    base=352+k*40
    hp,hpm,sh,shm=struct.unpack_from("<4I",f,base)
    e=struct.unpack_from("<3f",f,64+k*12)
    yaw=math.degrees(math.atan2(e[1]-cam[1], e[0]-cam[0]))
    dz=e[2]-cam[2]; D=math.hypot(e[0]-cam[0],e[1]-cam[1])
    pitch=math.degrees(math.atan2(-dz, D))
    print("[%d] hp=%d sh=%d  D=%.1fm  aim yaw=%.1f pitch=%.1f" % (k,hp,sh,D*0.01905,yaw,pitch))
