import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32); cam=struct.unpack_from("<3f",f,8)
cnt=struct.unpack_from("<I",f,44)[0]
print("??????:")
for k in range(min(cnt,6)):
    base=352+k*40
    hp,hpm,sh,shm=struct.unpack_from("<4I",f,base)
    e=struct.unpack_from("<3f",f,64+k*12)
    tz = e[2] + 40.0   # ????
    D=math.hypot(e[0]-cam[0], e[1]-cam[1])
    yaw=math.degrees(math.atan2(e[1]-cam[1], e[0]-cam[0]))
    pitch=math.degrees(math.atan2(-(tz-cam[2]), D))
    print("  [%d] hp=%d sh=%d D=%.1fm ? yaw=%.2f pitch=%.2f" % (k,hp,sh,D*0.01905,yaw,pitch))
    if k==0: open("aim0.txt","w").write("%.2f %.2f" % (pitch,yaw))
