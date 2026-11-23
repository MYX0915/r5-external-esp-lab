import struct, time
for _ in range(30):
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    if struct.unpack_from("<I",f,48)[0]: break
    time.sleep(0.2)
cnt=struct.unpack_from("<I",f,44)[0]
cam=struct.unpack_from("<3f",f,8); pos=struct.unpack_from("<3f",f,32)
print("count=%d cam=(%.0f,%.0f,%.0f) pos=(%.0f,%.0f,%.0f)" % (cnt,cam[0],cam[1],cam[2],pos[0],pos[1],pos[2]))
import math
for i in range(min(cnt,24)):
    e=struct.unpack_from("<3f", f, 64+i*12)
    d=math.dist(e,pos)
    print("   ent[%2d] (%9.1f,%9.1f,%9.1f)  dist=%.0f (%.0fm)" % (i,e[0],e[1],e[2],d,d*0.01905))
