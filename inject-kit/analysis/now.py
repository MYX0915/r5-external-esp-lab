import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32); ang=struct.unpack_from("<3f",f,20)
cnt=struct.unpack_from("<I",f,44)[0]; ok=struct.unpack_from("<I",f,48)[0]
inst=struct.unpack_from("<Q",f,56)[0]
print("ok=%d count=%d inst=0x%X" % (ok,cnt,inst))
print("pos=(%.1f,%.1f,%.1f) ang=(%.1f,%.1f)" % (pos[0],pos[1],pos[2],ang[0],ang[1]))
for k in range(min(cnt,24)):
    base=352+k*40
    hp,hpm,sh,shm=struct.unpack_from("<4I",f,base)
    team,life,nlen,flags=struct.unpack_from("<4B",f,base+16)
    e=struct.unpack_from("<3f",f,64+k*12)
    d=math.sqrt((e[0]-pos[0])**2+(e[1]-pos[1])**2+(e[2]-pos[2])**2)*0.01905
    print("  [%2d] %6.1fm hp=%d team=%d" % (k,d,hp,team))
