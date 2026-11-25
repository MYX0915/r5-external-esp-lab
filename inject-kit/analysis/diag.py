import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
magic,ver=struct.unpack_from("<II",f,0)
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20); pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]; ok=struct.unpack_from("<I",f,48)[0]
inst=struct.unpack_from("<Q",f,56)[0]
print("magic=0x%X ver=%d size=%d" % (magic,ver,len(f)))
print("ok=%d count=%d inst=0x%X" % (ok,cnt,inst))
print("cam=(%.1f,%.1f,%.1f)" % cam)
print("pos=(%.1f,%.1f,%.1f) ang=(%.2f,%.2f)" % (pos[0],pos[1],pos[2],ang[0],ang[1]))
print("\n????:")
for k in range(min(cnt,24)):
    base=352+k*40
    hp,hpm,sh,shm=struct.unpack_from("<4I",f,base)
    team,life,nlen,flags=struct.unpack_from("<4B",f,base+16)
    nm=f[base+20:base+40].split(b'\x00')[0].decode('latin1','replace')
    e=struct.unpack_from("<3f",f,64+k*12)
    import math
    d=math.sqrt((e[0]-pos[0])**2+(e[1]-pos[1])**2+(e[2]-pos[2])**2)*0.01905
    print("  [%2d] %6.1fm hp=%d sh=%d team=%d flags=%d '%s'" % (k,d,hp,sh,team,flags,nm))
