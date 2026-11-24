import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20); pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]
inst=struct.unpack_from("<Q",f,56)[0]
print("cam=(%.1f,%.1f,%.1f)" % cam)
print("pos=(%.1f,%.1f,%.1f) ang=(%.2f,%.2f)" % (pos[0],pos[1],pos[2],ang[0],ang[1]))
print("count=%d inst=0x%X" % (cnt,inst))
open("me.txt","w").write("0x%X"%inst)
