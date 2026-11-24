import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
magic,ver=struct.unpack_from("<II",f,0)
print("feed: magic=0x%X ver=%d size=%d" % (magic,ver,len(f)))
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
pos=struct.unpack_from("<3f",f,32); cnt=struct.unpack_from("<I",f,44)[0]
print("cam=(%.1f,%.1f,%.1f) ang=(%.1f,%.1f)" % (cam[0],cam[1],cam[2],ang[0],ang[1]))
print("pos=(%.1f,%.1f,%.1f) count=%d" % (pos[0],pos[1],pos[2],cnt))
print("\n?? size = 60 + 24*12 + 24*36 = %d" % (60+24*12+24*36))
