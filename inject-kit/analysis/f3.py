import struct
raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
ok=struct.unpack_from("<I",raw,64)[0]
inst=struct.unpack_from("<Q",raw,56)[0]
cam=struct.unpack_from("<3f",raw,8); pos=struct.unpack_from("<3f",raw,32)
print("feed ok=%d inst=0x%X cam=(%.1f,%.1f,%.1f) pos=(%.1f,%.1f,%.1f)" % (ok,inst,*cam,*pos))
