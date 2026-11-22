import struct
raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",raw,8); ang=struct.unpack_from("<3f",raw,20)
pos=struct.unpack_from("<3f",raw,32)
inst=struct.unpack_from("<Q",raw,56)[0]
ok=struct.unpack_from("<I",raw,64)[0]
print("ok=%d inst=0x%X" % (ok,inst))
print("cam=",["%.1f"%v for v in cam]); print("ang=",["%.2f"%v for v in ang]); print("pos=",["%.1f"%v for v in pos])
