import struct, time
for i in range(12):
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    ok=struct.unpack_from("<I",f,48)[0]
    inst=struct.unpack_from("<Q",f,56)[0]
    pos=struct.unpack_from("<3f",f,32)
    cnt=struct.unpack_from("<I",f,44)[0]
    print("ok=%d inst=0x%-12X pos=(%.1f,%.1f,%.1f) count=%d" % (ok,inst,pos[0],pos[1],pos[2],cnt))
    time.sleep(0.4)
