import struct, time
for i in range(10):
    try:
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        ok=struct.unpack_from("<I",raw,64)[0]
        inst=struct.unpack_from("<Q",raw,56)[0]
        cam=struct.unpack_from("<3f",raw,8); pos=struct.unpack_from("<3f",raw,32)
        print("t=%d ok=%d inst=0x%-12X cam=(%9.1f,%8.1f,%8.1f) pos=(%9.1f,%8.1f,%8.1f)" % (i,ok,inst,*cam,*pos))
    except Exception as e:
        print("t=%d err %s" % (i,e))
    time.sleep(0.4)
