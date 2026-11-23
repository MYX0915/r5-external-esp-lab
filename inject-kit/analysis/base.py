import struct, time, math
for _ in range(40):
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    ok=struct.unpack_from("<I",f,48)[0]
    cam=struct.unpack_from("<3f",f,8)
    if ok and abs(cam[0])>100: break
    time.sleep(0.2)
ang=struct.unpack_from("<3f",f,20); pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]
print("ok=%d count=%d" % (ok,cnt))
print("cam=(%.2f,%.2f,%.2f)" % cam)
print("ang=(%.2f,%.2f,%.2f)" % ang)
print("pos=(%.2f,%.2f,%.2f)" % pos)
