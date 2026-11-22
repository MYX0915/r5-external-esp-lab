import struct, time
for _ in range(20):
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    ok=struct.unpack_from("<I",f,48)[0]
    cnt=struct.unpack_from("<I",f,44)[0]
    inst=struct.unpack_from("<Q",f,56)[0]
    cam=struct.unpack_from("<3f",f,8); pos=struct.unpack_from("<3f",f,32)
    if ok: break
    time.sleep(0.2)
print("ok=%d inst=0x%X count=%d" % (ok,inst,cnt))
print("cam=(%.1f,%.1f,%.1f) pos=(%.1f,%.1f,%.1f)" % (cam+pos))
for i in range(min(cnt,8)):
    e=struct.unpack_from("<3f", f, 64+i*12)
    print("   ent[%d] = (%.1f, %.1f, %.1f)" % (i,e[0],e[1],e[2]))
