import struct, time
for _ in range(40):
    try: f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    except: time.sleep(0.2); continue
    ok=struct.unpack_from("<I",f,48)[0]
    if ok: break
    time.sleep(0.2)
inst=struct.unpack_from("<Q",f,56)[0]
pos=struct.unpack_from("<3f",f,32); cam=struct.unpack_from("<3f",f,8)
print("ok=%d inst=0x%X" % (ok,inst))
print("pos=(%.1f,%.1f,%.1f)  cam=(%.1f,%.1f,%.1f)" % (pos+cam))
sane = abs(pos[0])<40000 and abs(pos[1])<40000 and abs(pos[2])<5000 and (abs(pos[0])+abs(pos[1]))>10
print("sane:", sane)
