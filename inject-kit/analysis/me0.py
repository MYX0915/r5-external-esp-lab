import struct, time
for _ in range(40):
    try: f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    except: time.sleep(0.2); continue
    if struct.unpack_from("<I",f,48)[0]:
        inst=struct.unpack_from("<Q",f,56)[0]
        pos=struct.unpack_from("<3f",f,32)
        if inst: break
    time.sleep(0.2)
print("inst=0x%X pos=(%.1f,%.1f,%.1f) count=%d" % (inst,pos[0],pos[1],pos[2],struct.unpack_from("<I",f,44)[0]))
open("me.txt","w").write("0x%X"%inst)
