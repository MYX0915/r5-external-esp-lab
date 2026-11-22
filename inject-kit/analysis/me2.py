import struct, time
for _ in range(40):
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    if len(f)>=64 and struct.unpack_from("<I",f,48)[0]:
        inst=struct.unpack_from("<Q",f,56)[0]; pos=struct.unpack_from("<3f",f,32)
        if inst and abs(pos[0])>1: break
    time.sleep(0.15)
print("inst=0x%X pos=(%.1f,%.1f,%.1f)" % (inst,pos[0],pos[1],pos[2]))
open("me2.txt","w").write("0x%X 0x2000\n" % inst)
