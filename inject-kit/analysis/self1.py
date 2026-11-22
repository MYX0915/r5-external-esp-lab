import struct, time
for _ in range(40):
    raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    if len(raw)>=64 and struct.unpack_from("<I",raw,48)[0]:
        inst=struct.unpack_from("<Q",raw,56)[0]
        pos=struct.unpack_from("<3f",raw,32)
        if inst: break
    time.sleep(0.1)
print("local inst=0x%X pos=(%.1f,%.1f,%.1f)" % (inst,pos[0],pos[1],pos[2]))
open("selftxt.txt","w").write("0x%X 0x8000\n" % inst)
open("selfpos.txt","w").write("%.3f %.3f %.3f" % pos)
