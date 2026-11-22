import struct, time
for _ in range(40):
    try: f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    except: time.sleep(0.2); continue
    if struct.unpack_from("<I",f,48)[0]:
        inst=struct.unpack_from("<Q",f,56)[0]
        if inst: break
    time.sleep(0.2)
print("inst=0x%X count=%d" % (inst, struct.unpack_from("<I",f,44)[0]))
open("me3.txt","w").write("0x%X 0x200\n"%inst)
