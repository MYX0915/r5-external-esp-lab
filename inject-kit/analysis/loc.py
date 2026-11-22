import struct, time
for _ in range(40):
    raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    if len(raw)>=64:
        ok=struct.unpack_from("<I",raw,48)[0]
        inst=struct.unpack_from("<Q",raw,56)[0]
        if ok and inst: break
    time.sleep(0.1)
open("loc.txt","w").write("0x%X 0x10\n" % inst)
print("local inst = 0x%X" % inst)
