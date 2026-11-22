import struct, time
for _ in range(40):
    raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    if len(raw)>=68 and struct.unpack_from("<I",raw,64)[0]:
        inst=struct.unpack_from("<Q",raw,56)[0]
        if inst: break
    time.sleep(0.1)
open("plbig.txt","w").write("0x%X 0x20000\n" % inst)
print("player inst=0x%X" % inst)
