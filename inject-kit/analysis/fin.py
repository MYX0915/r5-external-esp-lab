import struct,time
good=0; bad=0
for i in range(10):
    raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    if len(raw)>=68:
        ok=struct.unpack_from("<I",raw,64)[0]
        inst=struct.unpack_from("<Q",raw,56)[0]
        if ok: good+=1
        else: bad+=1
    time.sleep(0.3)
print("feed ok=%d bad=%d" % (good,bad))
