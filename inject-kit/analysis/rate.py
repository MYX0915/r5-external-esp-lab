import struct, time
good=bad=0
for i in range(25):
    try:
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=68:
            ok=struct.unpack_from("<I",raw,64)[0]
            if ok: good+=1
            else: bad+=1
    except Exception: pass
    time.sleep(0.2)
print("feed samples: ok=%d  zero=%d" % (good,bad))
