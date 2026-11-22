import struct, time
good=None
for i in range(20):
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    ok=struct.unpack_from("<I",f,48)[0]
    inst=struct.unpack_from("<Q",f,56)[0]
    pos=struct.unpack_from("<3f",f,32)
    if ok and inst and abs(pos[0])>1:
        good=(inst,pos); break
    time.sleep(0.3)
print("inst=0x%X pos=(%.1f,%.1f,%.1f)" % (good[0],*good[1]) if good else "still zero")
if good:
    open("me.txt","w").write("0x%X 0x8000\n" % good[0])
    open("mepos.txt","w").write("%.4f %.4f %.4f" % good[1])
