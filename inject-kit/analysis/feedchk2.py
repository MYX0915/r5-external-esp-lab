import struct, time, os
p=r"C:\ProgramData\sc_feed.bin"
for i in range(30):
    if os.path.exists(p):
        raw=open(p,"rb").read()
        if len(raw)>=352:
            magic,ver=struct.unpack_from("<II",raw,0)
            if magic==0x44454546:
                cam=struct.unpack_from("<3f",raw,8); ang=struct.unpack_from("<3f",raw,20)
                pos=struct.unpack_from("<3f",raw,32)
                cnt,ok=struct.unpack_from("<II",raw,44)
                inst=struct.unpack_from("<Q",raw,52)[0]
                print("ver=%d ok=%d count=%d inst=0x%X" % (ver,ok,cnt,inst))
                print("cam=",["%.1f"%v for v in cam]," pos=",["%.1f"%v for v in pos])
                base=64
                for k in range(min(cnt,6)):
                    e=struct.unpack_from("<3f", raw, base+k*12)
                    d=sum((e[j]-pos[j])**2 for j in range(3))**0.5
                    print("   ent[%d] = (%9.1f,%9.1f,%9.1f)  dist=%.0f units (%.0f m)" % (k,e[0],e[1],e[2],d,d*0.01905))
                break
    time.sleep(0.2)
