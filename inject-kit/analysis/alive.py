import struct, time
def snap():
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
    pos=struct.unpack_from("<3f",f,32); cnt=struct.unpack_from("<I",f,44)[0]
    ok=struct.unpack_from("<I",f,48)[0]
    return cam,ang,pos,cnt,ok
a=snap(); time.sleep(1.5); b=snap()
print("t0 cam=%s ang=(%.2f,%.2f) ok=%d cnt=%d" % (["%.1f"%x for x in a[0]], a[1][0],a[1][1],a[4],a[3]))
print("t1 cam=%s ang=(%.2f,%.2f) ok=%d cnt=%d" % (["%.1f"%x for x in b[0]], b[1][0],b[1][1],b[4],b[3]))
same = all(abs(a[0][i]-b[0][i])<0.01 for i in range(3))
print("\ncam ????:", "?????????" if same else "????????")
