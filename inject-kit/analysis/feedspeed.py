import struct, time
def snap():
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    cnt=struct.unpack_from("<I",f,44)[0]
    return [struct.unpack_from("<3f", f, 64+i*12) for i in range(min(cnt,14))]
a=snap(); time.sleep(0.25); b=snap(); time.sleep(0.25); c=snap()
print("samples:", len(a), len(b), len(c))
for i in range(min(len(a),len(b),len(c))):
    d1=max(abs(a[i][k]-b[i][k]) for k in range(3))
    d2=max(abs(b[i][k]-c[i][k]) for k in range(3))
    print("  ent[%2d] a=(%9.1f,%9.1f,%9.1f)  d(a,b)=%.2f  d(b,c)=%.2f" % (i,a[i][0],a[i][1],a[i][2],d1,d2))
