import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cnt=struct.unpack_from("<I",f,44)[0]
me=struct.unpack_from("<3f",f,32)
print("feed count=%d  me=(%.0f,%.0f,%.0f)" % (cnt,me[0],me[1],me[2]))
for i in range(min(cnt,8)):
    e=struct.unpack_from("<3f", f, 64+i*12)
    import math
    print("   [%d] (%.0f,%.0f,%.0f)  %.1fm" % (i,e[0],e[1],e[2],math.dist(e,me)*0.01905))
