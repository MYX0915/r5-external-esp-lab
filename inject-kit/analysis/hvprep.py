import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32)
print("????: (%.1f, %.1f, %.1f)" % pos)
open("hvcmd.txt","w").write("hv %.1f %.1f %.1f 2500" % pos)
