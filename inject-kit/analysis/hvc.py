import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=struct.unpack_from("<3f",f,32)
print("%.1f %.1f %.1f" % me)
open("hvcmd.txt","w").write("hv %.1f %.1f %.1f 120\n" % me)
