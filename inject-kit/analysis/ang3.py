import struct, glob, os
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
print("inst=0x%X" % inst)
open("ang25.txt","w").write("0x%X 0x10\n" % (inst+0x25C8))
open("ang1f84.txt","w").write("0x%X 0x10\n" % (inst+0x1F84))
