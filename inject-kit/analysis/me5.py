import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
print("inst=0x%X" % inst)
open("me5.txt","w").write("0x%X 0x4000\n"%inst)
