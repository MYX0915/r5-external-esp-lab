import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
print("local inst = 0x%X" % inst)
open("me_now.txt","w").write("0x%X\n"%inst)
