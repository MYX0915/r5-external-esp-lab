import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
open("me.txt","w").write("0x%X"%inst)
print("???? 0x%X" % inst)
