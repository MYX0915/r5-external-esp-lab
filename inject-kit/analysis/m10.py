import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
print("me=0x%X" % inst)
open("me3.txt","w").write("0x%X 0x800"%inst)
