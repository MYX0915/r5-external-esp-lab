import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
cnt=struct.unpack_from("<I",f,44)[0]
print("me=0x%X  feed count=%d" % (inst,cnt))
open("me_v.txt","w").write("0x%X\n"%inst)
