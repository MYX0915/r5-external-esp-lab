import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
cnt=struct.unpack_from("<I",f,44)[0]
me=struct.unpack_from("<3f",f,32)
print("me=0x%X  feed count=%d  pos=(%.0f,%.0f,%.0f)" % (inst,cnt,me[0],me[1],me[2]))
open("me_v.txt","w").write("0x%X\n"%inst)
