import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
pos=struct.unpack_from("<3f",f,32)
print("???? 0x%X  feed pos=(%.1f,%.1f,%.1f)" % (inst,pos[0],pos[1],pos[2]))
open("me_now.txt","w").write("0x%X\n"%inst)
