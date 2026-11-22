import struct
feed=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",feed,56)[0]
pos=struct.unpack_from("<3f",feed,32)
print("player inst=0x%X pos=(%.1f,%.1f,%.1f)" % (inst,*pos))
open("pl.txt","w").write("0x%X 0x8000\n" % inst)
