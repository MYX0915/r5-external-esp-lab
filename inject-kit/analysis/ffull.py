import struct, os
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
print("feed ?? %d" % len(f))
print("  magic=0x%08X ver=%d" % (struct.unpack_from("<I",f,0)[0], struct.unpack_from("<I",f,4)[0]))
print("  cam=(%.1f,%.1f,%.1f)" % struct.unpack_from("<3f",f,8))
print("  ang=(%.3f,%.3f)" % struct.unpack_from("<2f",f,20))
print("  pos=(%.1f,%.1f,%.1f)" % struct.unpack_from("<3f",f,32))
print("  count=%d" % struct.unpack_from("<I",f,44)[0])
print("  inst=0x%X" % struct.unpack_from("<Q",f,56)[0])
