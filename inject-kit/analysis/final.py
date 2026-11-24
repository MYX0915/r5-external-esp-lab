import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
ang=struct.unpack_from("<3f",f,20); cnt=struct.unpack_from("<I",f,44)[0]
print("FEED ??: ver=%d count=%d ang=(%.1f,%.1f)" % (struct.unpack_from("<I",f,4)[0],cnt,ang[0],ang[1]))
