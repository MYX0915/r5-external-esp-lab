import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
ang=struct.unpack_from("<2f",f,20)
print("BEFORE pitch=%.2f yaw=%.2f" % (ang[0], ang[1]))
