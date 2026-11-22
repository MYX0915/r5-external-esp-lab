import struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
print("cam=(%.1f,%.1f,%.1f) ang=(%.2f,%.2f,%.2f)" % (cam+ang))
