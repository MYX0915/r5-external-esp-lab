import struct, os
try:
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    print("feed ok=%d inst=0x%X" % (struct.unpack_from("<I",f,48)[0], struct.unpack_from("<Q",f,56)[0]))
except Exception as e:
    print("no feed:", e)
