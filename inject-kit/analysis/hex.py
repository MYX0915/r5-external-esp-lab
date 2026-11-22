raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
print("size:", len(raw))
print("first 96 bytes:")
for i in range(0, min(96,len(raw)), 16):
    print("  %04X  %s" % (i, raw[i:i+16].hex(" ")))
import struct
print("magic/ver:", struct.unpack_from("<II", raw, 0))
