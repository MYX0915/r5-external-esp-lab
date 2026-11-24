import struct, glob, os
e=0x1270ECDB0
hexv="%X"%(e+0x290)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x30], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("?? 0x%X:" % e)
print("  +0x294 selector    = 0x%02X" % raw[4])
print("  +0x295 contexts[0] = 0x%02X" % raw[5])
print("  +0x29D focusedMask = 0x%02X" % raw[13])
print("  +0x2A8 parity      = 0x%08X" % struct.unpack_from("<I",raw,0x18)[0])
