import struct, glob, os
e=0x12B6FBF60
hexv="%X"%(e+0x260)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x100], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("?? 0x%X  +0x260 ~ +0x360\n" % e)
for i in range(0,0x100,0x10):
    off=0x260+i
    print("  +0x%03X  %s" % (off, " ".join("%02X"%b for b in raw[i:i+0x10])))
print("\n????:")
print("  +0x26C (?? visibilityType) = %d" % raw[0x0C])
print("  +0x28C (?? glow_enable)    = %d" % raw[0x2C])
print("  +0x294 (DX12 selector)      = %d" % raw[0x34])
print("  +0x295 contexts[0]          = %d" % raw[0x35])
print("  +0x29D focusedMask          = 0x%02X" % raw[0x3D])
print("  +0x2A8 parity               = 0x%08X" % struct.unpack_from("<I",raw,0x48)[0])
print("  +0x33C (??1 flag)         = 0x%08X" % struct.unpack_from("<I",raw,0xDC)[0])
print("  +0x138 ????             = 0x%08X" % struct.unpack_from("<I",raw,-0x128 if False else 0)[0])
