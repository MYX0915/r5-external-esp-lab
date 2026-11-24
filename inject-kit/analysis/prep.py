import struct, glob, os
e=0x1270ECDB0
hexv="%X"%(e+0x290)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x30], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
sel=raw[4]; ctx0=raw[5]; fm=raw[13]
par=struct.unpack_from("<I", raw, 0x18)[0]
print("?? 0x%X ??????:" % e)
print("  +0x294 selector    = 0x%02X (%d)" % (sel,sel))
print("  +0x295 contexts[0] = 0x%02X (%d)" % (ctx0,ctx0))
print("  +0x29D focusedMask = 0x%02X (bit0=%d)" % (fm, fm&1))
print("  +0x2A8 parity      = 0x%08X" % par)
print()
print("????:")
print("  +0x294 = 0x32 (50)")
print("  +0x295 = 0x32 (50)")
print("  +0x29D = 0x%02X  (? 0x%02X | 1)" % (fm|1, fm))
print("  +0x2A8 = 0x%08X  (? 0x%08X ^ 1)" % (par^1, par))
open("orig.txt","w").write("%d %d %d %d\n" % (sel,ctx0,fm,par))
