import struct, glob, os
e=0x12B6FBF60
hexv="%X"%(e+0x290)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x30], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
sel=raw[4]; fm=raw[13]; par=struct.unpack_from("<I",raw,0x18)[0]
print("?? 0x%X ??:" % e)
print("  selector=%d(%02X)  focusedMask=%02X(bit0=%d)  parity=%08X" % (sel,sel,fm,fm&1,par))
newfm = fm | 1
newpar = par ^ 1
print("\n???:")
print("  +0x294 = 0x32 (row 50)")
print("  +0x295 = 0x32")
print("  +0x29D = 0x%02X" % newfm)
print("  +0x2A8 = 0x%08X" % newpar)
open("wcmd.txt","w").write("32 32 %02X %08X\n" % (newfm, newpar))
