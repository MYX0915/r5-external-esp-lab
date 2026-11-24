import struct, glob, os
e=0x12D0F1C10
hexv="%X"%(e+0x290)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x30], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
sel=raw[4]; fm=raw[13]; par=struct.unpack_from("<I",raw,0x18)[0]
print("?? 0x%X ??: selector=%d  focusedMask=0x%02X  parity=%d" % (e,sel,fm,par))
open("glow_orig.txt","w").write("%d %d %d\n"%(sel,fm,par))
