import struct, glob, os
r50=int(open("row50.txt").read().strip(),16)
hexv="%X"%r50
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x10], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
fb=struct.unpack_from("<I",raw,0)[0]
r,g,b=struct.unpack_from("<3f",raw,4)
print("row50: functionBits=0x%08X  RGB=(%.3f, %.3f, %.3f)" % (fb,r,g,b))
l0=[l.split()[0] for l in open(r"C:\ProgramData\sc_loot.txt") if l.startswith("0x")][0]
e0=int(l0,16); hexv2="%X"%(e0+0x16C)
fs2=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv2) if os.path.getsize(p)==0xC], key=os.path.getmtime)
if fs2:
    print("%s +0x16C = (%.2f, %.2f, %.2f)" % (l0, *struct.unpack_from("<3f", open(fs2[-1],"rb").read(),0)))
