import struct, glob, os
e=0x12053D9A0
hexv="%X"%(e+0x478)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
q=struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0]
print("signifier ?? = 0x%X" % q)
open("sigptr_one.txt","w").write("0x%X"%q)
