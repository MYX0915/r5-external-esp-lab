import struct, glob, os
me=int(open("me_now.txt").read().strip(),16)
hexv="%X"%me
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
vt=struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0]
print("???? 0x%X  vtable = 0x%X" % (me, vt))
open("vt.txt","w").write("0x%X\n"%vt)
