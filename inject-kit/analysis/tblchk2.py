import struct, glob, os
mod=0x7FF7A1AD0000
hexv="%X"%(mod+0x72BE6C0)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)
if not fs: print("no dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
tbl=struct.unpack_from("<Q", raw, 0)[0]
cnt=struct.unpack_from("<I", raw, 0x18)[0]
print("HighlightSettings @ RVA 0x72BE6C0")
print("  ??? = 0x%X" % tbl)
print("  ??? = %d" % cnt)
open("tblptr.txt","w").write("0x%X\n"%tbl)
