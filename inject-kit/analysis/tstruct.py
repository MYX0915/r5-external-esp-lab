import struct, glob, os
mod=0x7FF7A1AD0000
hexv="%X"%(mod+0x72BE6C0)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x40], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("HighlightSettings ??? @ RVA 0x72BE6C0:")
for i in range(0,0x40,8):
    q=struct.unpack_from("<Q", raw, i)[0]
    d=struct.unpack_from("<I", raw, i)[0]
    tag=" ? ???" if i==0 else (" ? count" if i==0x18 else "")
    print("  +0x%02X  qword=0x%016X  dword=%d%s" % (i,q,d,tag))
