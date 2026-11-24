import struct, glob, os
mod=0x7FF612340000
hexv="%X"%(mod+0x72BE6C0)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
tbl=struct.unpack_from("<Q",raw,0)[0]
cnt=struct.unpack_from("<I",raw,0x18)[0]
row50=tbl+50*0x34
print("???=0x%X  ???=%d  row50=0x%X" % (tbl,cnt,row50))
open("row50.txt","w").write("0x%X\n"%row50)
