import struct, glob, os
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*.bin") if os.path.getsize(p)==0x20], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
q=struct.unpack_from("<Q", raw, 0)[0]
print("highlight ??? = 0x%X" % q)
open("tbl.txt","w").write("0x%X 0xD00\n"%q)
