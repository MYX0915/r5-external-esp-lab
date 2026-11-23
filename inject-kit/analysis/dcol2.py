import struct, glob, os
col=int(open("col2v.txt").read().split()[0],16)
hexv="%X"%col
fs=sorted([q for q in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(q)==0x20], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
sig,off,cd,ptd,pchd,pself=struct.unpack_from("<IIIIII", raw, 0)
print("COL sig=0x%X pTD=0x%X" % (sig,ptd))
if ptd:
    open("td3.txt","w").write("0x%X 0x30\n"%(0x7FF689680000+ptd))
