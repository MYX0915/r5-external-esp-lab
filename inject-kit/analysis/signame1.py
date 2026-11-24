import struct, glob, os
sp=int(open("sigptr_one.txt").read().strip(),16)
hexv="%X"%sp
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
n=0
while n<len(raw) and 32<=raw[n]<127: n+=1
print("?? = '%s'" % raw[:n].decode('latin1'))
