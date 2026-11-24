import struct, glob, os, collections
ptrs=[l.strip() for l in open("sigptrs.txt") if l.strip()]
print("?????:")
names=[]
for p in ptrs:
    e=int(p,16); hexv="%X"%e
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x20], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    n=0
    while n<len(raw) and 32<=raw[n]<127: n+=1
    s=raw[:n].decode('latin1')
    names.append(s)
    print("  %-32s (0x%s)" % (s if s else "(?)", p[2:]))
