import struct, glob, os
rows=[l.split() for l in open("clsmap.txt") if l.strip()]
print("%-20s %-5s %s" % ("vtable","count","scriptName"))
out=[]
for vt,cnt,s in rows:
    e=int(s,16); hexv="%X"%(e+0x590)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    n=0
    while n<len(raw) and 32<=raw[n]<127: n+=1
    name=raw[:n].decode('latin1')
    out.append((int(cnt),vt,name,s))
out.sort(reverse=True)
for cnt,vt,name,s in out:
    print("%-20s %-5d %s" % (vt,cnt,name if name else "(?)"))
open("names.txt","w").write("\n".join("%s %d %s %s"%(vt,c,name,s) for c,vt,name,s in out))
