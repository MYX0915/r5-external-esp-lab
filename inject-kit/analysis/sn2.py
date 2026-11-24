import struct, glob, os
tests=[('0xF79E4EE0','?n=36 ??'),('0x12D0F1C10','??? vt=...9330'),('0x123DAA480','??? vt=...EBA8'),('0x12D28A300','???2')]
for s,label in tests:
    e=int(s,16); hexv="%X"%(e+0x590)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)
    if not fs: print("  %s ?dump" % s); continue
    raw=open(fs[-1],"rb").read()
    n=0
    while n<len(raw) and 32<=raw[n]<127: n+=1
    print("  %-14s [%s]  =  \"%s\"" % (s,label,raw[:n].decode('latin1')))
