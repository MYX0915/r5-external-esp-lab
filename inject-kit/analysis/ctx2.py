import struct, glob, os
for name in ("me","dummy"):
    fn="ctx_%s.txt"%name
    if not os.path.exists(fn): continue
    t=open(fn).read().split()[0]; hexv=t[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)>=0x10], key=os.path.getmtime)
    if not fs: print(name,"ctx ????"); continue
    raw=open(fs[-1],"rb").read()
    print("%-6s ctx?? 0x%s ? ??? = %d (0x%02X)" % (name, hexv, raw[0], raw[0]))
