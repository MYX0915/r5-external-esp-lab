import struct, glob, os
me=int(open("me.txt").read().strip(),16)
for off in (0x18B0,0x18C0):
    hexv="%X"%(me+off)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x40], key=os.path.getmtime)
    if not fs: print("  +0x%X ?dump" % off); continue
    raw=open(fs[-1],"rb").read()
    n=0
    while n<len(raw) and 32<=raw[n]<127: n+=1
    printable=raw[:n].decode('latin1')
    print("  +0x%X: '%s'   first8=%s" % (off, printable, " ".join("%02X"%b for b in raw[:8])))
