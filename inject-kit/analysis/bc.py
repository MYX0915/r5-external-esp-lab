import numpy as np, glob, os, struct
for va in ("141E6C10","E4A95440","13E8D2F0"):
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%va) if os.path.getsize(p)>=0x4000]
    if not fs: continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    print("=== %s ===" % va)
    hits=[]
    for off in range(0, 0x400, 4):
        v=struct.unpack_from("<I", raw, off)[0]
        if 40 <= v <= 700:
            nxt=struct.unpack_from("<I", raw, off+4)[0] if off+8<len(raw) else 0
            hits.append((off,v,nxt))
    for off,v,nxt in hits[:12]:
        print("   +0x%03X = %-4d (next=0x%X)" % (off,v,nxt))
    if not hits: print("   (no plausible bone count)")
