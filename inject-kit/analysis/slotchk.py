import struct, glob, os, numpy as np
# 1) ????????????????
base=0x7FF65B750000
# ??? 2MB ?? dump??????????????
cands=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x200000]
if not cands:
    print("??? dump???????")
else:
    cands.sort(key=os.path.getmtime)
    a=np.fromfile(cands[-1], dtype=np.uint8)
    q=a.view(np.uint64)[::4]
    slot={}
    for i,v in enumerate(q):
        v=int(v)
        if v>=0x10000 and (v>>47)==0:
            slot[v]=i
    print("?? dump: %s, ?? %d" % (os.path.basename(cands[-1]), len(slot)))
    addrs=[l.strip() for l in open(r"C:\ProgramData\sc_addr.txt") if l.strip()]
    print("\n%-14s %-8s %-10s %-8s %s" % ("entity","slot","+0x298?16","???","CHandle(index,serial)"))
    hit=0; tot=0
    for a_ in addrs[:16]:
        hexv=a_[2:]
        fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000]
        if not fs: continue
        fs.sort(key=os.path.getmtime)
        raw=open(fs[-1],"rb").read()
        v=struct.unpack_from("<Q", raw, 0x298)[0]
        ea=int(a_,16)
        s=slot.get(ea)
        lo=v & 0xFFFF
        ser=(v>>16)&0xFFFF
        tot+=1
        ok = (s is not None and s==lo)
        if ok: hit+=1
        print("%-14s %-8s 0x%-8X %-8s (%d,%d)" % (a_[2:], s if s is not None else "?", lo, "?" if ok else "?", lo, ser))
    print("\n??==?16 ???: %d/%d" % (hit,tot))
