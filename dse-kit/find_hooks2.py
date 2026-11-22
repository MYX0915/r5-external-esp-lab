import struct
f=open(r"C:\Windows\System32\ntoskrnl.exe","rb").read()
m=open(r"C:\ProgramData\ntoskrnl_mem.bin","rb").read()
NT=0xFFFFF80790400000   # 该 dump 的运行基址

def secs(d):
    e=struct.unpack_from('<I',d,0x3C)[0]
    n=struct.unpack_from('<H',d,e+6)[0]; osz=struct.unpack_from('<H',d,e+20)[0]; opt=e+24
    out=[]; so=opt+osz
    for i in range(n):
        s=so+i*40
        nm=d[s:s+8].rstrip(b'\0').decode('latin1','ignore')
        vs,va,rs,rp=struct.unpack_from('<IIII',d,s+8)
        out.append((nm,va,vs,rp,rs))
    return out
fs, ms = secs(f), secs(m)
r2o=lambda S,rva: next((rp+(rva-va) for nm,va,vs,rp,rs in S if va<=rva<va+max(vs,rs)), None)

cands=[]
for nm,va,vs,rp,rs in fs:
    if nm not in ('.text','PAGE','PAGELK','PAGEKD'): continue
    n=min(vs,rs,len(m)-va)
    fo=r2o(fs,va)
    if fo is None: continue
    for i in range(n-12):
        rva=va+i
        if m[rva]!=0xE9: continue
        if f[fo+i]==0xE9: continue          # 原本就是跳转
        rel=struct.unpack_from('<i',m,rva+1)[0]
        tgt=NT+rva+5+rel
        inside = NT<=tgt<NT+len(m)
        cands.append((rva,tgt,inside))
print(f"候选（内存是 E9 而磁盘不是）: {len(cands)} 处")
byout=[c for c in cands if not c[2]]
print(f"其中跳转目标在 ntoskrnl 之外: {len(byout)} 处")
for rva,tgt,ins in byout[:20]:
    print(f"   rva=0x{rva:<9X} -> 0x{tgt:X}")
print("\n目标在 ntoskrnl 内的前 10 处（可能是内部跳转/热补丁）:")
for rva,tgt,ins in [c for c in cands if c[2]][:10]:
    print(f"   rva=0x{rva:<9X} -> 0x{tgt:X} (nt rva 0x{tgt-NT:X})")
