import glob, os, struct
mods=[]
for f in sorted(glob.glob(r'C:\ProgramData\kmod_*.bin')):
    d=open(f,'rb').read()
    if d[:2]!=b'MZ': continue
    e=struct.unpack_from('<I',d,0x3C)[0]
    if d[e:e+4]!=b'PE\0\0': continue
    ts=struct.unpack_from('<I',d,e+8)[0]
    if ts!=0: continue
    optsz=struct.unpack_from('<H',d,e+20)[0]
    sz=struct.unpack_from('<I',d,e+24+56)[0]
    b=int(os.path.basename(f)[5:-4],16)
    mods.append((b,b+min(sz,len(d)),os.path.basename(f),d,sz))
mods.sort()
def owner(v):
    for b,e2,n,d,sz in mods:
        if b<=v<e2: return n
    return None
# 统计跨模块引用
graph={}
for b,e2,n,d,sz in mods:
    lim=min(sz,len(d))
    for i in range(0,lim-8,8):
        v=struct.unpack_from('<Q',d,i)[0]
        if not (0xFFFFF80000000000<=v<=0xFFFFFFFFFFFFFFFF): continue
        o=owner(v)
        if o and o!=n:
            graph.setdefault(n,{}).setdefault(o,0)
            graph[n][o]+=1
print("模块间引用关系（谁 -> 谁 : 次数）")
tot_in={}
for src,tgts in graph.items():
    for t,c in tgts.items(): tot_in[t]=tot_in.get(t,0)+c
    line=', '.join(f"{k[-9:-4]}:{c}" for k,c in sorted(tgts.items(), key=lambda x:-x[1])[:4])
    print(f"  {src[-9:-4]} -> {line}")
print("\n被引用最多（最可能是核心模块）:")
for k,v in sorted(tot_in.items(), key=lambda x:-x[1])[:5]:
    print(f"  {k}  被引 {v} 次")
print("\n无出边模块:", [n[-9:-4] for b,e2,n,d,sz in mods if n not in graph])
