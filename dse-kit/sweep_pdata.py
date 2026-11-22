import sys, struct
sys.path.insert(0,'.')
import kva
KRNL=r"C:\Windows\System32\ntoskrnl.exe"
d=open(KRNL,'rb').read()
e=struct.unpack_from('<I',d,0x3C)[0]
nsec=struct.unpack_from('<H',d,e+6)[0]
optsz=struct.unpack_from('<H',d,e+20)[0]
opt=e+24
secs=[]
so=opt+optsz
for i in range(nsec):
    s=so+i*40
    nm=d[s:s+8].rstrip(b'\0').decode('latin1')
    vs,va,rs,rp=struct.unpack_from('<IIII',d,s+8)
    secs.append((nm,va,vs,rp,rs))
def sec(name):
    for nm,va,vs,rp,rs in secs:
        if nm==name: return va,vs,rp,rs
    return None
pd=sec('.pdata')
va,vs,rp,rs=pd
nf=rs//12
k=kva.KVA(); base,size=kva.nt_base()
print(f"ntoskrnl=0x{base:X}  .pdata functions={nf}")
hits=[]
for i in range(nf):
    b,e2,u=struct.unpack_from('<III', d, rp+i*12)
    if b==0 or b>=size: continue
    code=k.read(base+b, 12)
    if not code or len(code)<12: continue
    if code[0]==0xE9:
        t=base+b+5+struct.unpack_from('<i',code,1)[0]
        if not (base<=t<base+size): hits.append((b,'E9',t))
    elif code[0]==0x48 and code[1]==0xB8 and code[10]==0xFF and code[11]==0xE0:
        t=struct.unpack_from('<Q',code,2)[0]
        if not (base<=t<base+size): hits.append((b,'MOVJMP',t))
    elif code[0]==0xFF and code[1]==0x25:
        disp=struct.unpack_from('<i',code,2)[0]
        slot=base+b+6+disp
        p=k.read(slot,8)
        if p:
            t=struct.unpack('<Q',p)[0]
            if not (base<=t<base+size): hits.append((b,'FF25',t))
print(f"被 hook 的函数入口: {len(hits)}")
for b,kind,t in hits[:20]:
    print(f"  rva=0x{b:<8X} {kind} -> 0x{t:X}")
