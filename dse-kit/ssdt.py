import sys, struct
sys.path.insert(0,'.')
import kva
k = kva.KVA(); base,size = kva.nt_base()

def q(va):
    d = k.read(va, 8)
    return struct.unpack('<Q', d)[0] if d else None
def d32(va):
    d = k.read(va, 4)
    return struct.unpack('<i', d)[0] if d else None

# KeServiceDescriptorTable 指针所在（从分发代码里的 lea 目标读出）
desc_ptr = q(base + 0x12018C0)
print(f"KeServiceDescriptorTable = 0x{desc_ptr:X}")
if not desc_ptr: sys.exit(1)
pTable = q(desc_ptr)
count  = d32(desc_ptr + 0x10)
print(f"pServiceTable = 0x{pTable:X}  NumberOfServices = {count}")

# 导出表拿真身
hdr = k.read(base,0x1000); e=struct.unpack_from('<I',hdr,0x3C)[0]; nt=hdr[e:]
er,_ = struct.unpack_from('<II', nt, 0x18+0x70)
d = k.read(base+er, 0x400)
nf=struct.unpack_from('<I',d,0x14)[0]; nn=struct.unpack_from('<I',d,0x18)[0]
af,an,ao = struct.unpack_from('<III',d,0x1C)
names=k.read(base+an,nn*4); funcs=k.read(base+af,nf*4); ords=k.read(base+ao,nn*2)
exp={}
for i in range(nn):
    nr=struct.unpack_from('<I',names,i*4)[0]
    nm=(k.read(base+nr,64) or b'').split(b'\0')[0].decode('latin1')
    oi=struct.unpack_from('<H',ords,i*2)[0]
    exp[nm]=struct.unpack_from('<I',funcs,oi*4)[0]

def check(name, ssn):
    ent = d32(pTable + ssn*4)
    if ent is None: print(f"  {name:<28} ssn=0x{ssn:<3X} 读取失败"); return
    tgt = pTable + (ent >> 4)
    inside = base <= tgt < base+size
    real = base + exp[name] if name in exp else 0
    flag = 'OK' if inside and tgt == real else '*** 不一致 ***'
    print(f"  {name:<28} ssn=0x{ssn:<3X} table->0x{tgt:X}  真实=0x{real:X}  {flag}")

check('NtAllocateVirtualMemory', 0x18)
check('NtProtectVirtualMemory', 0x50)
for nm,ssn in exp.items():
    pass
