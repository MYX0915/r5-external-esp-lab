import sys, struct
sys.path.insert(0,'.')
import kva
from capstone import *
k = kva.KVA(); base, size = kva.nt_base()

# 导出表
hdr = k.read(base, 0x1000); e = struct.unpack_from('<I', hdr, 0x3C)[0]; nt = hdr[e:]
exp_rva,_ = struct.unpack_from('<II', nt, 0x18+0x70)
d = k.read(base+exp_rva, 0x400)
nf = struct.unpack_from('<I', d, 0x14)[0]; nn = struct.unpack_from('<I', d, 0x18)[0]
af,an,ao = struct.unpack_from('<III', d, 0x1C)
names = k.read(base+an, nn*4); funcs = k.read(base+af, nf*4); ords = k.read(base+ao, nn*2)
exp={}; inv={}
for i in range(nn):
    nr = struct.unpack_from('<I', names, i*4)[0]
    nm = (k.read(base+nr,64) or b'').split(b'\0')[0].decode('latin1')
    oi = struct.unpack_from('<H', ords, i*2)[0]
    fr = struct.unpack_from('<I', funcs, oi*4)[0]
    exp[nm]=fr; inv.setdefault(fr,nm)

api='NtAllocateVirtualMemory'; rva=exp[api]
code = k.read(base+rva, 0x600)
md = Cs(CS_ARCH_X86, CS_MODE_64)
print(f"=== {api}  0x{base+rva:X} ===")
for ins in md.disasm(code, base+rva):
    if ins.mnemonic in ('call','jmp') and ins.op_str.startswith('0x'):
        t = int(ins.op_str,16)
        outside = not (base <= t < base+size)
        tr = t-base
        nm = inv.get(tr, '')
        tag = ' <<< OUTSIDE ntoskrnl' if outside else (nm if nm else '')
        print(f"  +0x{ins.address-base:X}  {ins.mnemonic}  -> 0x{t:X}  {tag}")
    elif ins.mnemonic in ('call','jmp') and 'ptr' in ins.op_str:
        print(f"  +0x{ins.address-base:X}  {ins.mnemonic}  {ins.op_str}   [indirect]")
