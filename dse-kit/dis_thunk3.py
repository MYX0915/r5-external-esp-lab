import sys, re
sys.path.insert(0,'.')
import kva
from capstone import *
k = kva.KVA(); base,size = kva.nt_base()
rva = 0x6CF390
code = k.read(base+rva, 0x140)
md = Cs(CS_ARCH_X86, CS_MODE_64)
print(f"disasm rva=0x{rva:X}")
for ins in md.disasm(code, base+rva):
    extra=''
    m = re.search(r'rip \+ (0x[0-9a-f]+)', ins.op_str)
    if m:
        t = ins.address + ins.size + int(m.group(1),16)
        extra = f'   ; -> rva 0x{t-base:X}'
        data = k.read(t, 8)
        if data: extra += f'  [q={int.from_bytes(data,"little"):#x}]'
    elif re.search(r'rip - (0x[0-9a-f]+)', ins.op_str):
        m2 = re.search(r'rip - (0x[0-9a-f]+)', ins.op_str)
        t = ins.address + ins.size - int(m2.group(1),16)
        extra = f'   ; -> rva 0x{t-base:X}'
    print(f"  +0x{ins.address-base:<8X} {ins.mnemonic:<7} {ins.op_str}{extra}")
