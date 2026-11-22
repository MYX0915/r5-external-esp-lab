import sys
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
    for op in ins.operands:
        if op.type==3 and op.mem.base==41:
            t = ins.address + ins.size + op.mem.disp
            extra = f'   ; -> rva 0x{t-base:X}'
    print(f"  +0x{ins.address-base:<8X} {ins.mnemonic:<7} {ins.op_str}{extra}")
