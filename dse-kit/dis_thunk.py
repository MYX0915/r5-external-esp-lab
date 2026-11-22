import sys
sys.path.insert(0,'.')
import kva
from capstone import *
k = kva.KVA(); base,size = kva.nt_base()
rva = 0x6CEF80
code = k.read(base+rva, 0x120)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
print(f"thunk rva=0x{rva:X}")
for ins in md.disasm(code, base+rva):
    extra=''
    for op in ins.operands:
        if op.type==3 and op.mem.base==41:
            t = ins.address + ins.size + op.mem.disp
            extra = f'   ; -> 0x{t:X} (rva 0x{t-base:X})'
            # 若是 lea/mov 指向数据，尝试读 8/4 字节
    print(f"  +0x{ins.address-base:<8X} {ins.mnemonic:<7} {ins.op_str}{extra}")
