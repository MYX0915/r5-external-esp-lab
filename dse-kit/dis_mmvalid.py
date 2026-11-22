import struct, re
from capstone import *
m=open(r'C:\ProgramData\ntoskrnl_mem.bin','rb').read()
NT=0xFFFFF80790400000
RVA=0x2AA420   # MmIsAddressValid (磁盘导出 RVA)
md=Cs(CS_ARCH_X86,CS_MODE_64)
print(f"反汇编 MmIsAddressValid @ rva 0x{RVA:X}")
n=0
for ins in md.disasm(m[RVA:RVA+0x120], RVA):
    extra=''
    mm=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
    if mm:
        sign=1 if mm.group(1)=='+' else -1
        t=NT+ins.address+ins.size+sign*int(mm.group(2),16)
        extra=f'   ; -> 0x{t:X} (nt rva 0x{t-NT:X})'
        # 试着读出该全局的 8 字节
        off=(t-NT)
        if 0<=off<len(m)-8:
            v=struct.unpack_from('<Q',m,off)[0]
            extra+=f'  [q=0x{v:X}]'
    m2=re.search(r'(0x[0-9a-f]{12,})', ins.op_str)
    if m2:
        extra+=f'   ; imm 0x{int(m2.group(1),16):X}'
    print(f"  +0x{ins.address:X} {ins.mnemonic:<8} {ins.op_str}{extra}")
    n+=1
    if n>28: break
