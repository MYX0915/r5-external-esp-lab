import struct, re
from capstone import *
m=open(r'C:\ProgramData\ntoskrnl_mem.bin','rb').read()
NT=0xFFFFF80790400000
md=Cs(CS_ARCH_X86,CS_MODE_64)
RVA=0x2AB5A0
print(f"内层函数 @ rva 0x{RVA:X}")
n=0
for ins in md.disasm(m[RVA:RVA+0x140], RVA):
    extra=''
    mm=re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
    if mm:
        sign=1 if mm.group(1)=='+' else -1
        t=NT+ins.address+ins.size+sign*int(mm.group(2),16)
        off=t-NT
        q=None
        if 0<=off<len(m)-8: q=struct.unpack_from('<Q',m,off)[0]
        extra=f'   ; -> rva 0x{off:X}' + (f'  [q=0x{q:X}]' if q is not None else '')
    print(f"  +0x{ins.address:X} {ins.mnemonic:<8} {ins.op_str}{extra}")
    n+=1
    if n>26: break
