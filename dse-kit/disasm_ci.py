import struct, importlib.util
from capstone import *

src = open(r"tools\pe_exports.py").read()
ns = {}; exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ci.dll")

def read(rva, n):
    off, _ = rva2off(rva), None
    return d[off:off+n]

ci_init = exp['CiInitialize']
code = read(ci_init, 0x300)
md = Cs(CS_ARCH_X86, CS_MODE_64)
print(f"CiInitialize RVA=0x{ci_init:X}")
n = 0
for ins in md.disasm(code, 0x140000000 + ci_init):
    # 找 rip 相对写（mov [rip+x], imm）
    if ins.mnemonic == 'mov' and 'rip' in ins.op_str and ins.op_str.startswith('dword ptr'):
        rva = ins.address - 0x140000000
        print(f"  0x{rva:X}: {ins.mnemonic} {ins.op_str}")
        n += 1
        if n > 12: break
