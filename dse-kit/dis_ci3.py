import importlib.util
from capstone import *
src = open(r"tools\pe_exports.py").read()
ns = {}; exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ci.dll")
md = Cs(CS_ARCH_X86, CS_MODE_64)

rva = exp['CiInitialize'] + 0x160
off = rva2off(rva)
code = d[off:off+0xA0]
for ins in md.disasm(code, 0x140000000 + rva):
    print(f"  +0x{ins.address-0x140000000:X}  {ins.mnemonic:<8} {ins.op_str}")
