import importlib.util
from capstone import *
src = open(r"tools\pe_exports.py").read()
ns = {}; exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ci.dll")
md = Cs(CS_ARCH_X86, CS_MODE_64)
for fn in ('CiValidateFileObject','CiCheckSignedFile','CiVerifyHashInCatalog'):
    rva = exp[fn]
    off = rva2off(rva)
    print(f"\n=== {fn} 0x{rva:X} ===")
    for i, ins in enumerate(md.disasm(d[off:off+0x60], 0x140000000 + rva)):
        print(f"  +0x{ins.address-0x140000000:X}  {ins.mnemonic:<8} {ins.op_str}")
        if i > 14: break
